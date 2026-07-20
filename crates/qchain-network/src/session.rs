//! AEAD-encrypted session for the optional **encrypted** P2P channel, layered
//! on top of the authenticated ML-DSA handshake (`handshake`). This is the
//! confidentiality half that the auth handshake deliberately left out (see its
//! module docs): once both peers derive a shared secret from the in-handshake
//! ML-KEM exchange, every subsequent envelope is sealed with ChaCha20-Poly1305.
//!
//! Two properties this adds on top of authentication:
//!
//! * **Confidentiality** — P2P traffic (blocks, votes, batches, requests) is no
//!   longer sent in the clear. This is defense-in-depth: consensus payloads are
//!   already signed, so an eavesdropper can't forge them, but encryption stops
//!   passive traffic analysis and hides the unsigned message types (requests,
//!   gossip attribution) from an observer.
//! * **Channel binding → full relay resistance** — the ML-KEM public key and
//!   ciphertext are folded into the *signed* handshake transcript. An on-path
//!   attacker who transparently relays the three handshake frames to MITM the
//!   channel would have to substitute its own ML-KEM keypair to read/modify
//!   traffic, which changes the transcript and breaks both parties'
//!   signatures. This closes the honest limitation the auth-only handshake
//!   documented (a relay could forge attribution of *unsigned* messages
//!   between two honest peers): with encryption on, there is a real encrypted
//!   channel bound to the signed identities, so no such relay is possible.
//!
//! **Key derivation.** Two directional keys from the 32-byte ML-KEM shared
//! secret via SHA3-256, so the two directions never share a key (and thus never
//! risk nonce/key reuse):
//!   `key_c2s = SHA3(DOMAIN || "c2s" || ss || nonce_c || nonce_s || cid || sid)`
//!   `key_s2c = SHA3(DOMAIN || "s2c" || ss || nonce_c || nonce_s || cid || sid)`
//! The dialer sends under `c2s` and receives under `s2c`; the acceptor is
//! symmetric. Binding the nonces and identities into the KDF is belt-and-
//! suspenders on top of the KEM secret.
//!
//! **Nonces.** Each direction has its own key and its own strictly-monotonic
//! 64-bit frame counter starting at 0, encoded as the low 8 bytes of the
//! 12-byte AEAD nonce (top 4 bytes zero). Since each `(key, counter)` pair is
//! used exactly once, AEAD nonces never repeat — the one hard requirement for
//! ChaCha20-Poly1305 safety. A connection would have to send 2^64 frames to
//! exhaust a counter, which never happens in a real connection lifetime; the
//! seal path fails loudly rather than wrapping if it ever did.
//!
//! **Forward secrecy — a symmetric KDF ratchet.** The per-connection ML-KEM
//! keypair is already ephemeral, so a compromise of a validator's long-term
//! ML-DSA signing key never decrypts past *connections* (their KEM secret was
//! destroyed). This adds forward secrecy *within* a long-lived connection: P2P
//! connections here are persistent and can stay up for the network's lifetime,
//! so one static session key would otherwise protect days of traffic. Each
//! direction's key is ratcheted every `REKEY_INTERVAL` frames via a one-way
//! SHA3 KDF (`k' = SHA3(RATCHET_DOMAIN || k || boundary_counter)`), and the old
//! key is zeroized. Because the KDF is one-way, a session key compromised at
//! ratchet epoch `e` cannot recover any traffic from epoch `< e` — the exposure
//! window of a mid-connection key leak is bounded to `REKEY_INTERVAL` frames
//! instead of the whole connection. The ratchet is a pure function of the frame
//! counter, so both peers advance the key at exactly the same frame over the
//! ordered TCP stream — **no rekey messages, no round trips, no coordination to
//! desync**, which is why it can't fork or stall consensus (unlike an in-band
//! DH/KEM rekey). The global frame counter still drives the nonce (never
//! resets), so nonce uniqueness is preserved trivially across ratchets. This
//! delivers forward secrecy; *post-compromise healing* within a single
//! unbroken connection (re-injecting fresh KEM entropy) remains a follow-up,
//! though connections already heal on reconnect via a fresh ephemeral KEM.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use qchain_core::ValidatorId;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

const SESSION_DOMAIN: &[u8] = b"qchain-p2p-enc-v1";
const RATCHET_DOMAIN: &[u8] = b"qchain-p2p-rekey-v1";

/// Re-derive each direction's key after this many frames. Bounds the window a
/// compromised session key exposes to at most this many messages. Ratcheting is
/// one SHA3 hash, so this can be small; 1024 keeps the window tight while adding
/// negligible cost.
const REKEY_INTERVAL: u64 = 1024;

fn derive_key(label: &[u8], shared_secret: &[u8], nonce_c: &[u8; 32], nonce_s: &[u8; 32], client_id: &ValidatorId, server_id: &ValidatorId) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SESSION_DOMAIN);
    h.update(label);
    h.update(shared_secret);
    h.update(nonce_c);
    h.update(nonce_s);
    h.update(client_id.0);
    h.update(server_id.0);
    h.finalize().into()
}

/// One direction's AEAD state: the current ratchet key, its cipher, and the
/// global monotonic frame counter (which drives both the nonce and the ratchet
/// schedule). `key` is held in `Zeroizing` so the old key is wiped from memory
/// when the ratchet replaces it.
struct DirCipher {
    key: Zeroizing<[u8; 32]>,
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl DirCipher {
    fn new(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        DirCipher { key: Zeroizing::new(key), cipher, counter: 0 }
    }

    /// Advance the ratchet: derive the next key one-way from the current one,
    /// zeroize the old key (dropping the previous `Zeroizing`), and rebuild the
    /// cipher. Both peers call this at the same `counter` boundary, so their
    /// keys stay in lock-step.
    fn ratchet(&mut self) {
        let mut h = Sha3_256::new();
        h.update(RATCHET_DOMAIN);
        h.update(*self.key);
        h.update(self.counter.to_le_bytes());
        let next: [u8; 32] = h.finalize().into();
        self.key = Zeroizing::new(next); // old key wiped when the previous Zeroizing drops
        self.cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key[..]));
    }

    fn next_nonce(&mut self) -> anyhow::Result<Nonce> {
        // Ratchet the key at each REKEY_INTERVAL boundary, before this frame is
        // sealed/opened with it — deterministic on the frame counter, so both
        // sides advance at the same frame.
        if self.counter != 0 && self.counter.is_multiple_of(REKEY_INTERVAL) {
            self.ratchet();
        }
        // 12-byte nonce = [4 zero bytes][8-byte LE global counter]. The counter
        // never resets, so nonces are unique across the whole connection
        // regardless of ratcheting — the AEAD safety requirement.
        if self.counter == u64::MAX {
            anyhow::bail!("session frame counter exhausted (this never happens in a real connection)");
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Ok(*Nonce::from_slice(&nonce))
    }
}

/// A bidirectional encrypted session over one connection. The dialer and
/// acceptor construct it with the same shared secret but mirrored send/recv
/// keys, so each side seals under the key the other opens with.
pub struct Session {
    send: DirCipher,
    recv: DirCipher,
}

impl Session {
    /// Build a session from the handshake's shared secret. `is_client` picks
    /// the send/recv direction: the dialer sends under `c2s`, the acceptor
    /// under `s2c`.
    pub fn new(shared_secret: &[u8], nonce_c: &[u8; 32], nonce_s: &[u8; 32], client_id: &ValidatorId, server_id: &ValidatorId, is_client: bool) -> Self {
        let key_c2s = derive_key(b"c2s", shared_secret, nonce_c, nonce_s, client_id, server_id);
        let key_s2c = derive_key(b"s2c", shared_secret, nonce_c, nonce_s, client_id, server_id);
        let (send_key, recv_key) = if is_client { (key_c2s, key_s2c) } else { (key_s2c, key_c2s) };
        Session { send: DirCipher::new(send_key), recv: DirCipher::new(recv_key) }
    }

    /// Seal one plaintext frame, returning the ciphertext (which includes the
    /// 16-byte Poly1305 tag). The nonce is implicit (the send counter), never
    /// transmitted — both sides advance in lock-step.
    pub fn seal(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.send.next_nonce()?;
        self.send.cipher.encrypt(&nonce, plaintext).map_err(|_| anyhow::anyhow!("AEAD seal failed"))
    }

    /// Open one ciphertext frame, returning the plaintext. Fails if the tag
    /// doesn't verify (tamper, or a frame delivered out of order — this is a
    /// strictly-ordered TCP stream, so either is a real error worth dropping
    /// the connection over).
    pub fn open(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.recv.next_nonce()?;
        self.recv.cipher.decrypt(&nonce, ciphertext).map_err(|_| anyhow::anyhow!("AEAD open failed: authentication tag did not verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (ValidatorId, ValidatorId) {
        (qchain_crypto::Pubkey::new([1u8; 32]), qchain_crypto::Pubkey::new([2u8; 32]))
    }

    /// A client and server built from the same shared secret can exchange
    /// sealed frames in both directions, and the counters advance in lock-step
    /// so ordered frames decrypt correctly.
    #[test]
    fn a_client_and_server_session_seal_and_open_both_directions() {
        let ss = [7u8; 32];
        let nc = [1u8; 32];
        let ns = [2u8; 32];
        let (cid, sid) = ids();
        let mut client = Session::new(&ss, &nc, &ns, &cid, &sid, true);
        let mut server = Session::new(&ss, &nc, &ns, &cid, &sid, false);

        // client -> server, three frames in order
        for msg in [b"hello".as_slice(), b"world", b"third"] {
            let ct = client.seal(msg).unwrap();
            assert_ne!(ct, msg, "frame must be encrypted, not plaintext");
            assert_eq!(server.open(&ct).unwrap(), msg);
        }
        // server -> client
        let ct = server.seal(b"reply").unwrap();
        assert_eq!(client.open(&ct).unwrap(), b"reply");
    }

    /// A tampered ciphertext fails to open (Poly1305 authentication).
    #[test]
    fn a_tampered_frame_fails_to_open() {
        let ss = [7u8; 32];
        let (cid, sid) = ids();
        let mut client = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, true);
        let mut server = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, false);
        let mut ct = client.seal(b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(server.open(&ct).is_err(), "a tampered frame must not authenticate");
    }

    /// A session built from a *different* shared secret (what a relay that
    /// swapped the ML-KEM keypair would end up with) cannot open frames sealed
    /// under the real secret — the channel-binding property in miniature.
    #[test]
    fn a_session_from_a_different_secret_cannot_open() {
        let (cid, sid) = ids();
        let mut client = Session::new(&[7u8; 32], &[1u8; 32], &[2u8; 32], &cid, &sid, true);
        let mut relay = Session::new(&[8u8; 32], &[1u8; 32], &[2u8; 32], &cid, &sid, false);
        let ct = client.seal(b"secret").unwrap();
        assert!(relay.open(&ct).is_err(), "a foreign shared secret must not decrypt the channel");
    }

    /// The ratchet stays in lock-step: sealing and opening well past several
    /// `REKEY_INTERVAL` boundaries keeps decrypting correctly, so the key
    /// re-derivation happens at the same frame on both sides.
    #[test]
    fn the_ratchet_stays_in_sync_across_rekey_boundaries() {
        let ss = [7u8; 32];
        let (cid, sid) = ids();
        let mut client = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, true);
        let mut server = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, false);
        // Two full rekey intervals plus a few, so the key has ratcheted twice.
        for i in 0..(REKEY_INTERVAL * 2 + 5) {
            let msg = format!("frame {i}");
            let ct = client.seal(msg.as_bytes()).unwrap();
            assert_eq!(server.open(&ct).unwrap(), msg.as_bytes(), "frame {i} must decrypt after ratcheting");
        }
    }

    /// Forward secrecy in miniature: a peer that keeps the INITIAL key and never
    /// ratchets (what an attacker holding only the connection-start key has)
    /// cannot open a frame sealed after the sender has ratcheted — the current
    /// key is a one-way derivation the initial key can't reproduce.
    #[test]
    fn a_non_ratcheting_holder_of_the_initial_key_cannot_open_post_ratchet_frames() {
        let ss = [7u8; 32];
        let (cid, sid) = ids();
        let mut client = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, true);
        let mut server = Session::new(&ss, &[1u8; 32], &[2u8; 32], &cid, &sid, false);
        // Advance past the first ratchet boundary with real traffic.
        for _ in 0..(REKEY_INTERVAL + 2) {
            let ct = client.seal(b"x").unwrap();
            server.open(&ct).unwrap();
        }
        // The next frame is sealed under the ratcheted key.
        let post = client.seal(b"post-ratchet-secret").unwrap();
        // A fresh server session that only ever knew the initial key (no
        // ratchet) — reconstruct just the initial recv cipher and try to open
        // the post-ratchet frame with the initial key at that frame's nonce.
        let initial_key = derive_key(b"c2s", &ss, &[1u8; 32], &[2u8; 32], &cid, &sid);
        let stale = ChaCha20Poly1305::new(Key::from_slice(&initial_key));
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&(REKEY_INTERVAL + 2).to_le_bytes());
        assert!(
            stale.decrypt(Nonce::from_slice(&nonce), post.as_slice()).is_err(),
            "the initial key must not open a frame sealed under the ratcheted key"
        );
    }
}
