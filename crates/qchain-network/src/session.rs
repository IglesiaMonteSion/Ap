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

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use qchain_core::ValidatorId;
use sha3::{Digest, Sha3_256};

const SESSION_DOMAIN: &[u8] = b"qchain-p2p-enc-v1";

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

/// One direction's AEAD state: a fixed key and a monotonic frame counter.
struct DirCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl DirCipher {
    fn new(key: [u8; 32]) -> Self {
        DirCipher { cipher: ChaCha20Poly1305::new(Key::from_slice(&key)), counter: 0 }
    }

    fn next_nonce(&mut self) -> anyhow::Result<Nonce> {
        // 12-byte nonce = [4 zero bytes][8-byte LE counter]. Unique per frame
        // for this direction's key, which is the AEAD safety requirement.
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
}
