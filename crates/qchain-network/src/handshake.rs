//! Authenticated P2P handshake (task #176 — "transporte P2P autenticado").
//!
//! The phase-1 transport is unauthenticated: `Envelope.from` is a
//! self-reported validator id, and anyone who can reach a validator's P2P
//! port can connect and send envelopes claiming to be any validator. The
//! application layer verifies the signatures *inside* votes/certificates/
//! vertex proposals, but the connection itself — and every unsigned message
//! type (requests, gossip attribution, version announcements) — is spoofable.
//!
//! This closes that at the transport layer with a **mutual challenge-response
//! run once per TCP connection, before any `Envelope`**, that:
//!
//! * ties each connection to a **known validator identity** (rejects
//!   non-members at the door — a DoS/spoofing gate the app layer can't
//!   provide, since a non-member can't complete the handshake at all);
//! * is **post-quantum by construction** — it reuses the validator's existing
//!   hybrid Ed25519 + ML-DSA-65 key (no new key material, no Noise/X25519),
//!   with overhead paid *only at connect time*, never per message;
//! * binds the network's `chain_id` into the signed transcript, so a
//!   validator from a *different* qchain network can't complete the handshake
//!   even if both run authenticated transport;
//! * is **anti-replay and anti-MITM**: each side contributes a fresh random
//!   nonce and both nonces + both identities are signed, with a role byte
//!   separating the two signatures so a captured signature can't be reflected
//!   back as the other party's.
//!
//! **Confidentiality is opt-in** via the `encrypt` flag (see `AuthState`). With
//! it off (the default when auth alone is on), this is exactly the v6.4.x
//! authentication-only handshake: P2P traffic is public data (blocks, votes,
//! batches) and stays in the clear. With it on, the same three frames also
//! carry an **ML-KEM-768** exchange (never X25519 — post-quantum by
//! construction), so both peers derive a shared secret and every subsequent
//! envelope is AEAD-encrypted (`session`).
//!
//! **How encryption closes the honest limitation of the auth-only handshake.**
//! Auth-only stops an *off-path* attacker (anyone without a member's private
//! key) from spoofing a validator, but it does NOT resist an *on-path*
//! attacker who transparently relays the three frames between two honest peers
//! (there is no channel binding, since there is no encrypted channel to bind
//! to). Such a relay could forge attribution of *unsigned* messages between
//! those peers. With `encrypt` on, the ML-KEM public key and ciphertext are
//! folded into the **signed transcript**, so a relay that substitutes its own
//! ML-KEM keypair to MITM the channel changes the transcript and breaks both
//! parties' signatures — the channel is cryptographically bound to the signed
//! identities. It never could impersonate a third identity or forge signed
//! consensus traffic (votes/certs stay protected by their own signatures);
//! encryption additionally closes the unsigned-message relay gap.
//!
//! Wire protocol (each frame is `[u32 LE len][Borsh]`, same framing as an
//! `Envelope`):
//!   1. dialer  → acceptor: `HandshakeInit  { bundle_c, nonce_c, kem_pk? }`
//!   2. acceptor → dialer:  `HandshakeResp  { bundle_s, nonce_s, kem_ct?, sig_s }`
//!   3. dialer  → acceptor: `HandshakeFinal { sig_c }`
//!
//! where `sig_x = Sign_x( DOMAIN || role_x || network_id || client_id ||`
//! `server_id || nonce_c || nonce_s || kem_pk || kem_ct )` — `kem_pk`/`kem_ct`
//! are empty when encryption is off. When encryption is on, the acceptor
//! encapsulates against `kem_pk` to produce `kem_ct` + the shared secret, and
//! the dialer decapsulates `kem_ct` to recover the identical secret.

use crate::session::Session;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::ValidatorId;
use qchain_crypto::{MultiSignature, PublicKeyBundle, Signer};
use std::collections::HashSet;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Single source of truth (shared with the remote signer's SignRaw allowlist).
const HANDSHAKE_DOMAIN: &[u8] = qchain_crypto::domains::P2P_AUTH_V1;
const ROLE_CLIENT: u8 = 0x01;
const ROLE_SERVER: u8 = 0x02;

/// A handshake frame is a public key bundle plus a signature — at most tens of
/// KB even for the opt-in triple combo (Ed25519 + ML-DSA-65 + SLH-DSA, whose
/// signature alone is ~30 KB), never megabytes. Bounded tightly (64 KB) so a
/// malformed length prefix can't drive a large pre-body allocation during the
/// still-unauthenticated handshake; combined with the concurrency cap in
/// `transport::accept_loop`, the total memory a flood of half-open handshakes
/// can hold is bounded to a small, fixed multiple of this.
const HANDSHAKE_FRAME_CAP: usize = 64 * 1024;

/// The whole handshake (three small frames) must complete inside this
/// window. A peer that connects and then stalls mid-handshake is dropped —
/// the handshake-tier equivalent of `transport::FIRST_ENVELOPE_TIMEOUT`,
/// closing the same "open a connection, send nothing" resource-exhaustion
/// shape one layer earlier.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared authentication material for a node running the authenticated
/// transport. `authorized` is interior-mutable so phase-3.3 dynamic rotation
/// can update the set of accepted validator identities at an epoch boundary
/// (alongside the peer set), letting a genuinely new registered validator
/// both be dialed *and* be accepted. For a fixed-membership network it is set
/// once at startup and never changes.
pub struct AuthState {
    /// The validator's consensus signer (tarea #193). Holds the identity key in
    /// process (`Keypair`) or talks to an out-of-process remote/HSM signer. It is
    /// the validator IDENTITY (`bundle().to_address()` == validator id) and — when
    /// no separate network key is configured (legacy) — also signs the handshake
    /// transcript. When a `network` key IS configured (auditoría #1), the consensus
    /// signer is used ONLY to have issued the delegation cert once at startup; the
    /// per-connection transcript is signed by the network key, never this one.
    signer: Arc<dyn qchain_crypto::Signer>,
    /// **Clave de RED separada (auditoría #1).** `Some((network_keypair, cert))` =
    /// la identidad P2P está DELEGADA en una `network_key` distinta de la de
    /// consenso: el handshake por-conexión se firma con `network_keypair` y se
    /// anuncia `cert` (que la clave de consenso emitió una vez, atando
    /// `network_addr → validator_id`). Una fuga de la clave de red permite
    /// impersonar la identidad P2P pero NO firmar bloques/votos. `None` = legacy:
    /// el handshake se firma con la clave de consenso (comportamiento previo).
    network: Option<(Arc<qchain_crypto::Keypair>, MultiSignature)>,
    network_id: [u8; 32],
    authorized: StdRwLock<HashSet<ValidatorId>>,
    /// When true, the handshake also runs an ML-KEM exchange and returns a
    /// `Session`, so the connection is AEAD-encrypted (`session`). When false
    /// (the default), the handshake is authentication-only (v6.4.x behavior)
    /// and returns no session — envelopes flow in the clear. A network must run
    /// all nodes with the same choice; a mismatch simply fails the handshake
    /// (the signed transcript differs, so signatures don't verify), the same
    /// coordinated-cutover requirement as turning auth on.
    encrypt: bool,
}

impl AuthState {
    /// Authentication-only handshake (v6.4.x). Equivalent to
    /// `new_with_encryption(.., false)`.
    pub fn new(signer: Arc<dyn qchain_crypto::Signer>, network_id: [u8; 32], authorized: HashSet<ValidatorId>) -> Self {
        Self::new_with_encryption(signer, network_id, authorized, false)
    }

    /// Like `new`, but `encrypt` selects whether the handshake also performs
    /// the ML-KEM exchange and encrypts the channel.
    pub fn new_with_encryption(signer: Arc<dyn qchain_crypto::Signer>, network_id: [u8; 32], authorized: HashSet<ValidatorId>, encrypt: bool) -> Self {
        AuthState { signer, network: None, network_id, authorized: StdRwLock::new(authorized), encrypt }
    }

    /// Like `new_with_encryption`, but the P2P handshake is signed by a SEPARATE
    /// `network_key` (auditoría #1) instead of the consensus key. `network_cert`
    /// is the delegation cert the consensus key issued once at startup
    /// (`NETWORK_KEY_CERT_V1 ‖ network_id ‖ validator_id ‖ network_addr`); it is
    /// advertised in the handshake so peers can verify the binding. The consensus
    /// key thus never signs a per-connection P2P transcript.
    pub fn new_with_network_key(
        signer: Arc<dyn qchain_crypto::Signer>,
        network_keypair: Arc<qchain_crypto::Keypair>,
        network_cert: MultiSignature,
        network_id: [u8; 32],
        authorized: HashSet<ValidatorId>,
        encrypt: bool,
    ) -> Self {
        AuthState {
            signer,
            network: Some((network_keypair, network_cert)),
            network_id,
            authorized: StdRwLock::new(authorized),
            encrypt,
        }
    }

    /// Whether this node runs the encrypted (ML-KEM + AEAD) transport.
    pub fn encrypts(&self) -> bool {
        self.encrypt
    }

    /// Signs a handshake transcript: with the SEPARATE network key if configured
    /// (auditoría #1), else with the consensus signer (legacy). Both go through
    /// the typed `sign_network_handshake` (which enforces the P2P_AUTH_V1 domain).
    fn sign_handshake(&self, transcript: &[u8]) -> anyhow::Result<MultiSignature> {
        match &self.network {
            Some((net_kp, _)) => net_kp.sign_network_handshake(transcript),
            None => self.signer.sign_network_handshake(transcript),
        }
    }

    /// The (network_bundle, network_cert) pair to advertise in the handshake, or
    /// `None` in legacy mode (the consensus key signs the transcript directly).
    fn network_advert(&self) -> Option<(PublicKeyBundle, MultiSignature)> {
        self.network.as_ref().map(|(kp, cert)| (kp.public_key_bundle(), cert.clone()))
    }

    /// Verifies a peer's handshake signature over `transcript`, honoring the
    /// network-key delegation (auditoría #1). `consensus_bundle` is the peer's
    /// validator identity (already checked `is_authorized`). If the peer advertised
    /// a `(network_bundle, network_cert)`, the cert MUST bind that network key to
    /// this validator under our `network_id`, and the transcript MUST verify under
    /// the network key. Otherwise (legacy peer) the transcript verifies under the
    /// consensus key directly.
    fn verify_peer_handshake(
        &self,
        consensus_bundle: &PublicKeyBundle,
        network: &Option<(PublicKeyBundle, MultiSignature)>,
        transcript: &[u8],
        signature: &MultiSignature,
    ) -> bool {
        match network {
            Some((net_bundle, cert)) => {
                let validator_id = consensus_bundle.to_address();
                let network_addr = net_bundle.to_address();
                qchain_crypto::verify_network_key_cert(consensus_bundle, &self.network_id, &validator_id.0, &network_addr.0, cert)
                    && qchain_crypto::verify(net_bundle, transcript, signature)
            }
            None => qchain_crypto::verify(consensus_bundle, transcript, signature),
        }
    }

    pub fn is_authorized(&self, id: &ValidatorId) -> bool {
        self.authorized.read().expect("authorized lock not poisoned").contains(id)
    }

    /// Replace the set of accepted validator identities (rotation). Kept in
    /// lock-step with `Network::set_peers` by the caller so the dial set and
    /// the accept set never drift.
    pub fn set_authorized(&self, authorized: HashSet<ValidatorId>) {
        *self.authorized.write().expect("authorized lock not poisoned") = authorized;
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HandshakeInit {
    /// The dialer's CONSENSUS bundle — its validator identity (`to_address()`).
    bundle: PublicKeyBundle,
    nonce: [u8; 32],
    /// The dialer's ephemeral ML-KEM public key. `Some` only when the dialer
    /// runs the encrypted transport; `None` for authentication-only.
    kem_pk: Option<Vec<u8>>,
    /// Auditoría #1 — the dialer's SEPARATE network key + its delegation cert.
    /// `Some((network_bundle, cert))` when the dialer runs a network key (the
    /// transcript in `HandshakeFinal` is signed by it); `None` legacy (the
    /// transcript is signed by the consensus `bundle`).
    network: Option<(PublicKeyBundle, MultiSignature)>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HandshakeResp {
    /// The acceptor's CONSENSUS bundle — its validator identity.
    bundle: PublicKeyBundle,
    nonce: [u8; 32],
    /// The acceptor's ML-KEM ciphertext (encapsulated against `kem_pk`).
    /// `Some` only in the encrypted transport.
    kem_ct: Option<Vec<u8>>,
    signature: MultiSignature,
    /// Auditoría #1 — the acceptor's SEPARATE network key + delegation cert (as
    /// in `HandshakeInit`). `signature` is by the network key when this is `Some`.
    network: Option<(PublicKeyBundle, MultiSignature)>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HandshakeFinal {
    signature: MultiSignature,
}

/// The bytes both parties sign. Symmetric in content (same identities and
/// nonces), separated only by the `role` byte so the dialer's and acceptor's
/// signatures are distinct and one cannot be replayed as the other. The ML-KEM
/// public key and ciphertext are folded in (length-delimited so their boundary
/// is unambiguous) — empty when encryption is off — so a signed handshake
/// **binds the channel**: a relay that swaps in its own ML-KEM keypair changes
/// these bytes and both signatures fail to verify.
#[allow(clippy::too_many_arguments)] // each field is a distinct, meaningful part of the signed transcript
fn transcript(role: u8, network_id: &[u8; 32], client_id: &ValidatorId, server_id: &ValidatorId, nonce_c: &[u8; 32], nonce_s: &[u8; 32], kem_pk: &[u8], kem_ct: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 1 + 32 * 5 + 8 + kem_pk.len() + kem_ct.len());
    t.extend_from_slice(HANDSHAKE_DOMAIN);
    t.push(role);
    t.extend_from_slice(network_id);
    t.extend_from_slice(&client_id.0);
    t.extend_from_slice(&server_id.0);
    t.extend_from_slice(nonce_c);
    t.extend_from_slice(nonce_s);
    t.extend_from_slice(&(kem_pk.len() as u32).to_le_bytes());
    t.extend_from_slice(kem_pk);
    t.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
    t.extend_from_slice(kem_ct);
    t
}

fn fresh_nonce() -> anyhow::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    // Fail the handshake as a normal error rather than panicking the task/await
    // path if OS randomness is somehow unavailable — the caller already treats a
    // handshake error like any other connect failure (drop and retry).
    getrandom::getrandom(&mut n).map_err(|e| anyhow::anyhow!("OS randomness unavailable for a P2P handshake nonce: {e}"))?;
    Ok(n)
}

async fn write_frame<T: BorshSerialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<()> {
    let bytes = borsh::to_vec(value)?;
    if bytes.len() > HANDSHAKE_FRAME_CAP {
        anyhow::bail!("handshake frame too large to send: {} bytes", bytes.len());
    }
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: BorshDeserialize>(stream: &mut TcpStream) -> anyhow::Result<T> {
    let len = stream.read_u32_le().await? as usize;
    if len > HANDSHAKE_FRAME_CAP {
        anyhow::bail!("rejecting oversized handshake frame: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(borsh::from_slice(&buf)?)
}

/// Dialer side. Runs the handshake over an already-connected stream and
/// returns the peer's authenticated validator id. Fails (dropping the
/// connection, which the caller treats like any connect failure and retries)
/// if the peer isn't an authorized validator, if — when `expected` is `Some`
/// — it authenticates as a different id than the one we dialed this address
/// for, or if any signature doesn't verify.
pub async fn client_handshake(stream: &mut TcpStream, auth: &AuthState, expected: Option<ValidatorId>) -> anyhow::Result<(ValidatorId, Option<Session>)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let bundle_c = auth.signer.bundle();
        let client_id = bundle_c.to_address();
        let nonce_c = fresh_nonce()?;
        // Encrypted transport: a fresh ephemeral ML-KEM keypair per connection.
        // `kem_secret` never leaves this function; `kem_pk` goes on the wire.
        let (kem_pk, kem_secret): (Vec<u8>, Option<Vec<u8>>) = if auth.encrypt {
            let (pk, sk) = qchain_crypto::kem::keypair()?;
            (pk, Some(sk))
        } else {
            (Vec::new(), None)
        };
        let kem_pk_field = if auth.encrypt { Some(kem_pk.clone()) } else { None };
        write_frame(stream, &HandshakeInit { bundle: bundle_c, nonce: nonce_c, kem_pk: kem_pk_field, network: auth.network_advert() }).await?;

        let resp: HandshakeResp = read_frame(stream).await?;
        let server_id = resp.bundle.to_address();
        if !auth.is_authorized(&server_id) {
            anyhow::bail!("peer authenticated as {server_id}, which is not an authorized validator");
        }
        // Require the peer to authenticate as exactly the id we dialed this
        // address for (anti-misrouting). A dial to an address not in the peer
        // set (`expected == None`) is refused rather than accepted on
        // membership alone: under authenticated transport this node only ever
        // dials known peers, so a `None` here is unexpected and gets no
        // membership-only fallback that a relay could exploit.
        match expected {
            Some(want) if server_id == want => {}
            Some(want) => anyhow::bail!("dialed a peer expecting {want} but it authenticated as {server_id}"),
            None => anyhow::bail!("refusing to authenticate {server_id} at an address that is not a known peer"),
        }
        // In encrypted mode the acceptor must have returned a ciphertext bound
        // to our kem_pk; its absence means a mode mismatch (peer not encrypting).
        let kem_ct: Vec<u8> = match (auth.encrypt, resp.kem_ct) {
            (true, Some(ct)) => ct,
            (true, None) => anyhow::bail!("peer did not return an ML-KEM ciphertext — it is not running the encrypted transport"),
            (false, _) => Vec::new(),
        };
        let t_server = transcript(ROLE_SERVER, &auth.network_id, &client_id, &server_id, &nonce_c, &resp.nonce, &kem_pk, &kem_ct);
        if !auth.verify_peer_handshake(&resp.bundle, &resp.network, &t_server, &resp.signature) {
            anyhow::bail!("peer {server_id}'s handshake signature did not verify");
        }

        let t_client = transcript(ROLE_CLIENT, &auth.network_id, &client_id, &server_id, &nonce_c, &resp.nonce, &kem_pk, &kem_ct);
        let sig_c = auth.sign_handshake(&t_client)?;
        write_frame(stream, &HandshakeFinal { signature: sig_c }).await?;

        // Only after the transcript (which binds kem_pk/kem_ct) verified do we
        // decapsulate — so the shared secret is bound to the authenticated peer.
        let session = match kem_secret {
            Some(sk) => {
                let shared = qchain_crypto::kem::decapsulate(&sk, &kem_ct)?;
                Some(Session::new(&shared, &nonce_c, &resp.nonce, &client_id, &server_id, true))
            }
            None => None,
        };
        Ok((server_id, session))
    })
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"))?
}

/// Acceptor side. Reads the dialer's `HandshakeInit`, rejects it immediately
/// if it doesn't claim an authorized validator identity, then proves its own
/// identity and verifies the dialer's proof. Returns the dialer's
/// authenticated validator id — which the caller uses as the true sender of
/// every subsequent envelope on this connection, ignoring the spoofable
/// `Envelope.from`.
pub async fn server_handshake(stream: &mut TcpStream, auth: &AuthState) -> anyhow::Result<(ValidatorId, Option<Session>)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let init: HandshakeInit = read_frame(stream).await?;
        let client_id = init.bundle.to_address();
        if !auth.is_authorized(&client_id) {
            anyhow::bail!("inbound peer authenticated as {client_id}, which is not an authorized validator");
        }

        // In encrypted mode, encapsulate against the dialer's ML-KEM public key
        // to produce the ciphertext (sent back) and the shared secret (kept).
        let (kem_pk, kem_ct, shared): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = match (auth.encrypt, init.kem_pk) {
            (true, Some(pk)) => {
                let (ct, ss) = qchain_crypto::kem::encapsulate(&pk)?;
                (pk, ct, Some(ss))
            }
            (true, None) => anyhow::bail!("inbound peer sent no ML-KEM public key — it is not running the encrypted transport"),
            (false, _) => (Vec::new(), Vec::new(), None),
        };

        let bundle_s = auth.signer.bundle();
        let server_id = bundle_s.to_address();
        let nonce_s = fresh_nonce()?;
        let t_server = transcript(ROLE_SERVER, &auth.network_id, &client_id, &server_id, &init.nonce, &nonce_s, &kem_pk, &kem_ct);
        let sig_s = auth.sign_handshake(&t_server)?;
        let kem_ct_field = if auth.encrypt { Some(kem_ct.clone()) } else { None };
        write_frame(stream, &HandshakeResp { bundle: bundle_s, nonce: nonce_s, kem_ct: kem_ct_field, signature: sig_s, network: auth.network_advert() }).await?;

        let fin: HandshakeFinal = read_frame(stream).await?;
        let t_client = transcript(ROLE_CLIENT, &auth.network_id, &client_id, &server_id, &init.nonce, &nonce_s, &kem_pk, &kem_ct);
        if !auth.verify_peer_handshake(&init.bundle, &init.network, &t_client, &fin.signature) {
            anyhow::bail!("inbound peer {client_id}'s handshake signature did not verify");
        }
        let session = shared.map(|ss| Session::new(&ss, &init.nonce, &nonce_s, &client_id, &server_id, false));
        Ok((client_id, session))
    })
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;
    use tokio::net::{TcpListener, TcpStream};

    fn auth_for(kp: &Arc<Keypair>, network_id: [u8; 32], authorized: &[ValidatorId]) -> AuthState {
        AuthState::new(kp.clone(), network_id, authorized.iter().cloned().collect())
    }

    fn auth_enc(kp: &Arc<Keypair>, network_id: [u8; 32], authorized: &[ValidatorId]) -> AuthState {
        AuthState::new_with_encryption(kp.clone(), network_id, authorized.iter().cloned().collect(), true)
    }

    /// Build an `AuthState` whose P2P handshake is signed by a SEPARATE network
    /// key (auditoría #1). Generates a fresh network keypair and has the
    /// consensus key issue the delegation cert once. Returns the AuthState plus
    /// the network keypair (so a test can tamper with the cert if it wants).
    fn auth_netkey(consensus: &Arc<Keypair>, network_id: [u8; 32], authorized: &[ValidatorId]) -> (AuthState, Arc<Keypair>) {
        let net_kp = Arc::new(Keypair::generate().unwrap());
        let validator_id = consensus.pubkey();
        let network_addr = net_kp.pubkey();
        let cert = qchain_crypto::sign_network_key_cert(consensus, &network_id, &validator_id.0, &network_addr.0).unwrap();
        let auth = AuthState::new_with_network_key(consensus.clone(), net_kp.clone(), cert, network_id, authorized.iter().cloned().collect(), false);
        (auth, net_kp)
    }

    /// Two validators that each know the other is authorized complete the
    /// handshake and each learns the other's real id.
    #[tokio::test]
    async fn two_known_validators_complete_the_handshake() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let auth_s = auth_for(&kp_s, net, &[id_c, id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let auth_c = auth_for(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (seen_server, sess_c) = client_handshake(&mut stream, &auth_c, Some(id_s)).await.unwrap();
        let (seen_client, sess_s) = server.await.unwrap().unwrap();

        assert_eq!(seen_server, id_s, "dialer must learn the acceptor's real id");
        assert_eq!(seen_client, id_c, "acceptor must learn the dialer's real id");
        assert!(sess_c.is_none() && sess_s.is_none(), "auth-only handshake returns no encrypted session");
    }

    /// The encrypted handshake: two known validators running the encrypted
    /// transport complete the handshake, each learns the other's id, AND each
    /// gets a `Session` whose derived keys agree — a frame sealed by one opens
    /// on the other. This is the ML-KEM exchange + channel established
    /// end-to-end over real TCP.
    #[tokio::test]
    async fn the_encrypted_handshake_establishes_a_working_session() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let auth_s = auth_enc(&kp_s, net, &[id_c, id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let auth_c = auth_enc(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (seen_server, sess_c) = client_handshake(&mut stream, &auth_c, Some(id_s)).await.unwrap();
        let (seen_client, sess_s) = server.await.unwrap().unwrap();

        assert_eq!(seen_server, id_s);
        assert_eq!(seen_client, id_c);
        let mut sess_c = sess_c.expect("encrypted handshake must return a client session");
        let mut sess_s = sess_s.expect("encrypted handshake must return a server session");
        // The two sessions share the KEM secret: a sealed frame round-trips.
        let ct = sess_c.seal(b"encrypted consensus traffic").unwrap();
        assert_eq!(sess_s.open(&ct).unwrap(), b"encrypted consensus traffic");
        let ct2 = sess_s.seal(b"reply").unwrap();
        assert_eq!(sess_c.open(&ct2).unwrap(), b"reply");
    }

    /// Auditoría #1 — two validators each running a SEPARATE network key
    /// complete the handshake, and each still learns the other's CONSENSUS id
    /// (the validator identity). The per-connection transcript is signed by the
    /// network key; the delegation cert (issued by the consensus key) binds it
    /// to the consensus id, and the peer verifies that binding. The consensus
    /// key never signed the per-connection handshake.
    #[tokio::test]
    async fn separate_network_keys_authenticate_and_still_reveal_the_consensus_id() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (auth_s, net_s) = auth_netkey(&kp_s, net, &[id_c, id_s]);
        // The network key's own address is NOT the validator id — proving the
        // handshake authenticates the CONSENSUS id via the cert, not the signer.
        assert_ne!(net_s.pubkey(), id_s, "network key address differs from the validator id");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let (auth_c, _net_c) = auth_netkey(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (seen_server, _) = client_handshake(&mut stream, &auth_c, Some(id_s)).await.unwrap();
        let (seen_client, _) = server.await.unwrap().unwrap();

        assert_eq!(seen_server, id_s, "dialer learns the acceptor's CONSENSUS id even though the network key signed");
        assert_eq!(seen_client, id_c, "acceptor learns the dialer's CONSENSUS id");
    }

    /// A network key with a delegation cert bound to a DIFFERENT validator id
    /// is rejected: an attacker who leaks a network key cannot present it under
    /// someone else's consensus identity, because the cert (which the consensus
    /// key signed over `validator_id ‖ network_addr`) only verifies for the
    /// real validator. Here the acceptor advertises kp_s's consensus id but a
    /// cert that kp_s never issued for that network key.
    #[tokio::test]
    async fn a_network_cert_for_the_wrong_validator_is_rejected() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let kp_evil = Arc::new(Keypair::generate().unwrap()); // an unrelated consensus key
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Acceptor advertises kp_s's consensus bundle, but the cert was issued by
        // kp_evil (a key that is NOT kp_s) — so it does not verify under kp_s.
        let net_kp = Arc::new(Keypair::generate().unwrap());
        let forged_cert = qchain_crypto::sign_network_key_cert(&kp_evil, &net, &id_s.0, &net_kp.pubkey().0).unwrap();
        let auth_s = AuthState::new_with_network_key(kp_s.clone(), net_kp, forged_cert, net, [id_c, id_s].into_iter().collect(), false);
        let _server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = server_handshake(&mut stream, &auth_s).await;
        });

        let (auth_c, _net_c) = auth_netkey(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let client_res = client_handshake(&mut stream, &auth_c, Some(id_s)).await;
        assert!(client_res.is_err(), "a network cert not signed by the claimed validator must be rejected");
    }

    /// A network-keyed node and a LEGACY (consensus-key-signed) node interoperate:
    /// the legacy peer advertises `network: None` and signs with the consensus
    /// key, the network-keyed peer advertises its cert — both verify. Backward
    /// compatibility during a mixed rollout.
    #[tokio::test]
    async fn a_network_keyed_node_interoperates_with_a_legacy_node() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: legacy (consensus key signs the handshake, no network advert).
        let auth_s = auth_for(&kp_s, net, &[id_c, id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        // Client: network-keyed.
        let (auth_c, _net_c) = auth_netkey(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let (seen_server, _) = client_handshake(&mut stream, &auth_c, Some(id_s)).await.unwrap();
        let (seen_client, _) = server.await.unwrap().unwrap();
        assert_eq!(seen_server, id_s);
        assert_eq!(seen_client, id_c, "legacy acceptor still authenticates a network-keyed dialer via its cert");
    }

    /// A mode mismatch fails to connect: an encrypting dialer against an
    /// auth-only acceptor (and vice versa) must not complete the handshake —
    /// the coordinated-cutover requirement, the same as auth-on vs auth-off.
    #[tokio::test]
    async fn an_encryption_mode_mismatch_fails_to_handshake() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Acceptor is auth-only; dialer encrypts.
        let auth_s = auth_for(&kp_s, net, &[id_c, id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let auth_c = auth_enc(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let res = client_handshake(&mut stream, &auth_c, Some(id_s)).await;
        assert!(res.is_err(), "an encrypting dialer must not complete a handshake with an auth-only acceptor");
        assert!(server.await.unwrap().is_err(), "the auth-only acceptor must reject the encrypting dialer");
    }

    /// A connector whose id is not in the acceptor's authorized set is
    /// rejected at the door — the whole point of the gate.
    #[tokio::test]
    async fn an_unauthorized_connector_is_rejected() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // The server only authorizes itself — the connector is a stranger.
        let auth_s = auth_for(&kp_s, net, &[id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let auth_c = auth_for(&kp_c, net, &[kp_c.pubkey(), id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let client_res = client_handshake(&mut stream, &auth_c, Some(id_s)).await;

        assert!(server.await.unwrap().is_err(), "acceptor must reject a non-member connector");
        assert!(client_res.is_err(), "dialer's handshake must fail once the acceptor drops it");
    }

    /// A validator carrying a *different* network's chain_id can't complete
    /// the handshake even though both sides run authenticated transport and
    /// both know the other's id — the cross-network binding.
    #[tokio::test]
    async fn a_peer_from_a_different_network_cannot_handshake() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Different network_id on each side.
        let auth_s = auth_for(&kp_s, [1u8; 32], &[id_c, id_s]);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_handshake(&mut stream, &auth_s).await
        });

        let auth_c = auth_for(&kp_c, [2u8; 32], &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let client_res = client_handshake(&mut stream, &auth_c, Some(id_s)).await;

        assert!(server.await.unwrap().is_err(), "signatures over different network ids must not cross-verify");
        assert!(client_res.is_err(), "the dialer must reject the acceptor's signature bound to a different network");
    }

    /// The dialer rejects a peer that authenticates as a *different* (but
    /// still authorized) validator than the one it dialed this address for —
    /// anti-misrouting.
    #[tokio::test]
    async fn dialing_a_specific_id_rejects_a_different_authorized_id() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let kp_other = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let id_other = kp_other.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let auth_s = auth_for(&kp_s, net, &[id_c, id_s, id_other]);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = server_handshake(&mut stream, &auth_s).await;
        });

        let auth_c = auth_for(&kp_c, net, &[id_c, id_s, id_other]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // We dialed expecting id_other, but the peer is actually id_s.
        let res = client_handshake(&mut stream, &auth_c, Some(id_other)).await;
        assert!(res.is_err(), "authenticating as a different id than dialed must be rejected");
    }

    /// Dialing with no expected id (an address not in the peer set) is refused
    /// under authenticated transport, even against an authorized member — the
    /// anti-misrouting stance: this node only ever dials known peers, so there
    /// is no membership-only fallback for a `None`-expected dial to exploit.
    #[tokio::test]
    async fn dialing_with_no_expected_id_is_refused_even_for_a_member() {
        let kp_c = Arc::new(Keypair::generate().unwrap());
        let kp_s = Arc::new(Keypair::generate().unwrap());
        let id_c = kp_c.pubkey();
        let id_s = kp_s.pubkey();
        let net = [9u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let auth_s = auth_for(&kp_s, net, &[id_c, id_s]);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = server_handshake(&mut stream, &auth_s).await;
        });

        let auth_c = auth_for(&kp_c, net, &[id_c, id_s]);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let res = client_handshake(&mut stream, &auth_c, None).await;
        assert!(res.is_err(), "a None-expected dial must be refused even against an authorized member");
    }
}

#[cfg(test)]
mod fuzz_proptests {
    //! Property tests del handshake P2P PRE-AUTENTICACIÓN (roadmap #14). Los frames
    //! del handshake (`HandshakeInit`/`Resp`/`Final`) son lo PRIMERO que un nodo
    //! con auth lee de una conexión entrante, ANTES de verificar identidad — la
    //! superficie más expuesta. Un `read_frame` decodifica bytes arbitrarios de un
    //! atacante (tope `HANDSHAKE_FRAME_CAP`); deserializarlos nunca debe panicar.
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_handshake_frames(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
            let _ = borsh::from_slice::<HandshakeInit>(&bytes);
            let _ = borsh::from_slice::<HandshakeResp>(&bytes);
            let _ = borsh::from_slice::<HandshakeFinal>(&bytes);
        }
    }
}
