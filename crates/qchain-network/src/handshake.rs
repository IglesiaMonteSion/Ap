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
//! Deliberately **not** confidentiality: P2P traffic here is public data
//! (blocks, votes, batches). The goal is authentication / anti-spoofing, so
//! there is no key exchange or encryption — that would be an optional
//! follow-up (ML-KEM, never X25519), out of scope here.
//!
//! **Honest scope of the "anti-MITM" property (audited):** the handshake stops
//! an *off-path* attacker (anyone who does not hold a member's private key)
//! from spoofing a validator — that is the DoS/anti-spoofing door gate it
//! genuinely delivers, and it is what closes the real gap. It does NOT resist
//! an *on-path* attacker who can transparently relay the three frames between
//! two honest validators (there is no channel binding, since there is no
//! encrypted channel to bind to). Such a relay could forge attribution of
//! *unsigned* messages between those two peers; it can never impersonate a
//! third identity or forge signed consensus traffic (votes/certs/vertex
//! proposals stay protected by their own signatures). Full relay resistance is
//! deferred to the optional ML-KEM channel follow-up, which would provide an
//! exporter to bind into the transcript.
//!
//! Wire protocol (each frame is `[u32 LE len][Borsh]`, same framing as an
//! `Envelope`):
//!   1. dialer  → acceptor: `HandshakeInit  { bundle_c, nonce_c }`
//!   2. acceptor → dialer:  `HandshakeResp  { bundle_s, nonce_s, sig_s }`
//!   3. dialer  → acceptor: `HandshakeFinal { sig_c }`
//!
//! where `sig_x = Sign_x( DOMAIN || role_x || network_id || client_id ||`
//! `server_id || nonce_c || nonce_s )`.

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::ValidatorId;
use qchain_crypto::{Keypair, MultiSignature, PublicKeyBundle};
use std::collections::HashSet;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HANDSHAKE_DOMAIN: &[u8] = b"qchain-p2p-auth-v1";
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
    keypair: Arc<Keypair>,
    network_id: [u8; 32],
    authorized: StdRwLock<HashSet<ValidatorId>>,
}

impl AuthState {
    pub fn new(keypair: Arc<Keypair>, network_id: [u8; 32], authorized: HashSet<ValidatorId>) -> Self {
        AuthState { keypair, network_id, authorized: StdRwLock::new(authorized) }
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
    bundle: PublicKeyBundle,
    nonce: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HandshakeResp {
    bundle: PublicKeyBundle,
    nonce: [u8; 32],
    signature: MultiSignature,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HandshakeFinal {
    signature: MultiSignature,
}

/// The bytes both parties sign. Symmetric in content (same identities and
/// nonces), separated only by the `role` byte so the dialer's and acceptor's
/// signatures are distinct and one cannot be replayed as the other.
fn transcript(role: u8, network_id: &[u8; 32], client_id: &ValidatorId, server_id: &ValidatorId, nonce_c: &[u8; 32], nonce_s: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 1 + 32 * 5);
    t.extend_from_slice(HANDSHAKE_DOMAIN);
    t.push(role);
    t.extend_from_slice(network_id);
    t.extend_from_slice(&client_id.0);
    t.extend_from_slice(&server_id.0);
    t.extend_from_slice(nonce_c);
    t.extend_from_slice(nonce_s);
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
pub async fn client_handshake(stream: &mut TcpStream, auth: &AuthState, expected: Option<ValidatorId>) -> anyhow::Result<ValidatorId> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let bundle_c = auth.keypair.public_key_bundle();
        let client_id = bundle_c.to_address();
        let nonce_c = fresh_nonce()?;
        write_frame(stream, &HandshakeInit { bundle: bundle_c, nonce: nonce_c }).await?;

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
        let t_server = transcript(ROLE_SERVER, &auth.network_id, &client_id, &server_id, &nonce_c, &resp.nonce);
        if !qchain_crypto::verify(&resp.bundle, &t_server, &resp.signature) {
            anyhow::bail!("peer {server_id}'s handshake signature did not verify");
        }

        let t_client = transcript(ROLE_CLIENT, &auth.network_id, &client_id, &server_id, &nonce_c, &resp.nonce);
        let sig_c = auth.keypair.sign(&t_client)?;
        write_frame(stream, &HandshakeFinal { signature: sig_c }).await?;
        Ok(server_id)
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
pub async fn server_handshake(stream: &mut TcpStream, auth: &AuthState) -> anyhow::Result<ValidatorId> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let init: HandshakeInit = read_frame(stream).await?;
        let client_id = init.bundle.to_address();
        if !auth.is_authorized(&client_id) {
            anyhow::bail!("inbound peer authenticated as {client_id}, which is not an authorized validator");
        }

        let bundle_s = auth.keypair.public_key_bundle();
        let server_id = bundle_s.to_address();
        let nonce_s = fresh_nonce()?;
        let t_server = transcript(ROLE_SERVER, &auth.network_id, &client_id, &server_id, &init.nonce, &nonce_s);
        let sig_s = auth.keypair.sign(&t_server)?;
        write_frame(stream, &HandshakeResp { bundle: bundle_s, nonce: nonce_s, signature: sig_s }).await?;

        let fin: HandshakeFinal = read_frame(stream).await?;
        let t_client = transcript(ROLE_CLIENT, &auth.network_id, &client_id, &server_id, &init.nonce, &nonce_s);
        if !qchain_crypto::verify(&init.bundle, &t_client, &fin.signature) {
            anyhow::bail!("inbound peer {client_id}'s handshake signature did not verify");
        }
        Ok(client_id)
    })
    .await
    .map_err(|_| anyhow::anyhow!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    fn auth_for(kp: &Arc<Keypair>, network_id: [u8; 32], authorized: &[ValidatorId]) -> AuthState {
        AuthState::new(kp.clone(), network_id, authorized.iter().cloned().collect())
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
        let seen_server = client_handshake(&mut stream, &auth_c, Some(id_s)).await.unwrap();
        let seen_client = server.await.unwrap().unwrap();

        assert_eq!(seen_server, id_s, "dialer must learn the acceptor's real id");
        assert_eq!(seen_client, id_c, "acceptor must learn the dialer's real id");
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
