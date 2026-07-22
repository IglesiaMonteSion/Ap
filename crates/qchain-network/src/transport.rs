//! Real TCP transport for the qchain P2P layer (design: `ARCHITECTURE.md`
//! §1). Framing: `[u32 LE length][Borsh-encoded Envelope]`.
//!
//! **Two real optimizations closed here, requested explicitly by the user
//! after asking whether Qchain's throughput could be raised without
//! weakening security - evaluated first, then implemented once approved.**
//! Neither touches cryptography, consensus safety, or any security-relevant
//! decision; both are pure transport-layer engineering:
//!
//! 1. **Persistent, reused connections per peer**, replacing the phase-1
//!    design where every single send opened a fresh short-lived TCP
//!    connection (see `project-lessons-learned` for the real ephemeral-port
//!    exhaustion this caused at n=27 under heavy message churn - that
//!    finding is exactly the failure mode this closes, not a coincidence).
//!    A steady peer now pays one TCP handshake total, not one per message;
//!    a broken connection is detected on the failing write and transparently
//!    replaced with a fresh one, retried once, before the caller ever sees
//!    an error - the same best-effort-with-retry contract `send_to`/
//!    `broadcast` already had, just faster in the common case.
//! 2. **Borsh instead of JSON** for the wire encoding - a binary format
//!    already used throughout this codebase for on-chain account data
//!    (`Instruction`/`Message`/`PublicKeyBundle` etc. already derive it),
//!    smaller on the wire and cheaper to (de)serialize than JSON's
//!    text/hex encoding, with zero change to what's actually being sent.

use crate::handshake::{client_handshake, server_handshake, AuthState};
use crate::limits::{BandwidthMeter, ConnTracker, IpGuard, P2pLimits};
use crate::message::{Envelope, NetMessage};
use crate::session::Session;
use qchain_core::ValidatorId;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};

/// A cached outbound connection: the TCP stream plus, when the encrypted
/// transport is on, the AEAD `Session` established during the handshake. The
/// two live together so a write can seal under the session's send key and a
/// reconnect fully replaces both (a fresh handshake mints a fresh session).
/// `session` is `None` for the unauthenticated or auth-only transport, in
/// which case framing is byte-identical to before this field existed.
struct PeerConn {
    stream: TcpStream,
    session: Option<Session>,
}

/// Bounds how long a single `send_to` write attempt may block on a
/// half-stuck peer connection before being treated as a failure - see
/// `send_to`'s doc comment for the real deadlock this closes. Generous
/// relative to this project's own real round intervals (as low as 300ms in
/// live testnets this session) and real message sizes (a handful of
/// megabytes at most), so a healthy peer's connection is never spuriously
/// timed out under real load - only a connection that has genuinely
/// stopped draining.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Post-compromise security: bound an ENCRYPTED connection's lifetime so a
/// transient session-key compromise heals within a bounded window. Once a
/// session has sealed this many frames, the transport drops the cached
/// connection and re-dials, which re-runs the full handshake and mints a FRESH
/// ephemeral ML-KEM secret the attacker never saw — from that point the channel
/// is secure again even if the old session key leaked. This deliberately reuses
/// the existing, well-tested reconnect + handshake path instead of an in-band
/// rekey protocol: a rekey double-ratchet would add stateful, desync-prone
/// coordination to the transport (this project's most freeze-bug-prone layer)
/// for a defense-in-depth confidentiality property whose payloads are already
/// signed. Worst case of forcing a reconnect is one extra handshake — the same
/// thing that happens on any natural network blip. Large enough that the
/// periodic handshake is negligible churn (natural reconnects heal far more
/// often in practice); this is a guaranteed ceiling on the exposure window, not
/// the common case. A non-encrypted connection (`session == None`) has no
/// channel secret to heal, so it is never force-recycled.
const CONNECTION_REKEY_FRAMES: u64 = 1 << 20; // 1,048,576 frames

/// Caps how many inbound authenticated handshakes may be in flight at once
/// (task #176 hardening). Only meaningful when auth is on. Each in-flight
/// handshake holds a small pre-authentication allocation and forces the node
/// to do one hybrid PQC sign; without a cap, an attacker opening connections
/// and stalling mid-handshake (or replaying a *public* validator bundle it
/// can't finish) could accumulate memory/fds/CPU without bound — exactly the
/// unbounded-growth class this project has been OOM-killed by before, but on
/// the new pre-auth surface. The permit is held only for the duration of the
/// handshake, NOT the connection's lifetime, so an established persistent
/// connection never occupies a slot; legit validators handshake once and hold
/// a slot for milliseconds, so this bound is far above real concurrent-join
/// load while still bounding a flood. Auth-off transport never touches this.
const MAX_CONCURRENT_INBOUND_HANDSHAKES: usize = 256;

/// Global hard ceiling on any single frame's body length. The largest legitimate
/// message (a quorum certificate at a large validator set — measured ~1.12 MB at
/// n=500) fits far under this; it only bounds the pre-decode allocation a
/// malformed length prefix could otherwise drive. Tightened from the old 64 MiB
/// to 16 MiB (still ~14x a measured n=500 certificate, room for very large sets).
const GLOBAL_FRAME_CAP: usize = 16 * 1024 * 1024;

/// Once a message's length prefix (header) has been read, its body must arrive
/// within this window (task #208 — slowloris defense). A peer that announces "a
/// 1 MiB message follows" then trickles the body one byte per minute is dropped.
/// Generous for a real ~1 MiB message even on a slow link, far tighter than a
/// trickle.
const BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// How long an ESTABLISHED connection may sit idle waiting for the next message's
/// header before it is recycled. Two live validators exchange traffic every round
/// (empty vertices are still proposed + broadcast every `round_interval_ms`, as
/// low as 500 ms) plus a version announce every ~30 s, so 180 s is ~360 idle
/// rounds — a connection quiet that long is dead/wedged, and recycling it (the
/// peer re-dials) is harmless. Bounds "connect, send one message, then hold the
/// connection open forever." The FIRST message keeps the tighter
/// `FIRST_ENVELOPE_TIMEOUT`.
const IDLE_MESSAGE_TIMEOUT: Duration = Duration::from_secs(180);

/// The per-connection read timeouts, bundled to keep `handle_inbound`'s
/// signature readable.
#[derive(Clone, Copy)]
struct Timeouts {
    first: Duration,
    idle: Duration,
    body: Duration,
}

impl Timeouts {
    const DEFAULT: Timeouts = Timeouts { first: FIRST_ENVELOPE_TIMEOUT, idle: IDLE_MESSAGE_TIMEOUT, body: BODY_TIMEOUT };
}

/// Per-message-type wire-size cap (length prefix + body), enforced AFTER the
/// envelope is decoded so its type is known. `GLOBAL_FRAME_CAP` bounds the
/// pre-decode allocation; this rejects, e.g., a 16 MiB "Vote" that fit under the
/// global cap but is absurd for its type. Every cap is a generous multiple of the
/// real measured message so honest traffic never trips it, and none exceeds
/// `GLOBAL_FRAME_CAP`.
fn max_frame_len_for(msg: &NetMessage) -> usize {
    match msg {
        // Tiny fixed-shape control messages (a digest + one signature at most).
        NetMessage::Vote { .. }
        | NetMessage::CertificateRequest { .. }
        | NetMessage::WorkerBatchRequest { .. }
        | NetMessage::VersionAnnounce { .. } => 64 * 1024,
        // One transaction (~5.5 KB, capped at MAX_TRANSACTION_BYTES=320 KB) + overhead.
        NetMessage::TransactionGossip(_) => 512 * 1024,
        // A vertex plus the author's signature.
        NetMessage::VertexProposal { .. } => 512 * 1024,
        // One worker lane's batch of transactions (bounded in practice by the
        // per-round inclusion byte cap, ~1 MiB); 8 MiB is generous headroom.
        NetMessage::WorkerBatchGossip { .. } | NetMessage::WorkerBatchResponse { .. } => 8 * 1024 * 1024,
        // A quorum certificate — the largest type; one hybrid signature per
        // signer, scaling with the validator set.
        NetMessage::CertificateBroadcast(_) | NetMessage::CertificateResponse(_) => GLOBAL_FRAME_CAP,
    }
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: ValidatorId,
    pub addr: SocketAddr,
}

/// A connected node's outbound handle plus the channel its inbound listener
/// feeds. `recv()` on the returned receiver is how a node observes
/// messages from every peer, tagged with the sender's validator id.
///
/// `connections` caches one persistent outbound `TcpStream` per peer
/// address, each behind its own mutex so writes to different peers never
/// block each other, while concurrent writes to the *same* peer serialize
/// correctly instead of interleaving and corrupting the length-prefixed
/// framing.
pub struct Network {
    self_id: ValidatorId,
    /// The peers this node dials/broadcasts to. Interior-mutable (behind a
    /// `std::sync::RwLock`, held only for a cheap clone/lookup, never across an
    /// await) so phase-3.3 dynamic rotation can update the peer set at runtime —
    /// `set_peers` — from the on-chain registry addresses as the committee
    /// changes, letting a genuinely new validator be dialed automatically. For a
    /// fixed-membership network it is set once at startup and never changes.
    peers: StdRwLock<Vec<PeerInfo>>,
    connections: Mutex<HashMap<SocketAddr, Arc<Mutex<PeerConn>>>>,
    /// When `Some`, every connection — inbound and outbound — is
    /// authenticated with a per-connection ML-DSA handshake before any
    /// `Envelope` flows (task #176, see `handshake`). When `None` (the
    /// default) the transport is byte-identical to the phase-1 unauthenticated
    /// design: no handshake frames are ever sent, so a network running with
    /// auth off behaves exactly as before this field existed. A network must
    /// run all nodes with the same choice — an auth-on dialer's first frame is
    /// a `HandshakeInit`, which an auth-off peer reads as a malformed
    /// `Envelope` and drops, so a mismatch simply fails to connect (the
    /// coordinated-cutover requirement for this wire-breaking change).
    auth: Option<Arc<AuthState>>,
    /// Inbound-connection accounting (task #208): global/per-IP connection caps,
    /// one-connection-per-identity, per-peer bandwidth quota and temporary bans.
    /// Always present (generous defaults); consulted only on the accept path, so
    /// it never touches the outbound send path.
    conn_tracker: Arc<ConnTracker>,
}

/// Reads one length-prefixed frame with independent **idle** (waiting for the
/// next message's header) and **body** (once the header arrived — slowloris
/// defense, task #208) timeouts, decodes it into an `Envelope`, and enforces the
/// per-type size cap. Returns the envelope plus the number of WIRE bytes it
/// consumed (for per-peer bandwidth metering). When `session` is `Some`, the
/// frame body is AEAD ciphertext that is opened (and the frame counter advanced)
/// before Borsh-decoding; when `None`, the body is the plaintext Borsh envelope —
/// byte-identical to the pre-encryption wire.
async fn read_envelope_timed(stream: &mut TcpStream, session: Option<&mut Session>, idle: Duration, body: Duration) -> anyhow::Result<(Envelope, usize)> {
    // Header: wait up to `idle` for the next message to begin. Bounds "connect,
    // send one message, then hold the connection open forever."
    let len = tokio::time::timeout(idle, stream.read_u32_le())
        .await
        .map_err(|_| anyhow::anyhow!("idle timeout waiting for the next message header after {idle:?}"))?? as usize;
    // Global pre-decode allocation bound (the largest legitimate message fits far
    // under this; the per-type cap below is the tight, type-aware bound).
    if len > GLOBAL_FRAME_CAP {
        anyhow::bail!("rejecting oversized message: {len} bytes (global cap {GLOBAL_FRAME_CAP})");
    }
    let mut buf = vec![0u8; len];
    // Body: once a header announced `len` bytes, they must all arrive within
    // `body`. A trickle (slowloris) or a mid-body stall is dropped here.
    tokio::time::timeout(body, stream.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("message body read timed out after {body:?} (header announced {len} bytes)"))??;
    let plaintext = match session {
        Some(s) => s.open(&buf)?,
        None => buf,
    };
    let envelope: Envelope = borsh::from_slice(&plaintext)?;
    let wire = len.saturating_add(4); // 4-byte length prefix + body
    let cap = max_frame_len_for(&envelope.message);
    if wire > cap {
        anyhow::bail!("rejecting a {wire}-byte message over its {cap}-byte per-type cap");
    }
    Ok((envelope, wire))
}

/// Writes one length-prefixed frame. When `session` is `Some`, the Borsh bytes
/// are sealed (and the send counter advanced) so the body is AEAD ciphertext;
/// when `None`, the plaintext Borsh is written — byte-identical to before.
async fn write_envelope(stream: &mut TcpStream, session: Option<&mut Session>, envelope: &Envelope) -> anyhow::Result<()> {
    let bytes = borsh::to_vec(envelope)?;
    // Defensive bug-guard: never emit a frame over its per-type cap (we never
    // do in practice — this catches a future message type that outgrew its cap).
    let cap = max_frame_len_for(&envelope.message);
    if bytes.len().saturating_add(4) > cap {
        anyhow::bail!("refusing to send a {}-byte message over its {cap}-byte per-type cap", bytes.len().saturating_add(4));
    }
    let frame = match session {
        Some(s) => s.seal(&bytes)?,
        None => bytes,
    };
    stream.write_u32_le(frame.len() as u32).await?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// How long a freshly-accepted connection has to send its first complete
/// envelope before it's dropped - see `handle_inbound`'s doc comment for
/// the real vulnerability this closes.
const FIRST_ENVELOPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reads every envelope a peer sends over one persistent inbound
/// connection, dispatching each into `tx`, until the peer closes the
/// connection or a framing error occurs. Replaces the phase-1 design that
/// read exactly one envelope per accepted connection then dropped it -
/// the necessary server-side half of persistent connections; the
/// old one-shot version would silently reject every message past the
/// first one a peer's persistent connection tried to send.
///
/// A real, live-confirmed connection-exhaustion gap this closes (see
/// `project-lessons-learned`): `accept_loop` spawns one of these per
/// accepted connection with no cap and no timeout, and this function used
/// to block on `read_envelope` indefinitely - a connection that never
/// sends anything at all held one file descriptor and one task open
/// forever, for free, with no signature or admission check of any kind
/// (that only happens once real envelope bytes arrive). Confirmed live:
/// 1,000 raw TCP connections opened to a validator's P2P port and never
/// used for anything drove its open file descriptor count from 15 to
/// 1,015, bounded only by the OS file-descriptor limit. Only the *first*
/// read on a connection is timed out, not every subsequent one - a
/// legitimate persistent connection (this transport's whole design,
/// see the module docs above) can and does sit idle between real
/// messages once it's proven itself with at least one, and timing out
/// *that* would fight the persistent-connection optimization instead of
/// the actual attack (open many connections, send nothing, ever).
#[allow(clippy::too_many_arguments)] // each argument is a distinct dependency of one connection's lifecycle
async fn handle_inbound(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    mut guard: IpGuard,
    tracker: Arc<ConnTracker>,
    tx: mpsc::Sender<(ValidatorId, NetMessage)>,
    timeouts: Timeouts,
    auth: Option<Arc<AuthState>>,
    handshake_permits: Option<Arc<Semaphore>>,
) {
    // `guard` (an `IpGuard`) frees this connection's global + per-IP + per-
    // identity accounting slots the moment this function returns, for ANY reason
    // (handshake failure, timeout, abuse, framing error, forced supersede).
    //
    // When authenticated transport is on, prove identities before a single
    // envelope is read. A connection that fails the handshake (a non-member,
    // a wrong-network peer, a bad signature, or a stall) is dropped here,
    // never reaching the message loop. `authed_id` is the cryptographically
    // established sender of every envelope on this connection - used in place
    // of the spoofable `Envelope.from`, which strengthens attribution for
    // even the message types whose payload isn't itself signed.
    let (authed_id, mut session): (Option<ValidatorId>, Option<Session>) = match &auth {
        Some(a) => {
            // Bound concurrent in-flight handshakes. The permit is dropped at
            // the end of this block - i.e. as soon as the handshake finishes -
            // so the established connection's (untimed, long-lived) message
            // loop below never holds a handshake slot.
            let _permit = match &handshake_permits {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(p) => Some(p),
                    Err(_) => return, // semaphore closed (shutdown)
                },
                None => None,
            };
            match server_handshake(&mut stream, a).await {
                Ok((id, sess)) => (Some(id), sess),
                Err(e) => {
                    tracing::debug!("dropping an inbound connection that failed the handshake: {e}");
                    return;
                }
            }
        }
        None => (None, None),
    };
    // One connection per validator identity (auth on): register this connection
    // and force-close any OLDER one from the same id — a fresh reconnect (after a
    // network blip) supersedes a stale half-open connection instead of being
    // rejected. `close` is this connection's own close-notify; the read loop
    // selects on it so a later supersede drops THIS connection cleanly. With auth
    // off there is no authenticated id, so per-IP accounting (already applied by
    // `admit_ip`) is the bound and there is no per-identity signal.
    let close: Option<Arc<Notify>> = match authed_id {
        Some(id) => match tracker.bind_validator(&mut guard, id) {
            Some(n) => Some(n),
            None => {
                tracing::debug!("dropping inbound connection from temporarily-banned validator {id}");
                return;
            }
        },
        None => None,
    };
    let attributed = |envelope: &Envelope| authed_id.unwrap_or(envelope.from);
    // Per-peer bandwidth quota (task #208): a peer that sustains well over budget
    // across several windows is temporarily banned and dropped.
    let mut meter = BandwidthMeter::new(&tracker.limits);
    let ban_abuser = |why: &str| {
        tracing::warn!("temporarily banning an abusive peer ({why}): ip={peer_ip} id={authed_id:?}");
        tracker.ban_ip(peer_ip);
        if let Some(id) = authed_id {
            tracker.ban_id(id);
        }
    };

    // The FIRST message keeps the tighter `first` timeout ("connect then send
    // nothing"); subsequent header reads use the generous `idle` timeout so a
    // legitimately idle persistent connection isn't recycled prematurely.
    match read_envelope_timed(&mut stream, session.as_mut(), timeouts.first, timeouts.body).await {
        Ok((envelope, wire)) => {
            if !meter.record(wire) {
                ban_abuser("bandwidth quota exceeded");
                return;
            }
            if tx.send((attributed(&envelope), envelope.message)).await.is_err() {
                return; // engine shut down
            }
        }
        Err(e) => {
            tracing::debug!("inbound connection closed before its first message: {e}");
            return;
        }
    }

    loop {
        // Race the next message against a supersede signal (a fresher connection
        // for the same identity). `notify_one` stores a permit, so a supersede
        // that fires mid-dispatch is still observed on the next iteration.
        let read = read_envelope_timed(&mut stream, session.as_mut(), timeouts.idle, timeouts.body);
        let res = match &close {
            Some(notify) => tokio::select! {
                biased;
                _ = notify.notified() => {
                    tracing::debug!("closing a superseded inbound connection from {authed_id:?}");
                    return;
                }
                r = read => r,
            },
            None => read.await,
        };
        match res {
            Ok((envelope, wire)) => {
                if !meter.record(wire) {
                    ban_abuser("bandwidth quota exceeded");
                    return;
                }
                let from = attributed(&envelope);
                if tx.send((from, envelope.message)).await.is_err() {
                    return; // engine shut down
                }
            }
            Err(e) => {
                // Expected and frequent: the peer's own reconnect-on-broken-
                // write logic closes and replaces connections routinely, and
                // a clean process shutdown looks the same as a framing
                // error from here. Not worth a warning on every occurrence.
                tracing::debug!("inbound connection closed: {e}");
                return;
            }
        }
    }
}

async fn accept_loop(listener: TcpListener, tx: mpsc::Sender<(ValidatorId, NetMessage)>, auth: Option<Arc<AuthState>>, handshake_permits: Option<Arc<Semaphore>>, tracker: Arc<ConnTracker>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let ip = peer.ip();
                // Global cap + per-IP cap + ban check, all before spawning a task
                // or touching the still-unauthenticated stream. A refused
                // connection is dropped immediately (the stream closes on drop).
                let guard = match tracker.admit_ip(ip) {
                    Some(g) => g,
                    None => {
                        tracing::debug!("refusing an inbound connection from {ip} (connection cap or temporary ban)");
                        drop(stream);
                        continue;
                    }
                };
                let tx = tx.clone();
                let auth = auth.clone();
                let permits = handshake_permits.clone();
                let tracker = tracker.clone();
                tokio::spawn(handle_inbound(stream, ip, guard, tracker, tx, Timeouts::DEFAULT, auth, permits));
            }
            Err(e) => {
                // Back off instead of busy-spinning: a transient accept error
                // (notably fd exhaustion) would otherwise pin a core at 100%
                // retrying instantly with no log.
                tracing::warn!("accept error, backing off: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

impl Network {
    /// Binds `listen_addr` and starts accepting inbound connections.
    /// Returns the network handle (for sending) and a receiver of every
    /// `(sender, message)` pair observed from any peer.
    pub async fn start(
        self_id: ValidatorId,
        listen_addr: SocketAddr,
        peers: Vec<PeerInfo>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<(ValidatorId, NetMessage)>)> {
        Self::start_with_auth(self_id, listen_addr, peers, None).await
    }

    /// Like `start`, but with an optional authenticated-transport handshake.
    /// `auth: None` is byte-identical to `start` (phase-1 unauthenticated
    /// transport). `auth: Some(_)` runs the per-connection ML-DSA handshake
    /// (task #176) on every inbound and outbound connection before any
    /// envelope flows. Uses the default P2P connection limits.
    pub async fn start_with_auth(
        self_id: ValidatorId,
        listen_addr: SocketAddr,
        peers: Vec<PeerInfo>,
        auth: Option<Arc<AuthState>>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<(ValidatorId, NetMessage)>)> {
        Self::start_with_auth_limited(self_id, listen_addr, peers, auth, P2pLimits::default()).await
    }

    /// Like `start_with_auth`, but with explicit P2P connection/quota `limits`
    /// (task #208): global/per-IP connection caps, one-connection-per-identity,
    /// per-peer bandwidth quota and temporary bans. Always applied on the accept
    /// path; the defaults are generous, so honest traffic never trips them.
    pub async fn start_with_auth_limited(
        self_id: ValidatorId,
        listen_addr: SocketAddr,
        peers: Vec<PeerInfo>,
        auth: Option<Arc<AuthState>>,
        limits: P2pLimits,
    ) -> anyhow::Result<(Self, mpsc::Receiver<(ValidatorId, NetMessage)>)> {
        let listener = TcpListener::bind(listen_addr).await?;
        let (tx, rx) = mpsc::channel(4096);
        // Only allocate the handshake-concurrency semaphore when auth is on;
        // the auth-off accept path never acquires it (byte-identical to before).
        let handshake_permits = auth.as_ref().map(|_| Arc::new(Semaphore::new(MAX_CONCURRENT_INBOUND_HANDSHAKES)));
        let conn_tracker = ConnTracker::new(limits);
        tokio::spawn(accept_loop(listener, tx, auth.clone(), handshake_permits, conn_tracker.clone()));
        Ok((Network { self_id, peers: StdRwLock::new(peers), connections: Mutex::new(HashMap::new()), auth, conn_tracker }, rx))
    }

    /// A snapshot of the current peer set.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers.read().expect("peers lock not poisoned").clone()
    }

    /// Current number of live inbound connections (task #208 accounting) — a
    /// read-only DoS-visibility metric an operator dashboard can surface.
    pub fn live_inbound_connections(&self) -> usize {
        self.conn_tracker.live_connections()
    }

    /// Replace the peer set (phase-3.3 dynamic rotation). The caller passes the
    /// full desired set (typically the config mesh unioned with the current
    /// committee's on-chain registry addresses); `self_id` is expected to be
    /// excluded already. A no-op-equivalent call (same set) is harmless. Only
    /// ever used when validator rotation is on.
    pub fn set_peers(&self, peers: Vec<PeerInfo>) {
        *self.peers.write().expect("peers lock not poisoned") = peers;
    }

    /// Best-effort broadcast: a peer that's temporarily unreachable just
    /// misses this message (logged, not propagated as an error) - Narwhal's
    /// reliability comes from certificate-and-vote quorums tolerating
    /// missed messages, not from guaranteed delivery of any one of them.
    ///
    /// **Real bug closed here, found live pairing this with
    /// `qchain-node::main`'s `MAX_CONCURRENT_MESSAGE_HANDLERS` fix**: this
    /// used to `send_to` each peer in a sequential loop, awaiting one
    /// before starting the next. `send_to`'s underlying `write_all` only
    /// completes once the OS accepts the bytes into its socket send
    /// buffer - fine normally, but the whole point of the concurrency-cap
    /// fix is that an overloaded peer's receive side now deliberately
    /// stops draining fast (real backpressure, not a bug) exactly while
    /// it's resyncing a large gap. A sequential broadcast to `[healthy,
    /// overloaded, healthy]` would block on the *second* peer for as long
    /// as its backlog takes to drain, and every caller of `broadcast` -
    /// including `submit_transaction`, which a real wallet RPC call is
    /// waiting on synchronously - blocked right along with it. Confirmed
    /// live: submitting a transaction while one peer of three was
    /// mid-resync hung the RPC call itself past a 10-second client
    /// timeout, on a broadcast to a *different, perfectly healthy* peer
    /// that just happened to be queued behind the slow one. Fixed by
    /// spawning each peer's send as its own task instead of awaiting them
    /// in turn - "best effort, don't wait on any one of them" is what the
    /// doc comment above already promised; this makes the implementation
    /// actually keep that promise instead of only keeping it when every
    /// peer happens to be fast.
    pub async fn broadcast(self: &Arc<Self>, message: &NetMessage) {
        let current_peers = self.peers.read().expect("peers lock not poisoned").clone();
        for peer in current_peers {
            let net = self.clone();
            let message = message.clone();
            tokio::spawn(async move {
                if let Err(e) = net.send_to(peer.addr, &message).await {
                    tracing::warn!("broadcast to {} ({}) failed: {e}", peer.id, peer.addr);
                }
            });
        }
    }

    /// Returns this peer's cached persistent connection, opening a fresh
    /// one if none exists yet. The shared `connections` lock is only ever
    /// held for a HashMap lookup/insert, never across the connect itself -
    /// see `SEND_TIMEOUT`'s sibling fix on `send_to` for the real class of
    /// bug this closes for the *write* side; the same reasoning applies
    /// here to the *connect* side, since a version of this function that
    /// held the map lock across `TcpStream::connect(addr).await` (a real
    /// prior version of this function did) would let one slow-to-connect
    /// peer block every other peer's sends too, not just its own - the map
    /// lock is process-wide, not per-peer. Connecting to the same new peer
    /// from two concurrent callers is handled by re-checking the cache
    /// after connecting and discarding the loser's redundant stream.
    async fn connection_for(&self, addr: SocketAddr) -> anyhow::Result<Arc<Mutex<PeerConn>>> {
        let cached = self.connections.lock().await.get(&addr).cloned();
        if let Some(conn) = cached {
            // Post-compromise security: once an encrypted session is over its
            // frame budget, evict it so we re-dial and re-handshake with a fresh
            // ephemeral ML-KEM secret (see `CONNECTION_REKEY_FRAMES`). A
            // non-encrypted connection has no channel secret to heal, so
            // `frames_sent` is only consulted when a session exists. The old
            // stream closes when this scope drops its last `Arc`.
            let over_budget = conn.lock().await.session.as_ref().is_some_and(|s| s.frames_sent() >= CONNECTION_REKEY_FRAMES);
            if !over_budget {
                return Ok(conn);
            }
            self.connections.lock().await.remove(&addr);
            // fall through to dial a fresh, freshly-handshaked connection
        }
        let mut stream = tokio::time::timeout(SEND_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("timed out connecting to {addr} after {SEND_TIMEOUT:?}"))??;
        // Authenticate before caching: a connection that fails the handshake
        // (the dialed peer isn't an authorized validator, authenticates as a
        // different id than we dialed this address for, is on a different
        // network, or has a bad signature) is never cached or used - the
        // caller treats the error like any other connect failure and retries
        // on its next tick. Run outside the connections lock (like the
        // connect itself) so a slow-to-handshake peer never blocks sends to
        // any other peer - see `connection_for`'s doc comment. The handshake
        // also returns the AEAD `Session` when the encrypted transport is on;
        // it's cached alongside the stream so writes seal under it.
        let session = if let Some(auth) = &self.auth {
            let expected = self.addr_of_expected(addr);
            let (_id, sess) = client_handshake(&mut stream, auth, expected).await?;
            sess
        } else {
            None
        };
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get(&addr) {
            return Ok(conn.clone());
        }
        let conn = Arc::new(Mutex::new(PeerConn { stream, session }));
        conns.insert(addr, conn.clone());
        Ok(conn)
    }

    /// The validator id this node expects to find at `addr`, from its current
    /// peer set — so the dialer can require the peer to authenticate as
    /// exactly that id (anti-misrouting), not merely as *some* authorized
    /// validator. `None` if the address isn't a known peer (the handshake
    /// then only requires authorized-membership).
    fn addr_of_expected(&self, addr: SocketAddr) -> Option<ValidatorId> {
        self.peers.read().expect("peers lock not poisoned").iter().find(|p| p.addr == addr).map(|p| p.id)
    }

    /// Replace the set of validator identities this node will accept over the
    /// authenticated transport (phase-3.3 rotation). A no-op if auth is off.
    /// The caller keeps this in lock-step with `set_peers` so the dial set and
    /// the accept set never drift.
    pub fn set_authorized(&self, authorized: std::collections::HashSet<ValidatorId>) {
        if let Some(auth) = &self.auth {
            auth.set_authorized(authorized);
        }
    }

    /// Sends over a reused, persistent connection to `addr`, falling back
    /// to a single fresh reconnect-and-retry if the cached connection
    /// turns out to be broken (peer restarted, network reset) - the same
    /// one-retry-then-report-failure contract the phase-1 one-shot-
    /// connection version had, just without paying a fresh TCP handshake
    /// on every single message in the common (peer alive) case.
    ///
    /// **Real deadlock closed here, found live re-verifying the message-
    /// handler concurrency cap (`qchain-node::main`'s
    /// `MAX_CONCURRENT_MESSAGE_HANDLERS`) against a real resync scenario.**
    /// A write to a cached connection whose peer has stopped reading (not
    /// closed, just backed up - exactly what a validator deep in a real
    /// certificate-resync backlog looks like) doesn't fail, it blocks
    /// `write_all` indefinitely once the OS socket buffer fills. Every
    /// caller in this codebase that retries on a fixed tick
    /// (`qchain-node::engine`'s `retry_pending_resync_requests`, and the
    /// same `tokio::spawn`'d loop that also drives `propose_round`) awaited
    /// this call directly and sequentially - one permanently blocked peer
    /// therefore froze not just that one send, but every future tick of
    /// that entire loop, forever, confirmed live: a real 3-validator
    /// resync stopped advancing mid-catch-up with zero further log output
    /// at all (not even a slow trickle), which only a genuine hang
    /// explains. A first fix attempt (spawning each retry as its own
    /// `tokio::spawn`'d task instead of awaiting it inline) closed the hang
    /// but reintroduced the *other* failure mode this session already
    /// fixed once before: with hundreds of items retried unconditionally
    /// on every tick and no bound on how many spawned sends could be
    /// in-flight at once, a validator with a large real backlog flooded its
    /// peers with duplicate requests fast enough to OOM-kill one of them
    /// (confirmed live: kernel OOM killer terminated a validator at 15.5GB
    /// RSS) - trading a permanent hang for the exact unbounded-task-growth
    /// class of bug `MAX_CONCURRENT_MESSAGE_HANDLERS` was built to close.
    /// The actual fix is here instead, at the root: `write_envelope` is now
    /// wrapped in `SEND_TIMEOUT`, so a stuck write fails fast and this
    /// function returns a real `Err` rather than hanging - every caller's
    /// existing "log a warning and let the next tick retry" behavior
    /// (already correct, already bounded to one attempt per pending item
    /// per tick) then works exactly as designed, with no need for any
    /// caller to spawn anything.
    pub async fn send_to(&self, addr: SocketAddr, message: &NetMessage) -> anyhow::Result<()> {
        let envelope = Envelope { from: self.self_id, message: message.clone() };
        let conn = self.connection_for(addr).await?;
        {
            let mut guard = conn.lock().await;
            let PeerConn { stream, session } = &mut *guard;
            if tokio::time::timeout(SEND_TIMEOUT, write_envelope(stream, session.as_mut(), &envelope)).await.is_ok_and(|r| r.is_ok()) {
                return Ok(());
            }
        }
        self.connections.lock().await.remove(&addr);
        let conn = self.connection_for(addr).await?;
        let mut guard = conn.lock().await;
        let PeerConn { stream, session } = &mut *guard;
        tokio::time::timeout(SEND_TIMEOUT, write_envelope(stream, session.as_mut(), &envelope))
            .await
            .map_err(|_| anyhow::anyhow!("timed out writing to {addr} after {SEND_TIMEOUT:?}"))?
    }

    pub fn addr_of(&self, id: &ValidatorId) -> Option<SocketAddr> {
        self.peers.read().expect("peers lock not poisoned").iter().find(|p| &p.id == id).map(|p| p.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::{Batch, Digest};

    #[tokio::test]
    async fn two_nodes_exchange_a_message_over_real_tcp() {
        let addr_a: SocketAddr = "127.0.0.1:19801".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:19802".parse().unwrap();
        let id_a = qchain_crypto::Pubkey::new([1u8; 32]);
        let id_b = qchain_crypto::Pubkey::new([2u8; 32]);

        let (net_a, mut rx_a) = Network::start(id_a, addr_a, vec![PeerInfo { id: id_b, addr: addr_b }]).await.unwrap();
        let (_net_b, mut rx_b) = Network::start(id_b, addr_b, vec![PeerInfo { id: id_a, addr: addr_a }]).await.unwrap();
        let net_a = std::sync::Arc::new(net_a);

        net_a.broadcast(&NetMessage::WorkerBatchGossip { worker_id: 0, batch: Batch { transactions: vec![] } }).await;

        let (from, msg) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv())
            .await
            .expect("message must arrive within the timeout")
            .expect("channel must not close");
        assert_eq!(from, id_a);
        assert!(matches!(msg, NetMessage::WorkerBatchGossip { .. }));

        // No message was ever sent to A, so its receiver should stay empty.
        assert!(rx_a.try_recv().is_err());

        let digest: Digest = [7u8; 32];
        net_a.send_to(addr_b, &NetMessage::Vote { vertex_digest: digest, signature: sample_signature() }).await.unwrap();
        let (from2, msg2) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv()).await.unwrap().unwrap();
        assert_eq!(from2, id_a);
        assert!(matches!(msg2, NetMessage::Vote { .. }));
    }

    /// The real point of persistent connections: many sends to the same
    /// peer must all arrive, in order, over what is - confirmed here, not
    /// assumed - genuinely one single underlying TCP connection reused
    /// end to end, not a fresh one per message.
    #[tokio::test]
    async fn many_messages_to_the_same_peer_reuse_one_connection() {
        let addr_a: SocketAddr = "127.0.0.1:19811".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:19812".parse().unwrap();
        let id_a = qchain_crypto::Pubkey::new([3u8; 32]);
        let id_b = qchain_crypto::Pubkey::new([4u8; 32]);

        let (net_a, _rx_a) = Network::start(id_a, addr_a, vec![PeerInfo { id: id_b, addr: addr_b }]).await.unwrap();
        let (_net_b, mut rx_b) = Network::start(id_b, addr_b, vec![PeerInfo { id: id_a, addr: addr_a }]).await.unwrap();

        for i in 0..20u8 {
            let digest: Digest = [i; 32];
            net_a.send_to(addr_b, &NetMessage::Vote { vertex_digest: digest, signature: sample_signature() }).await.unwrap();
        }

        for i in 0..20u8 {
            let (from, msg) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv()).await.unwrap().unwrap();
            assert_eq!(from, id_a);
            match msg {
                NetMessage::Vote { vertex_digest, .. } => assert_eq!(vertex_digest, [i; 32], "messages must arrive in order over the reused connection"),
                other => panic!("unexpected message: {other:?}"),
            }
        }

        // Exactly one outbound connection should have been opened for
        // this peer, not 20 - the actual behavior being tested, not just
        // its observable effect (all 20 messages arriving).
        assert_eq!(net_a.connections.lock().await.len(), 1);
    }

    /// A cached connection that goes bad must be transparently replaced,
    /// not leave every subsequent send to that peer permanently failing.
    /// `accept_loop`'s listener is moved into a detached background task
    /// with no shutdown path (true of the phase-1 design too, not
    /// something this change introduced) - dropping a `Network` handle
    /// does *not* free its listen port, so this forces the break directly
    /// by shutting down net_a's own cached write half, rather than trying
    /// to simulate "peer process restarted" via a second real bind on the
    /// same address (which would race the OS actually releasing the port).
    #[tokio::test]
    async fn a_broken_cached_connection_is_replaced_on_the_next_send() {
        let addr_a: SocketAddr = "127.0.0.1:19821".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:19822".parse().unwrap();
        let id_a = qchain_crypto::Pubkey::new([5u8; 32]);
        let id_b = qchain_crypto::Pubkey::new([6u8; 32]);

        let (net_a, _rx_a) = Network::start(id_a, addr_a, vec![PeerInfo { id: id_b, addr: addr_b }]).await.unwrap();
        let (_net_b, mut rx_b) = Network::start(id_b, addr_b, vec![PeerInfo { id: id_a, addr: addr_a }]).await.unwrap();

        net_a.send_to(addr_b, &NetMessage::Vote { vertex_digest: [1u8; 32], signature: sample_signature() }).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv()).await.unwrap().unwrap();

        // Break net_a's cached connection to B directly - still present
        // in the map, but no longer usable for writes, exactly what a
        // real dead/reset peer connection looks like from the sender's
        // side.
        {
            let conns = net_a.connections.lock().await;
            let conn = conns.get(&addr_b).expect("first send must have cached a connection").clone();
            drop(conns);
            conn.lock().await.stream.shutdown().await.unwrap();
        }

        // This send must detect the dead connection, drop it, reconnect,
        // and succeed anyway - not surface the shutdown as a permanent
        // failure.
        net_a.send_to(addr_b, &NetMessage::Vote { vertex_digest: [2u8; 32], signature: sample_signature() }).await.unwrap();
        let (from, msg) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv()).await.unwrap().unwrap();
        assert_eq!(from, id_a);
        match msg {
            NetMessage::Vote { vertex_digest, .. } => assert_eq!(vertex_digest, [2u8; 32]),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// The real, live-confirmed connection-exhaustion gap this closes (see
    /// `handle_inbound`'s doc comment): a connection that never sends
    /// anything must be dropped, not held open (one file descriptor, one
    /// task) forever. Uses a tiny timeout directly rather than the real
    /// 30s `FIRST_ENVELOPE_TIMEOUT` so the test doesn't have to wait 30
    /// real seconds to observe it.
    #[tokio::test]
    async fn a_connection_that_sends_nothing_is_dropped_after_the_first_envelope_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let tracker = crate::limits::ConnTracker::new(P2pLimits::default());
            let guard = tracker.admit_ip(peer.ip()).unwrap();
            let timeouts = Timeouts { first: std::time::Duration::from_millis(200), idle: std::time::Duration::from_millis(200), body: std::time::Duration::from_millis(200) };
            handle_inbound(stream, peer.ip(), guard, tracker, tx, timeouts, None, None).await;
        });

        // Connect but deliberately never write anything - the exact
        // attack shape confirmed live (1,000 of these drove one
        // validator's open file descriptors from 15 to 1,015).
        let _silent_conn = TcpStream::connect(addr).await.unwrap();

        // No envelope ever arrives, and - the actual point - the receiver
        // closes (handle_inbound returned) once the timeout fires, rather
        // than the task and its file descriptor staying alive forever.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
        assert!(outcome.is_ok(), "handle_inbound must return within the timeout window, not hang forever");
        assert!(outcome.unwrap().is_none(), "a silent connection must never produce a message");
    }

    /// Slowloris (task #208): a peer that sends a length prefix announcing a
    /// large body, then never delivers the body, must be dropped by the BODY
    /// timeout — not hold the connection open trickling forever. Uses a tiny
    /// body timeout so the test doesn't wait the real 60s.
    #[tokio::test]
    async fn a_connection_that_stalls_mid_body_is_dropped_by_the_body_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let tracker = crate::limits::ConnTracker::new(P2pLimits::default());
            let guard = tracker.admit_ip(peer.ip()).unwrap();
            // Generous first/idle so the header IS read; tiny body timeout so the
            // stall-after-header is what trips.
            let timeouts = Timeouts {
                first: std::time::Duration::from_secs(2),
                idle: std::time::Duration::from_secs(2),
                body: std::time::Duration::from_millis(150),
            };
            handle_inbound(stream, peer.ip(), guard, tracker, tx, timeouts, None, None).await;
        });

        // Announce a 4096-byte body, then send nothing more (classic slowloris).
        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_u32_le(4096).await.unwrap();
        conn.flush().await.unwrap();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
        assert!(outcome.is_ok(), "handle_inbound must return once the body timeout fires, not hang on a half-sent message");
        assert!(outcome.unwrap().is_none(), "a stalled-mid-body connection must never produce a message");
    }

    fn sample_signature() -> qchain_crypto::MultiSignature {
        let kp = qchain_crypto::Keypair::generate().unwrap();
        kp.sign(b"test").unwrap()
    }

    /// Real, measured wire-encoded certificate size vs. validator count -
    /// not a literature estimate (see `project-lessons-learned`). Uses the
    /// real wire encoding (Borsh, since the transport-optimization work -
    /// see this module's doc comment); a quorum certificate still carries
    /// one individual hybrid signature per signer (no aggregation - see
    /// `ARCHITECTURE.md` §1's bandwidth analysis and the pending
    /// lattice-aggregation research item), so this should still scale
    /// ~linearly with the quorum size, which itself grows with the
    /// validator count - only the constant factor (Borsh vs. the old JSON)
    /// should differ from the numbers recorded before this change.
    #[test]
    #[ignore]
    fn certificate_wire_size_scales_with_validator_count() {
        use qchain_core::{Certificate, Vertex};

        for &n in &[3usize, 10, 20, 50, 100, 200, 500] {
            let keypairs: Vec<_> = (0..n).map(|_| qchain_crypto::Keypair::generate().unwrap()).collect();
            let author = keypairs[0].pubkey();
            let vertex = Vertex { round: 100, author, batch_digests: vec![(0, [7u8; 32])], parents: vec![[1u8; 32], [2u8; 32]] };
            let digest = vertex.digest();
            // Quorum-sized: 2f+1 out of n=3f+1 - the minimum a real
            // certificate would ever carry.
            let quorum = (n * 2).div_ceil(3);
            let signatures: Vec<_> = keypairs[..quorum.min(n)].iter().map(|kp| (kp.pubkey(), kp.sign(&digest[..]).unwrap())).collect();
            let cert = Certificate { vertex, signatures };

            let envelope = Envelope { from: author, message: NetMessage::CertificateBroadcast(cert) };
            let bytes = borsh::to_vec(&envelope).unwrap();
            println!("n={n:>3} validators, quorum={quorum:>3} signatures -> certificate wire size = {} bytes ({:.1} KB)", bytes.len(), bytes.len() as f64 / 1024.0);
        }
    }
}
