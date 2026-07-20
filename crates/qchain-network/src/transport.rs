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
use crate::message::{Envelope, NetMessage};
use qchain_core::ValidatorId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Bounds how long a single `send_to` write attempt may block on a
/// half-stuck peer connection before being treated as a failure - see
/// `send_to`'s doc comment for the real deadlock this closes. Generous
/// relative to this project's own real round intervals (as low as 300ms in
/// live testnets this session) and real message sizes (a handful of
/// megabytes at most), so a healthy peer's connection is never spuriously
/// timed out under real load - only a connection that has genuinely
/// stopped draining.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

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
    connections: Mutex<HashMap<SocketAddr, Arc<Mutex<TcpStream>>>>,
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
}

async fn read_envelope(stream: &mut TcpStream) -> anyhow::Result<Envelope> {
    let len = stream.read_u32_le().await? as usize;
    // A sanity bound - real message sizes here are at most a handful of
    // megabytes (a batch of PQC-signed transactions); this just stops a
    // malformed length prefix from causing an unbounded allocation.
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("rejecting oversized message: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(borsh::from_slice(&buf)?)
}

async fn write_envelope(stream: &mut TcpStream, envelope: &Envelope) -> anyhow::Result<()> {
    let bytes = borsh::to_vec(envelope)?;
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
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
async fn handle_inbound(mut stream: TcpStream, tx: mpsc::Sender<(ValidatorId, NetMessage)>, first_envelope_timeout: std::time::Duration, auth: Option<Arc<AuthState>>) {
    // When authenticated transport is on, prove identities before a single
    // envelope is read. A connection that fails the handshake (a non-member,
    // a wrong-network peer, a bad signature, or a stall) is dropped here,
    // never reaching the message loop. `authed_id` is the cryptographically
    // established sender of every envelope on this connection - used in place
    // of the spoofable `Envelope.from`, which strengthens attribution for
    // even the message types whose payload isn't itself signed.
    let authed_id: Option<ValidatorId> = match &auth {
        Some(a) => match server_handshake(&mut stream, a).await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::debug!("dropping an inbound connection that failed the handshake: {e}");
                return;
            }
        },
        None => None,
    };
    let attributed = |envelope: &Envelope| authed_id.unwrap_or(envelope.from);

    let first = match tokio::time::timeout(first_envelope_timeout, read_envelope(&mut stream)).await {
        Ok(Ok(envelope)) => envelope,
        Ok(Err(e)) => {
            tracing::debug!("inbound connection closed: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("dropping a connection that sent nothing within {first_envelope_timeout:?}");
            return;
        }
    };
    if tx.send((attributed(&first), first.message)).await.is_err() {
        return; // engine shut down
    }

    loop {
        match read_envelope(&mut stream).await {
            Ok(envelope) => {
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

async fn accept_loop(listener: TcpListener, tx: mpsc::Sender<(ValidatorId, NetMessage)>, auth: Option<Arc<AuthState>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let tx = tx.clone();
        let auth = auth.clone();
        tokio::spawn(handle_inbound(stream, tx, FIRST_ENVELOPE_TIMEOUT, auth));
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
    /// envelope flows.
    pub async fn start_with_auth(
        self_id: ValidatorId,
        listen_addr: SocketAddr,
        peers: Vec<PeerInfo>,
        auth: Option<Arc<AuthState>>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<(ValidatorId, NetMessage)>)> {
        let listener = TcpListener::bind(listen_addr).await?;
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(accept_loop(listener, tx, auth.clone()));
        Ok((Network { self_id, peers: StdRwLock::new(peers), connections: Mutex::new(HashMap::new()), auth }, rx))
    }

    /// A snapshot of the current peer set.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers.read().expect("peers lock not poisoned").clone()
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
    async fn connection_for(&self, addr: SocketAddr) -> anyhow::Result<Arc<Mutex<TcpStream>>> {
        if let Some(conn) = self.connections.lock().await.get(&addr) {
            return Ok(conn.clone());
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
        // any other peer - see `connection_for`'s doc comment.
        if let Some(auth) = &self.auth {
            let expected = self.addr_of_expected(addr);
            client_handshake(&mut stream, auth, expected).await?;
        }
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get(&addr) {
            return Ok(conn.clone());
        }
        let conn = Arc::new(Mutex::new(stream));
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
            let mut stream = conn.lock().await;
            if tokio::time::timeout(SEND_TIMEOUT, write_envelope(&mut stream, &envelope)).await.is_ok_and(|r| r.is_ok()) {
                return Ok(());
            }
        }
        self.connections.lock().await.remove(&addr);
        let conn = self.connection_for(addr).await?;
        let mut stream = conn.lock().await;
        tokio::time::timeout(SEND_TIMEOUT, write_envelope(&mut stream, &envelope))
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
            conn.lock().await.shutdown().await.unwrap();
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
            let (stream, _) = listener.accept().await.unwrap();
            handle_inbound(stream, tx, std::time::Duration::from_millis(200), None).await;
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
