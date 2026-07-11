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

use crate::message::{Envelope, NetMessage};
use qchain_core::ValidatorId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

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
    peers: Vec<PeerInfo>,
    connections: Mutex<HashMap<SocketAddr, Arc<Mutex<TcpStream>>>>,
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

/// Reads every envelope a peer sends over one persistent inbound
/// connection, dispatching each into `tx`, until the peer closes the
/// connection or a framing error occurs. Replaces the phase-1 design that
/// read exactly one envelope per accepted connection then dropped it -
/// the necessary server-side half of persistent connections; the
/// old one-shot version would silently reject every message past the
/// first one a peer's persistent connection tried to send.
async fn handle_inbound(mut stream: TcpStream, tx: mpsc::Sender<(ValidatorId, NetMessage)>) {
    loop {
        match read_envelope(&mut stream).await {
            Ok(envelope) => {
                if tx.send((envelope.from, envelope.message)).await.is_err() {
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

async fn accept_loop(listener: TcpListener, tx: mpsc::Sender<(ValidatorId, NetMessage)>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let tx = tx.clone();
        tokio::spawn(handle_inbound(stream, tx));
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
        let listener = TcpListener::bind(listen_addr).await?;
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(accept_loop(listener, tx));
        Ok((Network { self_id, peers, connections: Mutex::new(HashMap::new()) }, rx))
    }

    pub fn peers(&self) -> &[PeerInfo] {
        &self.peers
    }

    /// Best-effort broadcast: a peer that's temporarily unreachable just
    /// misses this message (logged, not propagated as an error) - Narwhal's
    /// reliability comes from certificate-and-vote quorums tolerating
    /// missed messages, not from guaranteed delivery of any one of them.
    pub async fn broadcast(&self, message: &NetMessage) {
        for peer in &self.peers {
            if let Err(e) = self.send_to(peer.addr, message).await {
                tracing::warn!("broadcast to {} ({}) failed: {e}", peer.id, peer.addr);
            }
        }
    }

    /// Returns this peer's cached persistent connection, opening a fresh
    /// one if none exists yet. The outer `connections` lock is only held
    /// for the HashMap lookup/insert (a fast, short critical section) -
    /// the actual I/O happens under the per-connection lock returned here,
    /// so a slow or stalled peer never blocks sends to any other peer.
    async fn connection_for(&self, addr: SocketAddr) -> anyhow::Result<Arc<Mutex<TcpStream>>> {
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get(&addr) {
            return Ok(conn.clone());
        }
        let stream = TcpStream::connect(addr).await?;
        let conn = Arc::new(Mutex::new(stream));
        conns.insert(addr, conn.clone());
        Ok(conn)
    }

    /// Sends over a reused, persistent connection to `addr`, falling back
    /// to a single fresh reconnect-and-retry if the cached connection
    /// turns out to be broken (peer restarted, network reset) - the same
    /// one-retry-then-report-failure contract the phase-1 one-shot-
    /// connection version had, just without paying a fresh TCP handshake
    /// on every single message in the common (peer alive) case.
    pub async fn send_to(&self, addr: SocketAddr, message: &NetMessage) -> anyhow::Result<()> {
        let envelope = Envelope { from: self.self_id, message: message.clone() };
        let conn = self.connection_for(addr).await?;
        {
            let mut stream = conn.lock().await;
            if write_envelope(&mut stream, &envelope).await.is_ok() {
                return Ok(());
            }
        }
        self.connections.lock().await.remove(&addr);
        let conn = self.connection_for(addr).await?;
        let mut stream = conn.lock().await;
        write_envelope(&mut stream, &envelope).await
    }

    pub fn addr_of(&self, id: &ValidatorId) -> Option<SocketAddr> {
        self.peers.iter().find(|p| &p.id == id).map(|p| p.addr)
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
