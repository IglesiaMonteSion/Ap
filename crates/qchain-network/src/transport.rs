//! Real TCP transport for the phase-1 testnet (design: `ARCHITECTURE.md`
//! §1). Framing: `[u32 LE length][JSON-encoded Envelope]`. Each send opens
//! a fresh short-lived connection rather than maintaining a persistent
//! pool - simplest thing that works for a handful of validators exchanging
//! infrequent (sub-second-cadence) consensus messages; connection reuse is
//! a later optimization, not a phase-1 requirement (see the
//! `blockchain-core-rust` skill).

use crate::message::{Envelope, NetMessage};
use qchain_core::ValidatorId;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: ValidatorId,
    pub addr: SocketAddr,
}

/// A connected node's outbound handle plus the channel its inbound listener
/// feeds. `recv()` on the returned receiver is how a node observes
/// messages from every peer, tagged with the sender's validator id.
pub struct Network {
    self_id: ValidatorId,
    peers: Vec<PeerInfo>,
}

async fn read_envelope(stream: &mut TcpStream) -> anyhow::Result<Envelope> {
    let len = stream.read_u32_le().await? as usize;
    // A phase-1 testnet sanity bound - real message sizes here are at most
    // a handful of megabytes (a batch of PQC-signed transactions); this
    // just stops a malformed length prefix from causing an unbounded
    // allocation.
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("rejecting oversized message: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn write_envelope(stream: &mut TcpStream, envelope: &Envelope) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(envelope)?;
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn accept_loop(listener: TcpListener, tx: mpsc::Sender<(ValidatorId, NetMessage)>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let tx = tx.clone();
        tokio::spawn(async move {
            match read_envelope(&mut stream).await {
                Ok(envelope) => {
                    let _ = tx.send((envelope.from, envelope.message)).await;
                }
                Err(e) => tracing::warn!("failed to read inbound message: {e}"),
            }
        });
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
        Ok((Network { self_id, peers }, rx))
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

    pub async fn send_to(&self, addr: SocketAddr, message: &NetMessage) -> anyhow::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        let envelope = Envelope { from: self.self_id, message: message.clone() };
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

        net_a.broadcast(&NetMessage::BatchGossip(Batch { transactions: vec![] })).await;

        let (from, msg) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv())
            .await
            .expect("message must arrive within the timeout")
            .expect("channel must not close");
        assert_eq!(from, id_a);
        assert!(matches!(msg, NetMessage::BatchGossip(_)));

        // No message was ever sent to A, so its receiver should stay empty.
        assert!(rx_a.try_recv().is_err());

        let digest: Digest = [7u8; 32];
        net_a.send_to(addr_b, &NetMessage::Vote { vertex_digest: digest, signature: sample_signature() }).await.unwrap();
        let (from2, msg2) = tokio::time::timeout(std::time::Duration::from_secs(2), rx_b.recv()).await.unwrap().unwrap();
        assert_eq!(from2, id_a);
        assert!(matches!(msg2, NetMessage::Vote { .. }));
    }

    fn sample_signature() -> qchain_crypto::MultiSignature {
        let kp = qchain_crypto::Keypair::generate().unwrap();
        kp.sign(b"test").unwrap()
    }

    /// Real, measured wire-encoded certificate size vs. validator count -
    /// not a literature estimate (see `project-lessons-learned`). A
    /// quorum certificate carries one individual hybrid signature per
    /// signer (no aggregation - see `ARCHITECTURE.md` §1's bandwidth
    /// analysis and the pending lattice-aggregation research item), so
    /// this should scale ~linearly with the quorum size, which itself
    /// grows with the validator count.
    #[test]
    #[ignore]
    fn certificate_wire_size_scales_with_validator_count() {
        use qchain_core::{Certificate, Vertex};

        for &n in &[3usize, 10, 20, 50, 100, 200, 500] {
            let keypairs: Vec<_> = (0..n).map(|_| qchain_crypto::Keypair::generate().unwrap()).collect();
            let author = keypairs[0].pubkey();
            let vertex = Vertex { round: 100, author, batch_digest: [7u8; 32], parents: vec![[1u8; 32], [2u8; 32]] };
            let digest = vertex.digest();
            // Quorum-sized: 2f+1 out of n=3f+1 - the minimum a real
            // certificate would ever carry.
            let quorum = (n * 2).div_ceil(3);
            let signatures: Vec<_> = keypairs[..quorum.min(n)].iter().map(|kp| (kp.pubkey(), kp.sign(&digest[..]).unwrap())).collect();
            let cert = Certificate { vertex, signatures };

            let envelope = Envelope { from: author, message: NetMessage::CertificateBroadcast(cert) };
            let bytes = serde_json::to_vec(&envelope).unwrap();
            println!("n={n:>3} validators, quorum={quorum:>3} signatures -> certificate wire size = {} bytes ({:.1} KB)", bytes.len(), bytes.len() as f64 / 1024.0);
        }
    }
}
