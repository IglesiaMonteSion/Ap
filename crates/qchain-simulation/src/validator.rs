//! A synchronous re-implementation of `qchain-node`'s `engine.rs`
//! propose/vote/certify/commit state machine - same protocol logic
//! (including the equivocation lock, see `project-lessons-learned`),
//! minus async/tokio/real-TCP, so a deterministic simulator can drive it
//! tick-by-tick. Batches carry no transactions here (consensus safety
//! doesn't depend on execution content, and worker-tier batch dissemination
//! is orthogonal to what this harness tests - see `qchain-node`'s
//! `engine.rs` for the real multi-worker split) - a vertex's
//! `batch_digests` is just a single `(0, [0u8; 32])` entry for honest
//! validators, or `(0, [1u8; 32])` for an `Equivocator`'s second,
//! conflicting vertex, purely so the two vertices hash differently.

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorSet};
use qchain_core::{Certificate, Digest, Round, ValidatorId, Vertex};
use qchain_crypto::{Keypair, MultiSignature};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByzantineBehavior {
    Honest,
    /// Never proposes and never votes - a crashed or censoring validator.
    Silent,
    /// Proposes a second, conflicting vertex for the same round it just
    /// proposed, sent only to the first half of its peers - tries to get
    /// two certificates for the same (round, author). Exercises the
    /// `voted_for` equivocation lock in `handle_message`.
    Equivocator,
}

#[derive(Clone, Debug)]
pub enum SimMessage {
    VertexProposal(Vertex),
    Vote { vertex_digest: Digest, signature: MultiSignature },
    CertificateBroadcast(Certificate),
    /// Mirrors `qchain_network::NetMessage::CertificateRequest` - see its
    /// doc comment for why this exists (a dropped `CertificateBroadcast`
    /// is otherwise unrecoverable, a real complete-stall bug found via
    /// this exact harness).
    CertificateRequest { digest: Digest },
    CertificateResponse(Certificate),
}

pub struct SimValidator {
    pub id: ValidatorId,
    pub keypair: Keypair,
    pub behavior: ByzantineBehavior,
    pub dag: DagStore,
    pub consensus: ConsensusState,
    own_pending_vertex: Option<Vertex>,
    pending_votes: HashMap<Digest, HashMap<ValidatorId, MultiSignature>>,
    voted_for: HashMap<(Round, ValidatorId), Digest>,
    next_round: Round,
    /// Total order as this validator has observed it commit, in order -
    /// what the simulation's safety check compares across validators.
    pub committed_order: Vec<Digest>,
}

impl SimValidator {
    pub fn new(id: ValidatorId, keypair: Keypair, behavior: ByzantineBehavior) -> Self {
        SimValidator {
            id,
            keypair,
            behavior,
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            own_pending_vertex: None,
            pending_votes: HashMap::new(),
            voted_for: HashMap::new(),
            next_round: 0,
            committed_order: Vec::new(),
        }
    }

    /// Mirrors `engine.rs`'s `propose_round`. Returns `(recipient,
    /// message)` pairs for the caller (the simulation driver) to enqueue
    /// on the simulated network.
    pub fn maybe_propose(&mut self, validators: &ValidatorSet, peers: &[ValidatorId]) -> Vec<(ValidatorId, SimMessage)> {
        if self.behavior == ByzantineBehavior::Silent {
            return vec![];
        }
        if let Some(pending) = &self.own_pending_vertex {
            // Retry: re-broadcast our still-uncertified proposal every
            // tick. Without this, a single dropped copy (e.g. a transient
            // network partition active only when we first proposed)
            // stalls this validator - and every later round that depends
            // on its certificate - forever, since nothing else ever
            // resends it. Found via this harness's healing-partition
            // scenario (see project-lessons-learned); idempotent for
            // peers who already voted (the equivocation lock's "same
            // digest again" branch is a harmless no-op).
            return peers.iter().map(|&peer| (peer, SimMessage::VertexProposal(pending.clone()))).collect();
        }
        let round = self.next_round;
        if round > 0 {
            let prev = round - 1;
            let stake: u64 = self.dag.certificates_in_round(prev).map(|c| validators.stake_of(&c.vertex.author)).sum();
            if stake < validators.quorum_threshold() {
                return vec![];
            }
        }
        let parents: Vec<Digest> = if round == 0 {
            vec![]
        } else {
            let mut p: Vec<Digest> = self.dag.certificates_in_round(round - 1).map(|c| c.digest()).collect();
            p.sort();
            p
        };
        let vertex = Vertex { round, author: self.id, batch_digests: vec![(0, [0u8; 32])], parents: parents.clone() };
        let digest = vertex.digest();
        self.own_pending_vertex = Some(vertex.clone());
        self.next_round = round + 1;
        self.voted_for.insert((round, self.id), digest);

        let mut out = Vec::new();
        for &peer in peers {
            out.push((peer, SimMessage::VertexProposal(vertex.clone())));
        }
        let sig = self.keypair.sign(&digest[..]).expect("signing never fails in this harness");
        if let Some(cert) = self.record_vote(digest, self.id, sig, validators) {
            for &peer in peers {
                out.push((peer, SimMessage::CertificateBroadcast(cert.clone())));
            }
        }

        if self.behavior == ByzantineBehavior::Equivocator && !peers.is_empty() {
            let evil_vertex = Vertex { round, author: self.id, batch_digests: vec![(0, [1u8; 32])], parents };
            let half = peers.len() / 2;
            for &peer in &peers[..half.max(1)] {
                out.push((peer, SimMessage::VertexProposal(evil_vertex.clone())));
            }
        }
        out
    }

    /// Any `parents` digest not already in the local DAG, turned into a
    /// `CertificateRequest` addressed to `from` - the peer who just sent a
    /// message referencing it, and who therefore must have had it. See
    /// `SimMessage::CertificateRequest`'s doc comment for why this exists.
    fn missing_parent_requests(&self, parents: &[Digest], from: ValidatorId) -> Vec<(ValidatorId, SimMessage)> {
        parents.iter().filter(|d| !self.dag.contains(d)).map(|&digest| (from, SimMessage::CertificateRequest { digest })).collect()
    }

    /// Mirrors `engine.rs`'s `handle_message`, synchronously.
    pub fn handle_message(&mut self, from: ValidatorId, msg: SimMessage, validators: &ValidatorSet, peers: &[ValidatorId]) -> Vec<(ValidatorId, SimMessage)> {
        if self.behavior == ByzantineBehavior::Silent {
            return vec![];
        }
        match msg {
            SimMessage::VertexProposal(vertex) => {
                if vertex.author != from {
                    return vec![];
                }
                let digest = vertex.digest();
                let key = (vertex.round, vertex.author);
                let mut out = self.missing_parent_requests(&vertex.parents, from);
                match self.voted_for.get(&key) {
                    // Equivocation lock: refuse to sign a second, different
                    // vertex for a (round, author) already voted on.
                    Some(existing) if *existing != digest => return out,
                    Some(_) => {}
                    None => {
                        self.voted_for.insert(key, digest);
                    }
                }
                let sig = self.keypair.sign(&digest[..]).expect("signing never fails in this harness");
                out.push((from, SimMessage::Vote { vertex_digest: digest, signature: sig }));
                out
            }
            SimMessage::Vote { vertex_digest, signature } => {
                if let Some(cert) = self.record_vote(vertex_digest, from, signature, validators) {
                    peers.iter().map(|&peer| (peer, SimMessage::CertificateBroadcast(cert.clone()))).collect()
                } else {
                    vec![]
                }
            }
            SimMessage::CertificateBroadcast(cert) => {
                if verify_certificate(&cert, validators) {
                    let parents = cert.vertex.parents.clone();
                    self.dag.insert(cert);
                    self.missing_parent_requests(&parents, from)
                } else {
                    vec![]
                }
            }
            SimMessage::CertificateRequest { digest } => match self.dag.get(&digest) {
                Some(cert) => vec![(from, SimMessage::CertificateResponse(cert.clone()))],
                None => vec![],
            },
            SimMessage::CertificateResponse(cert) => {
                if verify_certificate(&cert, validators) {
                    let parents = cert.vertex.parents.clone();
                    self.dag.insert(cert);
                    self.missing_parent_requests(&parents, from)
                } else {
                    vec![]
                }
            }
        }
    }

    fn record_vote(&mut self, vertex_digest: Digest, voter: ValidatorId, sig: MultiSignature, validators: &ValidatorSet) -> Option<Certificate> {
        self.pending_votes.entry(vertex_digest).or_default().insert(voter, sig);
        let vertex = self.own_pending_vertex.as_ref()?;
        if vertex.digest() != vertex_digest {
            return None;
        }
        let stake: u64 = self.pending_votes[&vertex_digest].keys().map(|id| validators.stake_of(id)).sum();
        if stake < validators.quorum_threshold() {
            return None;
        }
        let vertex = self.own_pending_vertex.take().unwrap();
        let signatures = self.pending_votes.remove(&vertex_digest).unwrap().into_iter().collect();
        let cert = Certificate { vertex, signatures };
        self.dag.insert(cert.clone());
        Some(cert)
    }

    /// Mirrors `engine.rs`'s `try_commit`: re-run Bullshark ordering and
    /// record any newly-finalized digests.
    pub fn try_commit(&mut self, validators: &ValidatorSet) {
        let newly = self.consensus.advance(&self.dag, validators);
        self.committed_order.extend(newly);
    }
}
