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

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorSchedule, ValidatorSet};
use qchain_core::{Certificate, Digest, EquivocationEvidence, Round, ValidatorId, Vertex};
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
    /// Mirrors `qchain_network::NetMessage::VertexProposal` - see its doc
    /// comment for why `author_signature` exists at all (equivocation
    /// evidence needs to be attributable, not just locally refused).
    VertexProposal { vertex: Vertex, author_signature: MultiSignature },
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
    own_pending_vertex: Option<(Vertex, MultiSignature)>,
    pending_votes: HashMap<Digest, HashMap<ValidatorId, MultiSignature>>,
    voted_for: HashMap<(Round, ValidatorId), Digest>,
    /// The first validly author-signed vertex seen per (round, author) -
    /// mirrors `qchain-node::engine::EngineState::first_seen_vertex`.
    first_seen_vertex: HashMap<(Round, ValidatorId), (Vertex, MultiSignature)>,
    /// Real equivocation evidence this validator has independently
    /// verified - mirrors `EngineState::equivocation_evidence`. Public so
    /// the simulation driver's test assertions can inspect it directly.
    pub equivocation_evidence: HashMap<(Round, ValidatorId), EquivocationEvidence>,
    /// Outstanding `CertificateRequest`s not yet answered - mirrors
    /// `qchain-node::engine`'s `pending_cert_requests`, see
    /// `retry_pending_cert_requests`'s doc comment for the real bug this
    /// closes (found live, not via this harness - see
    /// `project-lessons-learned`).
    pending_cert_requests: HashMap<Digest, ValidatorId>,
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
            first_seen_vertex: HashMap::new(),
            equivocation_evidence: HashMap::new(),
            pending_cert_requests: HashMap::new(),
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
        if let Some((pending, author_signature)) = &self.own_pending_vertex {
            // Retry: re-broadcast our still-uncertified proposal every
            // tick. Without this, a single dropped copy (e.g. a transient
            // network partition active only when we first proposed)
            // stalls this validator - and every later round that depends
            // on its certificate - forever, since nothing else ever
            // resends it. Found via this harness's healing-partition
            // scenario (see project-lessons-learned); idempotent for
            // peers who already voted (the equivocation lock's "same
            // digest again" branch is a harmless no-op).
            return peers
                .iter()
                .map(|&peer| (peer, SimMessage::VertexProposal { vertex: pending.clone(), author_signature: author_signature.clone() }))
                .collect();
        }
        let round = self.next_round;
        if round > 0 {
            let prev = round - 1;
            let quorum = validators.quorum_threshold();
            // Mirrors the real fix in `qchain-node::engine::propose_round`
            // (see its doc comment for the full real-world reproduction):
            // a validator whose own stake alone already meets quorum can
            // never be stuck waiting on DAG content the harness (like
            // `round_checkpoint` for the real node) doesn't persist -
            // `next_round > 0` alone already proves a prior tick satisfied
            // this same gate. Does not change behavior when no single
            // validator's stake reaches quorum alone.
            if validators.stake_of(&self.id) < quorum {
                let stake: u64 = self.dag.certificates_in_round(prev).map(|c| validators.stake_of(&c.vertex.author)).sum();
                if stake < quorum {
                    return vec![];
                }
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
        // One signature, reused for both the wire-level `author_signature`
        // and this validator's own self-vote - mirrors
        // `qchain-node::engine::propose_round`'s identical reuse.
        let sig = self.keypair.sign(&digest[..]).expect("signing never fails in this harness");
        self.own_pending_vertex = Some((vertex.clone(), sig.clone()));
        self.next_round = round + 1;
        self.voted_for.insert((round, self.id), digest);

        let mut out = Vec::new();
        for &peer in peers {
            out.push((peer, SimMessage::VertexProposal { vertex: vertex.clone(), author_signature: sig.clone() }));
        }
        if let Some(cert) = self.record_vote(digest, self.id, sig, validators) {
            for &peer in peers {
                out.push((peer, SimMessage::CertificateBroadcast(cert.clone())));
            }
        }

        if self.behavior == ByzantineBehavior::Equivocator && !peers.is_empty() {
            let evil_vertex = Vertex { round, author: self.id, batch_digests: vec![(0, [1u8; 32])], parents };
            let evil_signature = self.keypair.sign(&evil_vertex.digest()[..]).expect("signing never fails in this harness");
            let half = peers.len() / 2;
            for &peer in &peers[..half.max(1)] {
                out.push((peer, SimMessage::VertexProposal { vertex: evil_vertex.clone(), author_signature: evil_signature.clone() }));
            }
        }
        out
    }

    /// Any `parents` digest not already in the local DAG, turned into a
    /// `CertificateRequest` addressed to `from` - the peer who just sent a
    /// message referencing it, and who therefore must have had it. See
    /// `SimMessage::CertificateRequest`'s doc comment for why this exists.
    /// Also records each as outstanding in `pending_cert_requests` - see
    /// `retry_pending_cert_requests`.
    fn missing_parent_requests(&mut self, parents: &[Digest], from: ValidatorId) -> Vec<(ValidatorId, SimMessage)> {
        let missing: Vec<Digest> = parents.iter().copied().filter(|d| !self.dag.contains(d)).collect();
        for &digest in &missing {
            self.pending_cert_requests.insert(digest, from);
        }
        missing.into_iter().map(|digest| (from, SimMessage::CertificateRequest { digest })).collect()
    }

    /// Re-sends any still-outstanding `CertificateRequest`s, called once
    /// per validator per tick alongside `maybe_propose`. Mirrors
    /// `qchain-node::engine::Engine::retry_pending_resync_requests` -
    /// see its doc comment for the full story: `missing_parent_requests`
    /// only ever fired reactively (triggered by a fresh incoming message
    /// referencing the same missing digest again), which is not enough
    /// when the response to a request is what's lost, not just the
    /// original broadcast. Found live via a real crash-loop test, not via
    /// this harness, but closed here too so the simulator stays faithful
    /// to what the real node now does.
    pub fn retry_pending_cert_requests(&mut self) -> Vec<(ValidatorId, SimMessage)> {
        let resolved: Vec<Digest> = self.pending_cert_requests.keys().copied().filter(|d| self.dag.contains(d)).collect();
        for digest in &resolved {
            self.pending_cert_requests.remove(digest);
        }
        self.pending_cert_requests.iter().map(|(&digest, &from)| (from, SimMessage::CertificateRequest { digest })).collect()
    }

    /// Mirrors `engine.rs`'s `handle_message`, synchronously.
    pub fn handle_message(&mut self, from: ValidatorId, msg: SimMessage, validators: &ValidatorSet, peers: &[ValidatorId]) -> Vec<(ValidatorId, SimMessage)> {
        if self.behavior == ByzantineBehavior::Silent {
            return vec![];
        }
        match msg {
            SimMessage::VertexProposal { vertex, author_signature } => {
                if vertex.author != from {
                    return vec![];
                }
                // Mirrors `engine.rs`'s `handle_message`: verify the
                // author's signature before trusting anything about this
                // vertex, since it's what makes equivocation evidence
                // attributable at all.
                let Some(author_info) = validators.get(&vertex.author) else {
                    return vec![];
                };
                let digest = vertex.digest();
                if !qchain_crypto::verify(&author_info.pubkey_bundle, &digest[..], &author_signature) {
                    return vec![];
                }
                let key = (vertex.round, vertex.author);
                // Real equivocation-evidence capture, mirroring
                // `engine.rs` exactly: the first validly-signed vertex
                // seen per (round, author) is kept; a second, different
                // one turns into `EquivocationEvidence`.
                let prior = self.first_seen_vertex.get(&key).cloned();
                match prior {
                    Some((prior_vertex, prior_signature)) if prior_vertex.digest() != digest => {
                        self.equivocation_evidence.entry(key).or_insert_with(|| EquivocationEvidence {
                            vertex_a: prior_vertex,
                            signature_a: prior_signature,
                            vertex_b: vertex.clone(),
                            signature_b: author_signature.clone(),
                            author_bundle: author_info.pubkey_bundle.clone(),
                        });
                    }
                    Some(_) => {}
                    None => {
                        self.first_seen_vertex.insert(key, (vertex.clone(), author_signature.clone()));
                    }
                }
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
        let (vertex, _) = self.own_pending_vertex.as_ref()?;
        if vertex.digest() != vertex_digest {
            return None;
        }
        let stake: u64 = self.pending_votes[&vertex_digest].keys().map(|id| validators.stake_of(id)).sum();
        if stake < validators.quorum_threshold() {
            return None;
        }
        let (vertex, _) = self.own_pending_vertex.take().unwrap();
        let signatures = self.pending_votes.remove(&vertex_digest).unwrap().into_iter().collect();
        let cert = Certificate { vertex, signatures };
        self.dag.insert(cert.clone());
        Some(cert)
    }

    /// Mirrors `engine.rs`'s `try_commit`: re-run Bullshark ordering and
    /// record any newly-finalized digests.
    pub fn try_commit(&mut self, validators: &ValidatorSet) {
        // Phase-3.3 stage-1: `advance` now takes a `ValidatorSchedule`. The DST
        // is a single static committee, so wrap the set in a single-committee
        // schedule (cheap clone at this test-harness scale). Behavior is
        // identical to passing the bare set — the reason the DST must still pass
        // 9/9 unchanged.
        let schedule = ValidatorSchedule::single(validators.clone());
        let newly = self.consensus.advance(&self.dag, &schedule);
        self.committed_order.extend(newly);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_consensus::ValidatorInfo;

    /// The exact real bug this closes (see `maybe_propose`'s doc comment
    /// and `qchain-node::engine::propose_round`'s, and
    /// `project-lessons-learned`): reproduces a real validator's process
    /// restart by advancing `next_round` normally, then wiping `dag` while
    /// leaving `next_round` untouched - exactly what `round_checkpoint`
    /// persistence does for a real node (it persists the round number but
    /// deliberately not the DAG's certificate content). A single validator
    /// has no peer to ever resupply the wiped round's certificate, so
    /// without the fix this would never propose again.
    #[test]
    fn a_solo_validator_resuming_with_an_empty_dag_but_an_already_advanced_next_round_keeps_proposing() {
        let kp = Keypair::generate().unwrap();
        let info = ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake: 1 };
        let validators = ValidatorSet::new(vec![info]);
        let mut v = SimValidator::new(kp.pubkey(), kp, ByzantineBehavior::Honest);

        // Advance a few real rounds with no peers - a lone validator
        // self-certifies every round immediately (its own stake alone
        // already meets quorum), same as a real single-validator network.
        // `maybe_propose`'s return value is only the *peer-directed*
        // messages to send (empty with zero peers, regardless of whether
        // this validator itself actually advanced) - `next_round` ticking
        // up is the real, peer-independent signal that it proposed and
        // self-certified.
        for i in 0..3 {
            v.maybe_propose(&validators, &[]);
            assert_eq!(v.next_round, i + 1, "next_round must advance by one on every real proposal");
        }

        // Simulate the restart: next_round survives (this is exactly what
        // `round_checkpoint` persists for the real node), the DAG's
        // certificate content does not.
        v.dag = DagStore::new();
        v.own_pending_vertex = None;

        v.maybe_propose(&validators, &[]);
        assert_eq!(v.next_round, 4, "a solo validator must keep proposing (next_round must actually advance) after resuming from a persisted round with no local certificate history - this is the real bug that was found live");
    }

    /// A second, deeper real bug found live in the same restart
    /// reproduction as the one above: fixing `maybe_propose`/
    /// `propose_round` restores round *proposal* liveness (certificates
    /// keep forming, `next_round` keeps climbing), but `ConsensusState::
    /// advance` unconditionally started walking Bullshark's total order
    /// from round `0` - permanently `Undecided` once the DAG's content
    /// before the restart is gone, since round 0 can never resolve
    /// (`qchain-node`'s `/status` looked alive - `next_round`/
    /// `dag_certificates` climbing - while `executed_transactions` stayed
    /// frozen forever and no new transaction ever actually committed).
    /// Confirms `ConsensusState::resuming_from` closes it: committed order
    /// keeps growing after a restart with an empty DAG, not just proposals.
    #[test]
    fn a_solo_validator_resuming_also_keeps_committing_new_rounds_not_just_proposing_them() {
        let kp = Keypair::generate().unwrap();
        let info = ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake: 1 };
        let validators = ValidatorSet::new(vec![info]);
        let mut v = SimValidator::new(kp.pubkey(), kp, ByzantineBehavior::Honest);

        for _ in 0..3 {
            v.maybe_propose(&validators, &[]);
            v.try_commit(&validators);
        }
        let committed_before_restart = v.committed_order.len();
        assert!(committed_before_restart > 0, "at least one round must have genuinely committed before the simulated restart");

        // Simulate the restart exactly like the sibling test above, but
        // this time also reset `consensus` the way `qchain-node::main.rs`
        // now does: resuming from the persisted `next_round`, not a fresh
        // `ConsensusState::new()` (which would silently reintroduce this
        // exact bug by trying to resolve from round 0 again).
        v.dag = DagStore::new();
        v.own_pending_vertex = None;
        v.consensus = ConsensusState::resuming_from(v.next_round);

        for _ in 0..3 {
            v.maybe_propose(&validators, &[]);
            v.try_commit(&validators);
        }
        assert!(
            v.committed_order.len() > committed_before_restart,
            "committed_order must keep growing after resuming - a validator whose status page shows rounds advancing but never gains new committed/executed transactions is the real, more dangerous shape of this bug"
        );
    }
}
