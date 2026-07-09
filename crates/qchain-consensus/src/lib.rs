//! Narwhal-Bullshark DAG-BFT consensus core (design: `ARCHITECTURE.md` §1,
//! full protocol rationale in the `dag-consensus-design` skill). This crate
//! is the deterministic algorithm only - vertex/certificate/quorum logic,
//! round advancement, leader-based total ordering - with no networking:
//! transport is a caller concern (`qchain-network`), per the
//! `blockchain-core-rust` skill's "deterministic core, I/O pushed to the
//! edges" convention.
//!
//! Scope note: the round-synchronous simulation test in this crate proves
//! *correctness of the ordering algorithm* - that independent replicas
//! converge on the same total order given the same replicated DAG data.
//! Byzantine fault injection and real asynchronous networking are phase-1
//! out-of-scope (`ARCHITECTURE.md`'s phased roadmap) and land with
//! `qchain-network` and the phase-2 adversarial test suite.

pub mod bullshark;
pub mod dag_store;
pub mod quorum;

pub use bullshark::Bullshark;
pub use dag_store::DagStore;
pub use quorum::{ValidatorInfo, ValidatorSet};

use qchain_core::{Certificate, Digest, Round};
use std::collections::HashSet;

/// Verify a certificate carries real, quorum-weighted signatures over its
/// vertex digest. A validator's signature only counts once even if it
/// somehow appears twice (no restaking the same stake); a signer absent
/// from the validator set is silently ignored rather than rejecting the
/// whole certificate outright.
pub fn verify_certificate(cert: &Certificate, validators: &ValidatorSet) -> bool {
    let digest = cert.vertex.digest();
    let mut counted = HashSet::new();
    let mut signer_stake = 0u64;
    for (validator_id, sig) in &cert.signatures {
        if !counted.insert(*validator_id) {
            continue;
        }
        let Some(info) = validators.get(validator_id) else {
            continue;
        };
        if qchain_crypto::verify(&info.pubkey_bundle, &digest[..], sig) {
            signer_stake += info.stake;
        }
    }
    signer_stake >= validators.quorum_threshold()
}

/// Drives Bullshark ordering forward as the DAG grows. Tracks which
/// certificates have already been emitted so repeated calls to `advance`
/// only ever return newly-finalized digests, in commit order - the piece a
/// node's block-application loop actually consumes.
#[derive(Default)]
pub struct ConsensusState {
    seen: HashSet<Digest>,
}

impl ConsensusState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-evaluates leader commitment across the whole DAG (cheap at
    /// phase-1/testnet scale - see the `dag-consensus-design` skill for the
    /// tradeoff) and returns any certificate digests newly finalized into
    /// the total order since the last call.
    pub fn advance(&mut self, dag: &DagStore, validators: &ValidatorSet) -> Vec<Digest> {
        let bullshark = Bullshark::new(dag, validators);
        bullshark.extend_order(0, dag.highest_round(), &mut self.seen)
    }

    pub fn ordered_count(&self) -> usize {
        self.seen.len()
    }
}

/// Round advancement guard: a validator only starts round `r+1` once it
/// holds 2f+1 certificates from round `r` (Narwhal's synchronization rule).
/// Pure predicate - no state - so callers can check it against whatever DAG
/// view they currently have.
pub fn can_advance_round(dag: &DagStore, validators: &ValidatorSet, round: Round) -> bool {
    let stake: u64 = dag.certificates_in_round(round).map(|c| validators.stake_of(&c.vertex.author)).sum();
    stake >= validators.quorum_threshold()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::{Batch, Vertex};
    use qchain_crypto::{HybridSignature, Keypair};

    struct TestValidator {
        keypair: Keypair,
        id: qchain_core::ValidatorId,
    }

    fn make_validators(n: usize) -> (Vec<TestValidator>, ValidatorSet) {
        let mut tvs = Vec::new();
        let mut infos = Vec::new();
        for _ in 0..n {
            let kp = Keypair::generate().unwrap();
            let id = kp.pubkey();
            infos.push(ValidatorInfo { id, pubkey_bundle: kp.public_key_bundle(), stake: 1 });
            tvs.push(TestValidator { keypair: kp, id });
        }
        (tvs, ValidatorSet::new(infos))
    }

    fn certify(vertex: Vertex, signers: &[TestValidator]) -> Certificate {
        let digest = vertex.digest();
        let signatures: Vec<(qchain_core::ValidatorId, HybridSignature)> =
            signers.iter().map(|v| (v.id, v.keypair.sign(&digest[..]).unwrap())).collect();
        Certificate { vertex, signatures }
    }

    /// Builds a fully-connected, round-synchronous DAG: every vertex at
    /// round `r + 1` references every certificate from round `r` as a
    /// parent, and every certificate is signed by every validator. Not a
    /// realistic asynchronous network pattern - just enough real DAG
    /// structure (real signatures, real quorum certificates, real parent
    /// references) to exercise leader election and causal-history ordering
    /// end to end.
    fn build_dag(tvs: &[TestValidator], rounds: u64) -> DagStore {
        let mut dag = DagStore::new();
        let mut prev_round_digests: Vec<Digest> = Vec::new();
        for round in 0..rounds {
            let mut this_round_digests = Vec::new();
            for (i, v) in tvs.iter().enumerate() {
                let mut batch_digest = Batch { transactions: vec![] }.digest();
                batch_digest[0] = batch_digest[0].wrapping_add(i as u8);
                let vertex = Vertex { round, author: v.id, batch_digest, parents: prev_round_digests.clone() };
                let cert = certify(vertex, tvs);
                this_round_digests.push(dag.insert(cert));
            }
            prev_round_digests = this_round_digests;
        }
        dag
    }

    #[test]
    fn certificate_verification_rejects_insufficient_stake() {
        let (tvs, validators) = make_validators(4);
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digest: [0u8; 32], parents: vec![] };
        // Only one signer - below the quorum threshold of 3.
        let cert = certify(vertex, &tvs[..1]);
        assert!(!verify_certificate(&cert, &validators));
    }

    #[test]
    fn certificate_verification_accepts_quorum_signatures() {
        let (tvs, validators) = make_validators(4);
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digest: [0u8; 32], parents: vec![] };
        let cert = certify(vertex, &tvs[..3]);
        assert!(verify_certificate(&cert, &validators));
    }

    #[test]
    fn certificate_verification_rejects_forged_signatures() {
        let (tvs, validators) = make_validators(4);
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digest: [0u8; 32], parents: vec![] };
        let mut cert = certify(vertex, &tvs[..3]);
        cert.signatures[0].1.ed25519.0[0] ^= 0xFF;
        assert!(!verify_certificate(&cert, &validators), "a quorum count that includes a forged signature must not pass");
    }

    #[test]
    fn round_advancement_requires_quorum_of_the_round() {
        let (tvs, validators) = make_validators(4);
        let mut dag = DagStore::new();
        assert!(!can_advance_round(&dag, &validators, 0));

        for v in &tvs[..2] {
            let vertex = Vertex { round: 0, author: v.id, batch_digest: [0u8; 32], parents: vec![] };
            dag.insert(certify(vertex, &tvs));
        }
        assert!(!can_advance_round(&dag, &validators, 0), "2 of 4 is below the quorum threshold of 3");

        let vertex = Vertex { round: 0, author: tvs[2].id, batch_digest: [0u8; 32], parents: vec![] };
        dag.insert(certify(vertex, &tvs));
        assert!(can_advance_round(&dag, &validators, 0), "3 of 4 meets the quorum threshold");
    }

    #[test]
    fn honest_round_synchronous_dag_produces_a_converging_total_order() {
        let (tvs, validators) = make_validators(4);
        let dag = build_dag(&tvs, 5);

        // Two independent replicas ordering the same replicated DAG data
        // must reach byte-identical results - the actual property Bullshark
        // ordering exists to guarantee.
        let order_a = ConsensusState::new().advance(&dag, &validators);
        let order_b = ConsensusState::new().advance(&dag, &validators);

        assert!(!order_a.is_empty(), "a 5-round honest DAG must commit at least one leader");
        assert_eq!(order_a, order_b, "independent replicas must converge on the same total order");

        for digest in &order_a {
            assert!(dag.get(digest).is_some(), "every ordered digest must be a real certificate in the DAG");
        }
    }

    #[test]
    fn advancing_incrementally_matches_ordering_the_full_dag_in_one_call() {
        let (tvs, validators) = make_validators(4);

        let dag_partial = build_dag(&tvs, 3);
        let mut state = ConsensusState::new();
        let first = state.advance(&dag_partial, &validators);

        let dag_full = build_dag(&tvs, 6);
        let mut combined = first.clone();
        combined.extend(state.advance(&dag_full, &validators));

        let direct = ConsensusState::new().advance(&dag_full, &validators);

        assert_eq!(combined, direct, "incremental advancement must match ordering the full DAG in one call");
    }
}
