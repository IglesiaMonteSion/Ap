//! Bullshark: deterministic leader election and total ordering over the
//! certified DAG produced by Narwhal (design: `ARCHITECTURE.md` §1,
//! `dag-consensus-design` skill). Phase-1 simplification: a leader commits
//! via the direct rule only (quorum support from the very next round) -
//! the indirect/fallback commit rule for a leader that never gathers direct
//! support is deferred to phase 2 alongside Byzantine fault injection (see
//! `ARCHITECTURE.md`'s phase-1 out-of-scope list). Liveness under real
//! network asynchrony is therefore not yet proven - only that, given a
//! replicated set of certificates, every validator computes the identical
//! order.

use crate::dag_store::DagStore;
use crate::quorum::ValidatorSet;
use qchain_core::{Digest, Round, ValidatorId};
use sha3::{Digest as _, Sha3_256};
use std::collections::HashSet;

pub struct Bullshark<'a> {
    dag: &'a DagStore,
    validators: &'a ValidatorSet,
}

impl<'a> Bullshark<'a> {
    pub fn new(dag: &'a DagStore, validators: &'a ValidatorSet) -> Self {
        Bullshark { dag, validators }
    }

    /// Deterministic, stake-agnostic leader selection: every honest
    /// validator computes the same leader for a given round from a hash of
    /// the round number alone, so agreeing on "who proposes this round's
    /// block" costs no extra consensus round.
    pub fn leader_for_round(&self, round: Round) -> Option<ValidatorId> {
        let ids = self.validators.ids_sorted();
        if ids.is_empty() {
            return None;
        }
        let mut hasher = Sha3_256::new();
        hasher.update(round.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let idx = (u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize) % ids.len();
        Some(ids[idx])
    }

    /// A round's leader certificate is committed once a quorum of stake in
    /// `round + 1` has certified a vertex listing it as a parent: every
    /// honest validator will eventually observe it in their own causal
    /// history, so it's safe to finalize its position in the order now.
    fn committed_leader_digest(&self, round: Round) -> Option<Digest> {
        let leader = self.leader_for_round(round)?;
        let leader_cert = self.dag.certificate_by_author(round, &leader)?;
        let leader_digest = leader_cert.digest();

        let supporting_stake: u64 = self
            .dag
            .certificates_in_round(round + 1)
            .filter(|c| c.vertex.parents.contains(&leader_digest))
            .map(|c| self.validators.stake_of(&c.vertex.author))
            .sum();

        (supporting_stake >= self.validators.quorum_threshold()).then_some(leader_digest)
    }

    /// Deterministic post-order walk of a certificate's causal history (its
    /// parents, recursively, sorted for determinism). Every validator
    /// running this over the same replicated set of certificates produces
    /// byte-identical output - that convergence is the entire point of a
    /// leader-based DAG ordering rule.
    fn walk_causal_history(&self, digest: Digest, seen: &mut HashSet<Digest>, ordered: &mut Vec<Digest>) {
        if !seen.insert(digest) {
            return;
        }
        let Some(cert) = self.dag.get(&digest) else {
            return;
        };
        let mut parents = cert.vertex.parents.clone();
        parents.sort();
        for parent in parents {
            self.walk_causal_history(parent, seen, ordered);
        }
        ordered.push(digest);
    }

    /// Extend the total order across every leader round in `from_round
    /// ..= up_to_round` that has committed, in ascending round order.
    /// `seen` persists across calls so a certificate already placed in the
    /// order is never emitted twice - callers can call this repeatedly as
    /// the DAG grows and only ever get newly-finalized digests back.
    pub fn extend_order(&self, from_round: Round, up_to_round: Round, seen: &mut HashSet<Digest>) -> Vec<Digest> {
        let mut ordered = Vec::new();
        let mut round = from_round;
        loop {
            if let Some(leader_digest) = self.committed_leader_digest(round) {
                self.walk_causal_history(leader_digest, seen, &mut ordered);
            }
            if round >= up_to_round {
                break;
            }
            round += 1;
        }
        ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;

    fn validators(n: usize) -> ValidatorSet {
        let infos = (0..n)
            .map(|_| {
                let kp = Keypair::generate().unwrap();
                crate::quorum::ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake: 1 }
            })
            .collect();
        ValidatorSet::new(infos)
    }

    #[test]
    fn leader_election_is_deterministic_and_spans_the_validator_set() {
        let validators = validators(4);
        let dag = DagStore::new();
        let bullshark = Bullshark::new(&dag, &validators);

        assert_eq!(bullshark.leader_for_round(5), bullshark.leader_for_round(5));

        let leaders: HashSet<_> = (0..50).filter_map(|r| bullshark.leader_for_round(r)).collect();
        assert!(leaders.len() > 1, "leadership must rotate across rounds, not stick to one validator");
    }

    #[test]
    fn empty_validator_set_has_no_leader() {
        let validators = ValidatorSet::new(vec![]);
        let dag = DagStore::new();
        let bullshark = Bullshark::new(&dag, &validators);
        assert!(bullshark.leader_for_round(0).is_none());
    }
}
