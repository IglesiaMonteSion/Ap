//! Bullshark: deterministic leader election and total ordering over the
//! certified DAG produced by Narwhal (design: `ARCHITECTURE.md` §1,
//! `dag-consensus-design` skill). Implements both the direct commit rule
//! (a leader with quorum support from the very next round) and the
//! indirect commit rule (a leader that never gathers direct support, but
//! is reachable from a later, directly-committed leader's causal history,
//! commits through that witness instead) - the indirect rule was added
//! after `extend_order`'s own safety fix (see its doc comment) turned "a
//! round's designated leader never proposes at all" (a crashed/silent
//! validator elected leader, which happens to any validator roughly `1/n`
//! of the time) into a permanent total-order stall instead of the
//! pre-fix, unsafe-but-live behavior of silently skipping ahead. Found via
//! `qchain-simulation`'s `one_silent_validator...` scenario, not
//! anticipated in advance - see `project-lessons-learned`.
//!
//! **A first attempt at the indirect rule had its own safety bug**, also
//! caught by `qchain-simulation` (the certificate-loss scenario, run
//! immediately after landing the first attempt): it picked "whichever
//! later round happens to already satisfy the direct rule against this
//! validator's *current* local data" as the witness for an undecided
//! round. Two validators with different amounts of locally-synced data at
//! the moment they each resolve the same round can genuinely pick
//! *different* witnesses that are each individually real/valid but have
//! different causal histories - and if their reachability answers for the
//! undecided round disagree, that's a real divergence, not a data-race
//! artifact that resolves itself later (a decision, once made, is final).
//! Fixed by requiring every step - both "does round `r` directly commit"
//! and "is round `r` provably unable to ever directly commit" - to be a
//! *quorum-intersection-sound* fact, never a guess, using the same bound
//! `committed_leader_digest` already relied on: once round `r+1`'s
//! *already-known* certificate stake plus whatever stake is still
//! *missing* cannot possibly reach quorum, no future arrival can change
//! that verdict, so it's safe to treat as permanent. The one case that
//! bound alone can't resolve - genuinely not enough round `r+1` data
//! locally yet to tell either way - stays `Undecided`, which never
//! commits to anything and is safe to leave for a later call. See
//! `RoundOutcome`/`direct_status` for the precise three-way logic this
//! forces throughout.

use crate::dag_store::DagStore;
use crate::quorum::ValidatorSet;
use qchain_core::{Certificate, Digest, Round, ValidatorId};
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

    /// The three-way, always-sound outcome of checking round `round`'s
    /// leader against the direct commit rule (quorum-worth of round+1
    /// stake referencing it as a parent). Never a guess: `Committed` and
    /// `DefinitivelyNot` are both permanent, provable facts about the
    /// eventual fully-replicated DAG; `Undecided` means genuinely not
    /// enough local data yet to tell either way.
    fn direct_status(&self, round: Round) -> RoundOutcome {
        let Some(leader) = self.leader_for_round(round) else {
            return RoundOutcome::Skipped;
        };
        let quorum = self.validators.quorum_threshold();
        let next_round_certs: Vec<&Certificate> = self.dag.certificates_in_round(round + 1).collect();
        let known_stake: u64 = next_round_certs.iter().map(|c| self.validators.stake_of(&c.vertex.author)).sum();
        // However much round+1 stake this validator simply hasn't seen a
        // certificate for yet - the upper bound on how much MORE support
        // could still show up, no matter what it turns out to reference.
        let unknown_stake = self.validators.total_stake().saturating_sub(known_stake);

        match self.dag.certificate_by_author(round, &leader) {
            Some(leader_cert) => {
                let leader_digest = leader_cert.digest();
                let supporting_stake: u64 =
                    next_round_certs.iter().filter(|c| c.vertex.parents.contains(&leader_digest)).map(|c| self.validators.stake_of(&c.vertex.author)).sum();
                if supporting_stake >= quorum {
                    RoundOutcome::Committed(leader_digest)
                } else if supporting_stake + unknown_stake < quorum {
                    // Even if every still-missing round+1 certificate
                    // turned out to reference this leader, the total
                    // could never reach quorum - permanently ruled out.
                    RoundOutcome::Skipped
                } else {
                    RoundOutcome::Undecided
                }
            }
            None => {
                // No certificate for this leader-slot is known locally at
                // all, so there's no known support to measure - only the
                // upper bound from whatever round+1 data is still
                // missing. If even that alone can't reach quorum, this
                // leader-slot (whether it's genuinely empty - a
                // crashed/silent validator - or its certificate just
                // hasn't synced here yet) can never directly commit.
                if unknown_stake < quorum {
                    RoundOutcome::Skipped
                } else {
                    RoundOutcome::Undecided
                }
            }
        }
    }

    /// Deterministic post-order walk of a certificate's causal history (its
    /// parents, recursively, sorted for determinism). Every validator
    /// running this over the same replicated set of certificates produces
    /// byte-identical output - that convergence is the entire point of a
    /// leader-based DAG ordering rule.
    ///
    /// Returns whether `digest` (and everything it transitively depends
    /// on) is now fully present and committed to `ordered`. A digest not
    /// yet in the local DAG - the real, non-hypothetical case being a
    /// `CertificateBroadcast` that hasn't arrived (or arrived late via
    /// `CertificateRequest`/`CertificateResponse` re-sync) - must NOT be
    /// marked `seen`: an earlier version of this function inserted into
    /// `seen` unconditionally, before checking whether the certificate was
    /// even found, which permanently blacklisted that digest (and anything
    /// only reachable through it) from ever being committed even after it
    /// showed up later. That's what caused two honest validators to
    /// diverge in `qchain-simulation`'s targeted certificate-loss scenario
    /// once a real re-sync mechanism started letting certificates arrive
    /// out of order - the stall the missing retry logic caused had been
    /// masking this ordering bug the whole time (nothing ever committed,
    /// so nothing could diverge). A sibling subtree reachable via a
    /// *different*, already-resolved parent still commits immediately -
    /// only the specific digest whose own dependency chain isn't fully
    /// resolved yet stays pending, to retry on a future call once its
    /// dependencies (which are never blacklisted either) show up.
    fn walk_causal_history(&self, digest: Digest, seen: &mut HashSet<Digest>, ordered: &mut Vec<Digest>) -> bool {
        if seen.contains(&digest) {
            return true;
        }
        let Some(cert) = self.dag.get(&digest) else {
            return false;
        };
        let mut parents = cert.vertex.parents.clone();
        parents.sort();
        let mut all_parents_resolved = true;
        for parent in parents {
            if !self.walk_causal_history(parent, seen, ordered) {
                all_parents_resolved = false;
                // Keep going, don't short-circuit - a sibling reachable via
                // a different parent may still be fully resolved and
                // should still commit on its own merits.
            }
        }
        if !all_parents_resolved {
            return false;
        }
        seen.insert(digest);
        ordered.push(digest);
        true
    }

    /// Extend the total order across every leader round in `from_round
    /// ..= up_to_round` that has committed, in ascending round order.
    /// `seen` persists across calls so a certificate already placed in the
    /// order is never emitted twice - callers can call this repeatedly as
    /// the DAG grows and only ever get newly-finalized digests back.
    ///
    /// Stops at the first round whose fate (`resolve`) is still
    /// `Undecided`, rather than skipping over it to check later rounds -
    /// a real safety bug an earlier version had, found via
    /// `qchain-simulation`'s certificate-loss scenario (see
    /// `project-lessons-learned`). The correctness argument for why a
    /// later leader's causal history is safe to walk *at all* depends on
    /// every earlier round already having a *permanent, provable*
    /// outcome (committed directly, committed indirectly, or definitively
    /// skipped) - never one based on "whatever this validator happens to
    /// know so far." Skip that discipline for an earlier round and two
    /// honest validators can resolve *the same round* using different
    /// locally-available evidence and permanently disagree - not a
    /// hypothetical, confirmed twice while building this (see the module
    /// docs' two-bug history).
    pub fn extend_order(&self, from_round: Round, up_to_round: Round, seen: &mut HashSet<Digest>) -> Vec<Digest> {
        let mut ordered = Vec::new();
        let mut round = from_round;
        while round <= up_to_round {
            match self.resolve(round, up_to_round) {
                RoundOutcome::Committed(digest) => {
                    if !self.walk_causal_history(digest, seen, &mut ordered) {
                        break;
                    }
                    round += 1;
                }
                RoundOutcome::Skipped => {
                    // Provably, permanently empty (e.g. a crashed/silent
                    // validator's designated round) - nothing to walk,
                    // move on.
                    round += 1;
                }
                RoundOutcome::Undecided => break,
            }
        }
        ordered
    }

    /// Resolves round `round`'s ultimate fate: `Committed(digest)` if its
    /// leader directly commits (`direct_status`) or is indirectly proven
    /// reachable from a later, provably-resolved witness round;
    /// `Skipped` if its leader-slot is proven permanently unable to ever
    /// matter; `Undecided` if there simply isn't enough local data yet to
    /// tell. See the module docs for why every branch here must be a
    /// quorum-intersection-sound fact, never "whichever later round
    /// happens to already look resolved."
    fn resolve(&self, round: Round, up_to_round: Round) -> RoundOutcome {
        let direct = self.direct_status(round);
        if !matches!(direct, RoundOutcome::Skipped) {
            return direct; // Committed or Undecided - nothing further to do
        }
        // Direct rule provably fails. The leader-slot might still be
        // reachable (multi-hop, sub-quorum-but-nonzero support) from
        // whatever round eventually gives the *next* provable outcome -
        // walked strictly forward, one round at a time, never jumping
        // ahead past an undecided one (`ultimate_witness`).
        let leader = self.leader_for_round(round);
        let target = leader.and_then(|l| self.dag.certificate_by_author(round, &l)).map(|c| c.digest());
        let Some(target) = target else {
            return RoundOutcome::Skipped; // no certificate exists at all locally - nothing to check reachability against
        };
        let Some(witness_digest) = self.ultimate_witness(round + 1, up_to_round) else {
            return RoundOutcome::Undecided;
        };
        let mut visited = HashSet::new();
        match self.reaches(witness_digest, target, &mut visited) {
            Some(true) => RoundOutcome::Committed(target),
            Some(false) => RoundOutcome::Skipped,
            // The witness's own causal history isn't fully resolved
            // locally yet (some certificate along the way is still
            // missing, e.g. pending `CertificateRequest` re-sync) -
            // concluding "not reachable" from incomplete data here would
            // risk permanently and wrongly skipping a round that should
            // have committed, so stay undecided instead.
            None => RoundOutcome::Undecided,
        }
    }

    /// Walks forward from `round` (inclusive), one round at a time, using
    /// only `direct_status`'s sound three-way verdict at each step:
    /// returns the first round's leader digest that directly commits,
    /// skipping over rounds provably ruled out, and stopping (returning
    /// `None`) the moment a round is genuinely undecided rather than
    /// guessing past it. Because every step here is either a permanent,
    /// provable fact or an immediate stop, the walk taken - and therefore
    /// whatever digest it lands on - is the same for any two validators
    /// who each manage to compute a non-`None` result, regardless of how
    /// much data either had at the time.
    fn ultimate_witness(&self, round: Round, up_to_round: Round) -> Option<Digest> {
        if round > up_to_round {
            return None;
        }
        match self.direct_status(round) {
            RoundOutcome::Committed(d) => Some(d),
            RoundOutcome::Skipped => self.ultimate_witness(round + 1, up_to_round),
            RoundOutcome::Undecided => None,
        }
    }

    /// Whether `target` is reachable from `from` by following parent
    /// links - `None` (not `Some(false)`) if the answer can't yet be
    /// determined because some certificate along a still-unexplored path
    /// is missing locally. See `resolve` for why that distinction is
    /// load-bearing, not pedantic.
    fn reaches(&self, from: Digest, target: Digest, visited: &mut HashSet<Digest>) -> Option<bool> {
        if from == target {
            return Some(true);
        }
        if !visited.insert(from) {
            return Some(false);
        }
        let cert = self.dag.get(&from)?;
        let mut any_undecided = false;
        for &parent in &cert.vertex.parents {
            match self.reaches(parent, target, visited) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => any_undecided = true,
            }
        }
        if any_undecided {
            None
        } else {
            Some(false)
        }
    }
}

/// The permanent, provable outcome of resolving one round's leader-slot -
/// see `Bullshark::resolve`/`direct_status`. Deliberately reused for both
/// "does round `r` directly commit" and "what is round `r`'s ultimate
/// fate" - both share the same three-way shape (a real digest, a proven
/// permanent absence, or genuinely not-yet-decidable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoundOutcome {
    Committed(Digest),
    Skipped,
    Undecided,
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
