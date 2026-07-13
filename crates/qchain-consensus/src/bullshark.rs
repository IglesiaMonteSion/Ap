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
use std::collections::{HashMap, HashSet};

pub struct Bullshark<'a> {
    dag: &'a DagStore,
    validators: &'a ValidatorSet,
    /// GC barrier: any certificate whose round is strictly below this is
    /// treated as already-committed permanent history and its slot in a
    /// causal walk is satisfied without requiring the certificate to be
    /// present. `0` disables the barrier (nothing pruned). This is what lets
    /// `DagStore::prune_below` drop old committed rounds without stalling a
    /// restarted node whose `seen` set (not persisted) starts empty and
    /// would otherwise try to walk a leader's full ancestry down into the
    /// pruned region and fail. During *live* operation the barrier is never
    /// actually reached - `walk_causal_history`/`reaches` short-circuit on
    /// `seen` (which already holds every committed digest) long before a
    /// walk descends anywhere near `gc_floor` - so it only affects the
    /// empty-`seen` restart re-derivation, keeping it a no-op on the hot
    /// path. Sound across validators with *different* floors: the barrier
    /// only suppresses re-emitting history already committed (and applied,
    /// idempotently) in a prior life, never changes the relative order of
    /// rounds at or above either validator's floor - see
    /// `ConsensusState::set_gc_floor`.
    gc_floor: Round,
}

impl<'a> Bullshark<'a> {
    pub fn new(dag: &'a DagStore, validators: &'a ValidatorSet) -> Self {
        Bullshark { dag, validators, gc_floor: 0 }
    }

    pub fn with_gc_floor(dag: &'a DagStore, validators: &'a ValidatorSet, gc_floor: Round) -> Self {
        Bullshark { dag, validators, gc_floor }
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
                // The leader's own certificate is not known locally. It is
                // NOT sound to declare this round permanently `Skipped` just
                // because `unknown_stake < quorum` - that bound treats the
                // support from every *known* round+1 certificate as zero,
                // which is only true if none of them actually references the
                // (unsynced) leader. A round+1 certificate that DOES
                // reference the leader carries the leader's digest in its
                // `parents`, but this validator can't recognize that without
                // the leader's own certificate to compare against, so
                // counting it as non-supporting is exactly the unsound step.
                //
                // **Real BFT safety bug this closes (found in the exhaustive
                // pre-production audit).** Before this, a validator that had
                // advanced past round `r` (committing round `r+1`'s anchor,
                // whose leader happened to exclude the round-`r` leader `L`)
                // while still missing `L`'s certificate would permanently
                // `Skip` round `r`; when `L` finally synced it would re-resolve
                // to `Committed(L)` and append `L` out of order - two honest
                // validators committing different total orders (a fork). Low
                // probability in practice (needs a validator 2+ rounds ahead
                // yet still missing a prior leader's certificate despite the
                // re-sync retries), but a genuine safety violation.
                //
                // The sound refinement: only conclude `Skipped` when the
                // known support is provably, *permanently* zero - i.e. every
                // known round+1 certificate has all of its parents present
                // locally (so we can be sure none of them is the still-
                // missing leader). In that state, known support is a fixed
                // fact of 0 and the total possible support is at most
                // `unknown_stake < quorum`, so `L` genuinely cannot commit -
                // this is the genuinely-crashed-leader case, and skipping it
                // keeps the chain live. If instead any known round+1
                // certificate still has a missing parent, that parent COULD
                // be `L` (it's exactly what `request_missing_parents` is
                // fetching), so we must wait: `Undecided`. Once `L` (or the
                // missing parents) sync, this resolves correctly - either the
                // leader turns out present and its real support is measured
                // by the `Some` arm above, or it's confirmed absent and
                // skipped soundly here.
                let known_support_is_permanently_zero =
                    next_round_certs.iter().all(|c| c.vertex.parents.iter().all(|p| self.dag.contains(p)));
                if unknown_stake < quorum && known_support_is_permanently_zero {
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
    /// **Real exponential-blowup bug closed here, found live (not by
    /// inspection) building the restart-liveness fixes elsewhere in this
    /// session (see `qchain-node::engine::propose_round`'s and
    /// `ConsensusState::resuming_from`'s doc comments for the sibling
    /// fixes this one was found alongside).** `seen` only ever records a
    /// digest once its *entire* causal history is confirmed fully
    /// present - by design, so a node blocked on a still-missing ancestor
    /// can be retried on a later call once resync fills the gap. But a
    /// real Narwhal DAG is wide, not a chain: every certificate lists
    /// *multiple* parents (one per validator that certified the previous
    /// round), so many certificates across many rounds share the same
    /// ancestors. Without any *per-call* memo, every one of those shared
    /// ancestors that isn't yet in `seen` (anything still resyncing) gets
    /// re-explored, *from scratch, recursively*, on every single path
    /// that reaches it - and with a branching factor of `n` validators and
    /// `d` still-unresolved rounds of depth, that's `O(n^d)` redundant
    /// re-visits of the exact same nodes within one `extend_order` call.
    /// Confirmed live: a real 3-validator testnet, one validator resyncing
    /// after a real (not even large - tens of rounds) gap - a peer that
    /// never restarted spiked past 10GB RSS and 100%+ CPU within a couple
    /// of minutes, because *its own* `walk_causal_history` calls kept
    /// re-walking the same not-yet-fully-synced-on-the-other-side ancestor
    /// region exponentially many times. Fixed with `memo`, scoped to one
    /// `extend_order` call only (never persisted across calls, unlike
    /// `seen`): every digest visited during this call - whether it
    /// resolves or not - is cached, so a shared ancestor reached via a
    /// second or third path is an `O(1)` lookup instead of a repeat
    /// recursive walk. A genuinely still-missing ancestor is retried fresh
    /// on the *next* `extend_order` call (new `memo`), exactly preserving
    /// the existing liveness guarantee that new data always gets a fair
    /// re-check - only the redundant *within-one-call* re-exploration is
    /// eliminated.
    fn walk_causal_history(&self, digest: Digest, seen: &mut HashSet<Digest>, ordered: &mut Vec<Digest>, memo: &mut HashMap<Digest, bool>) -> bool {
        if seen.contains(&digest) {
            return true;
        }
        if let Some(&resolved) = memo.get(&digest) {
            return resolved;
        }
        let Some(cert) = self.dag.get(&digest) else {
            memo.insert(digest, false);
            return false;
        };
        let mut parents = cert.vertex.parents.clone();
        parents.sort();
        let mut all_parents_resolved = true;
        // A certificate at round `r` lists parents from round `r - 1`. Once
        // `r <= gc_floor` those parents belong to the pruned, permanently-
        // committed region (see `gc_floor`): they are treated as resolved
        // without recursion, so a restart re-derivation that walks a
        // retained-window leader's ancestry stops cleanly at the barrier
        // instead of failing on a certificate that was legitimately dropped.
        if cert.vertex.round > self.gc_floor {
            for parent in parents {
                if !self.walk_causal_history(parent, seen, ordered, memo) {
                    all_parents_resolved = false;
                    // Keep going, don't short-circuit - a sibling reachable via
                    // a different parent may still be fully resolved and
                    // should still commit on its own merits.
                }
            }
        }
        if !all_parents_resolved {
            memo.insert(digest, false);
            return false;
        }
        seen.insert(digest);
        ordered.push(digest);
        memo.insert(digest, true);
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
    /// Returns the newly-finalized digests together with the round the walk
    /// stopped at - the first round not yet permanently resolved (or
    /// `up_to_round + 1` if every round through `up_to_round` finalized).
    /// Every round strictly below that value is now permanently committed or
    /// skipped *and* fully walked into `seen`, so a caller can advance its
    /// start round to it (never re-resolving settled history each call) and,
    /// far enough below it, garbage-collect the DAG - see
    /// `ConsensusState::advance`/`set_gc_floor`.
    pub fn extend_order(&self, from_round: Round, up_to_round: Round, seen: &mut HashSet<Digest>) -> (Vec<Digest>, Round) {
        let mut ordered = Vec::new();
        // Scoped to this one call only - see `walk_causal_history`'s doc
        // comment for the real exponential-blowup bug this closes. Many
        // rounds' leader digests share ancestors in a real (wide, multi-
        // parent) DAG; without this, each shared-but-still-unresolved
        // ancestor gets fully re-walked from scratch on every path that
        // reaches it, within this single call.
        let mut memo = HashMap::new();
        let mut round = from_round;
        while round <= up_to_round {
            match self.resolve(round, up_to_round) {
                RoundOutcome::Committed(digest) => {
                    if !self.walk_causal_history(digest, seen, &mut ordered, &mut memo) {
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
        (ordered, round)
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
        // Below the GC barrier there is no retained history left to search,
        // and none is needed: the reachability `target` is always a round
        // being resolved (>= the consensus floor >= `gc_floor`), so it can
        // never lie in the pruned region a barrier certificate's parents
        // point into. Stopping here matches `walk_causal_history`'s barrier.
        if cert.vertex.round <= self.gc_floor {
            return Some(false);
        }
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

    fn cert(round: Round, author: ValidatorId, parents: Vec<Digest>) -> Certificate {
        let vertex = qchain_core::Vertex { round, author, batch_digests: vec![], parents };
        Certificate { vertex, signatures: vec![] }
    }

    /// The exact BFT safety bug the refined `direct_status` `None` arm
    /// closes: a validator missing round `r`'s leader certificate must NOT
    /// permanently `Skip` the round while round+1 certificates it *does*
    /// hold reference that (still-unsynced) leader as a parent - doing so
    /// lets it diverge from a peer that has the leader and commits it.
    #[test]
    fn a_missing_leader_referenced_by_a_known_child_is_undecided_not_skipped() {
        let validators = validators(4);
        let ids = validators.ids_sorted();
        let r = 1;
        // The four round-r certificates (one per validator). The leader's is
        // the one we'll withhold from the "behind" validator's DAG.
        let leader = {
            let dag = DagStore::new();
            Bullshark::new(&dag, &validators).leader_for_round(r).unwrap()
        };
        let round_r: Vec<Certificate> = ids.iter().map(|id| cert(r, *id, vec![])).collect();
        let leader_digest = round_r.iter().find(|c| c.vertex.author == leader).unwrap().digest();

        // Three round-(r+1) certificates, every one referencing the leader as
        // a parent (so on a fully-synced validator the leader has 3-of-4
        // support = quorum and commits directly).
        let non_leaders: Vec<ValidatorId> = ids.iter().copied().filter(|id| *id != leader).collect();
        let round_r1: Vec<Certificate> = non_leaders.iter().map(|id| cert(r + 1, *id, vec![leader_digest])).collect();

        // "Behind" validator: has all three round-(r+1) certs but NOT the
        // leader's round-r certificate. The three children reference the
        // leader's digest, which is a *missing* parent here.
        let mut behind = DagStore::new();
        for c in &round_r1 {
            behind.insert(c.clone());
        }
        // (also give it the two non-leader round-r certs so only the leader
        // is genuinely missing, matching the real scenario)
        for c in round_r.iter().filter(|c| c.vertex.author != leader) {
            behind.insert(c.clone());
        }
        let b = Bullshark::new(&behind, &validators);
        assert_eq!(
            b.direct_status(r),
            RoundOutcome::Undecided,
            "a round whose leader is missing but is referenced as a parent by known children must be Undecided (wait for sync), never permanently Skipped"
        );

        // Fully-synced validator: add the leader's own cert. Now the leader
        // has quorum support and commits directly - the outcome the behind
        // validator must not be allowed to contradict by skipping.
        let mut synced = DagStore::new();
        for c in round_r.iter().chain(round_r1.iter()) {
            synced.insert(c.clone());
        }
        let s = Bullshark::new(&synced, &validators);
        assert_eq!(s.direct_status(r), RoundOutcome::Committed(leader_digest), "with the leader present and 3-of-4 support, it commits directly");
    }

    /// The crashed-leader liveness case the same code path must still allow:
    /// when the leader genuinely produced no certificate (so no round+1
    /// certificate references it and every known child's parents are all
    /// present), the round is soundly `Skipped` so the chain keeps moving.
    #[test]
    fn a_genuinely_absent_leader_is_still_skipped_so_the_chain_stays_live() {
        let validators = validators(4);
        let ids = validators.ids_sorted();
        let r = 1;
        let leader = {
            let dag = DagStore::new();
            Bullshark::new(&dag, &validators).leader_for_round(r).unwrap()
        };
        // Round-r certs from the THREE non-leader validators only - the
        // leader crashed and never certified round r.
        let non_leaders: Vec<ValidatorId> = ids.iter().copied().filter(|id| *id != leader).collect();
        let round_r: Vec<Certificate> = non_leaders.iter().map(|id| cert(r, *id, vec![])).collect();
        let round_r_digests: Vec<Digest> = round_r.iter().map(|c| c.digest()).collect();
        // Three round-(r+1) certs, each referencing only the present
        // non-leader round-r certs (never the absent leader).
        let round_r1: Vec<Certificate> = non_leaders.iter().map(|id| cert(r + 1, *id, round_r_digests.clone())).collect();

        let mut dag = DagStore::new();
        for c in round_r.iter().chain(round_r1.iter()) {
            dag.insert(c.clone());
        }
        let b = Bullshark::new(&dag, &validators);
        // known_stake = 3 (all round+1 certs present), unknown = 1 < quorum 3,
        // and every child's parents are present (none is the absent leader),
        // so known support is provably zero => sound permanent Skip.
        assert_eq!(
            b.direct_status(r),
            RoundOutcome::Skipped,
            "a genuinely-absent leader (no cert, no child references it, all child parents present) is soundly skipped to keep the chain live"
        );
    }
}
