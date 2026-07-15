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
use crate::schedule::ValidatorSchedule;
use qchain_core::{Certificate, Digest, Round, ValidatorId};
use sha3::{Digest as _, Sha3_256};
use std::collections::{HashMap, HashSet};

pub struct Bullshark<'a> {
    dag: &'a DagStore,
    /// Resolves the committee in effect for a given round (stage 1: a single
    /// set for all rounds — see `ValidatorSchedule`). Leader election and every
    /// quorum check below ask this per round rather than assuming one global
    /// set, so a later stage can vary the committee by epoch without touching
    /// the ordering logic here.
    schedule: &'a ValidatorSchedule,
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
    pub fn new(dag: &'a DagStore, schedule: &'a ValidatorSchedule) -> Self {
        Bullshark { dag, schedule, gc_floor: 0 }
    }

    pub fn with_gc_floor(dag: &'a DagStore, schedule: &'a ValidatorSchedule, gc_floor: Round) -> Self {
        Bullshark { dag, schedule, gc_floor }
    }

    /// Deterministic, stake-agnostic leader selection: every honest
    /// validator computes the same leader for a given round from a hash of
    /// the round number alone, so agreeing on "who proposes this round's
    /// block" costs no extra consensus round.
    pub fn leader_for_round(&self, round: Round) -> Option<ValidatorId> {
        let ids = self.schedule.for_round(round).ids_sorted();
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
        // Committee in effect for this round (stage 1: the single base set).
        let validators = self.schedule.for_round(round);
        let quorum = validators.quorum_threshold();
        let next_round_certs: Vec<&Certificate> = self.dag.certificates_in_round(round + 1).collect();
        let known_stake: u64 = next_round_certs.iter().map(|c| validators.stake_of(&c.vertex.author)).sum();
        // However much round+1 stake this validator simply hasn't seen a
        // certificate for yet - the upper bound on how much MORE support
        // could still show up, no matter what it turns out to reference.
        let unknown_stake = validators.total_stake().saturating_sub(known_stake);

        match self.dag.certificate_by_author(round, &leader) {
            Some(leader_cert) => {
                let leader_digest = leader_cert.digest();
                let supporting_stake: u64 =
                    next_round_certs.iter().filter(|c| c.vertex.parents.contains(&leader_digest)).map(|c| validators.stake_of(&c.vertex.author)).sum();
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
    ///
    /// **Iterative, not recursive, on purpose.** A causal history can be
    /// thousands of rounds deep on a long-lived chain, and a recursive walk
    /// would overflow the stack. This is an explicit-stack post-order DFS
    /// that reproduces the recursive version's output byte-for-byte: each
    /// node is emitted into `ordered` only after all of its (above-barrier)
    /// parents, parents are visited in sorted order, `memo` caches per-call
    /// and `seen` short-circuits across calls, and the `gc_floor` barrier
    /// cuts a node's parents off exactly as before. The `Enter`/`Exit`
    /// two-phase marker is what gives post-order (a node's `Exit` runs only
    /// after its whole subtree); because the stack is LIFO, a shared ancestor
    /// reached via a second path is always already in `memo` by the time that
    /// path re-enters it, so it is never re-expanded - the same anti-blowup
    /// guarantee the per-call memo gave the recursive version.
    fn walk_causal_history(&self, root: Digest, seen: &mut HashSet<Digest>, ordered: &mut Vec<Digest>, memo: &mut HashMap<Digest, bool>) -> bool {
        enum Step {
            Enter(Digest),
            Exit(Digest),
        }
        let mut stack = vec![Step::Enter(root)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(digest) => {
                    if seen.contains(&digest) || memo.contains_key(&digest) {
                        continue;
                    }
                    let Some(cert) = self.dag.get(&digest) else {
                        memo.insert(digest, false);
                        continue;
                    };
                    // A certificate at round `r` lists parents from round
                    // `r - 1`. Once `r <= gc_floor` those parents belong to
                    // the pruned, permanently-committed region (see
                    // `gc_floor`): they are treated as resolved without being
                    // visited, so a restart re-derivation stops cleanly at the
                    // barrier instead of failing on a dropped certificate.
                    if cert.vertex.round <= self.gc_floor {
                        seen.insert(digest);
                        ordered.push(digest);
                        memo.insert(digest, true);
                        continue;
                    }
                    let mut parents = cert.vertex.parents.clone();
                    parents.sort();
                    // Exit runs after every parent's subtree (LIFO); parents
                    // pushed in reverse so they pop in sorted order, matching
                    // the recursive `for parent in sorted(parents)` emission.
                    stack.push(Step::Exit(digest));
                    for parent in parents.into_iter().rev() {
                        stack.push(Step::Enter(parent));
                    }
                }
                Step::Exit(digest) => {
                    if seen.contains(&digest) || memo.contains_key(&digest) {
                        continue;
                    }
                    let cert = self.dag.get(&digest).expect("a digest present at Enter is still present at Exit");
                    let all_parents_resolved = cert.vertex.parents.iter().all(|p| seen.contains(p) || memo.get(p).copied().unwrap_or(false));
                    if all_parents_resolved {
                        seen.insert(digest);
                        ordered.push(digest);
                        memo.insert(digest, true);
                    } else {
                        // A sibling reachable via a different parent already
                        // committed on its own merits during the walk; only
                        // this digest's own chain is still unresolved.
                        memo.insert(digest, false);
                    }
                }
            }
        }
        seen.contains(&root)
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
    pub fn extend_order(&self, from_round: Round, up_to_round: Round, seen: &mut HashSet<Digest>, committed_cache: &mut HashMap<Round, Digest>) -> (Vec<Digest>, Round) {
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
            // A `Committed` verdict is permanent (see `ConsensusState::
            // committed_cache`): once cached, skip the O(n) re-resolution and
            // reuse it - byte-identical, since the digest can never change. Only
            // `Committed` is cached; `Skipped`/`Undecided` are always recomputed
            // so a late resync can still revise them (why `from_round` stays put).
            let outcome = match committed_cache.get(&round) {
                Some(&digest) => RoundOutcome::Committed(digest),
                None => {
                    let o = self.resolve(round, up_to_round);
                    if let RoundOutcome::Committed(d) = o {
                        committed_cache.insert(round, d);
                    }
                    o
                }
            };
            match outcome {
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
    ///
    /// Iterative for the same stack-depth reason as `walk_causal_history`.
    /// Equivalent to the recursive tri-state: `Some(true)` the moment any
    /// fully-present path reaches `target`; `None` if no present path reaches
    /// it but some path ran into a certificate missing locally (still being
    /// resynced - can't yet conclude "unreachable"); `Some(false)` only when
    /// every path is definitively present and none reaches `target`. The
    /// global `undecided` flag captures the recursive `any_undecided`
    /// propagation exactly, since a `None` bubbles up through any node that
    /// finds no `Some(true)` among its parents. The `gc_floor` barrier stops
    /// a path as a definite non-reach (the target is always a round being
    /// resolved, `>= gc_floor`, so it can never lie in the pruned region).
    fn reaches(&self, from: Digest, target: Digest, visited: &mut HashSet<Digest>) -> Option<bool> {
        let mut undecided = false;
        let mut stack = vec![from];
        while let Some(node) = stack.pop() {
            if node == target {
                return Some(true);
            }
            if !visited.insert(node) {
                continue;
            }
            let Some(cert) = self.dag.get(&node) else {
                undecided = true;
                continue;
            };
            if cert.vertex.round <= self.gc_floor {
                continue;
            }
            for &parent in &cert.vertex.parents {
                stack.push(parent);
            }
        }
        if undecided {
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
    use crate::quorum::ValidatorSet;
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
        let schedule = ValidatorSchedule::single(validators(4));
        let dag = DagStore::new();
        let bullshark = Bullshark::new(&dag, &schedule);

        assert_eq!(bullshark.leader_for_round(5), bullshark.leader_for_round(5));

        let leaders: HashSet<_> = (0..50).filter_map(|r| bullshark.leader_for_round(r)).collect();
        assert!(leaders.len() > 1, "leadership must rotate across rounds, not stick to one validator");
    }

    #[test]
    fn empty_validator_set_has_no_leader() {
        let schedule = ValidatorSchedule::single(ValidatorSet::new(vec![]));
        let dag = DagStore::new();
        let bullshark = Bullshark::new(&dag, &schedule);
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
        let schedule = ValidatorSchedule::single(validators.clone());
        let ids = validators.ids_sorted();
        let r = 1;
        // The four round-r certificates (one per validator). The leader's is
        // the one we'll withhold from the "behind" validator's DAG.
        let leader = {
            let dag = DagStore::new();
            Bullshark::new(&dag, &schedule).leader_for_round(r).unwrap()
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
        let b = Bullshark::new(&behind, &schedule);
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
        let s = Bullshark::new(&synced, &schedule);
        assert_eq!(s.direct_status(r), RoundOutcome::Committed(leader_digest), "with the leader present and 3-of-4 support, it commits directly");
    }

    /// The iterative `walk_causal_history` must handle a causal chain far
    /// deeper than the native stack could recurse (the whole reason it was
    /// converted from recursion). Also pins the exact post-order: a linear
    /// chain emits ancestor-first, byte-identical to what the recursive
    /// version produced.
    #[test]
    fn walk_causal_history_handles_a_chain_far_deeper_than_the_recursion_limit() {
        let validators = validators(1);
        let author = validators.ids_sorted()[0];
        let schedule = ValidatorSchedule::single(validators);
        let mut dag = DagStore::new();
        let depth: u64 = 200_000;
        let mut prev: Vec<Digest> = vec![];
        let mut digests = Vec::with_capacity(depth as usize);
        for r in 0..depth {
            let d = dag.insert(cert(r, author, prev.clone()));
            digests.push(d);
            prev = vec![d];
        }
        let bull = Bullshark::new(&dag, &schedule);
        let mut seen = HashSet::new();
        let mut ordered = Vec::new();
        let mut memo = HashMap::new();
        assert!(bull.walk_causal_history(*digests.last().unwrap(), &mut seen, &mut ordered, &mut memo), "a fully-present deep chain must resolve");
        assert_eq!(ordered.len() as u64, depth, "every certificate in the chain is emitted exactly once");
        assert_eq!(ordered, digests, "a linear chain must emit ancestor-first (deepest first), identical to the recursive post-order");
    }

    /// The crashed-leader liveness case the same code path must still allow:
    /// when the leader genuinely produced no certificate (so no round+1
    /// certificate references it and every known child's parents are all
    /// present), the round is soundly `Skipped` so the chain keeps moving.
    #[test]
    fn a_genuinely_absent_leader_is_still_skipped_so_the_chain_stays_live() {
        let validators = validators(4);
        let schedule = ValidatorSchedule::single(validators.clone());
        let ids = validators.ids_sorted();
        let r = 1;
        let leader = {
            let dag = DagStore::new();
            Bullshark::new(&dag, &schedule).leader_for_round(r).unwrap()
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
        let b = Bullshark::new(&dag, &schedule);
        // known_stake = 3 (all round+1 certs present), unknown = 1 < quorum 3,
        // and every child's parents are present (none is the absent leader),
        // so known support is provably zero => sound permanent Skip.
        assert_eq!(
            b.direct_status(r),
            RoundOutcome::Skipped,
            "a genuinely-absent leader (no cert, no child references it, all child parents present) is soundly skipped to keep the chain live"
        );
    }

    /// **Phase-3.3 stage-2 core proof: a committee change at an epoch boundary
    /// does not fork honest validators and the chain stays live across it.**
    /// Epoch length 2, committee A = {v0,v1,v2,v3} for epoch 0 (rounds 0-1),
    /// committee B = {v1,v2,v3,v4} for epoch 1 (rounds 2-3) — a real rotation
    /// (v0 leaves, v4 joins, three overlap). Each round `r` is decided entirely
    /// under `for_round(r)` (see `direct_status`), so the boundary round 1
    /// (committee A) counts its round-2 support weighted by A: v4 (in B, not A)
    /// contributes zero, v1/v2/v3 contribute their A stake. Verifies: (1) the
    /// committed order is independent of delivery order (full-at-once vs
    /// incremental) — the safety property; (2) a peer missing a certificate
    /// commits a prefix of the full order, never a divergent one; (3) the order
    /// actually crosses the boundary and commits a committee-B round — liveness
    /// under rotation.
    #[test]
    fn a_committee_change_at_an_epoch_boundary_keeps_honest_validators_consistent_and_live() {
        use crate::ConsensusState;
        let kps: Vec<Keypair> = (0..5).map(|_| Keypair::generate().unwrap()).collect();
        let info = |i: usize| crate::quorum::ValidatorInfo { id: kps[i].pubkey(), pubkey_bundle: kps[i].public_key_bundle(), stake: 1 };
        let committee_a = ValidatorSet::new((0..4).map(info).collect());
        let committee_b = ValidatorSet::new((1..5).map(info).collect());
        let a_ids: Vec<ValidatorId> = (0..4).map(|i| kps[i].pubkey()).collect();
        let b_ids: Vec<ValidatorId> = (1..5).map(|i| kps[i].pubkey()).collect();
        let mut schedule = ValidatorSchedule::new(2, committee_a);
        schedule.install_epoch(1, committee_b);
        schedule.set_frontier_epoch(1); // the node has derived committee(1); epoch 1 is now resolvable

        // Build a full cross-epoch DAG: rounds 0,1 authored by A; rounds 2,3 by
        // B; every round references all of the previous round's certificates.
        let r0: Vec<Certificate> = a_ids.iter().map(|id| cert(0, *id, vec![])).collect();
        let r0d: Vec<Digest> = r0.iter().map(|c| c.digest()).collect();
        let r1: Vec<Certificate> = a_ids.iter().map(|id| cert(1, *id, r0d.clone())).collect();
        let r1d: Vec<Digest> = r1.iter().map(|c| c.digest()).collect();
        let r2: Vec<Certificate> = b_ids.iter().map(|id| cert(2, *id, r1d.clone())).collect();
        let r2d: Vec<Digest> = r2.iter().map(|c| c.digest()).collect();
        let r3: Vec<Certificate> = b_ids.iter().map(|id| cert(3, *id, r2d.clone())).collect();

        let insert_all = |dag: &mut DagStore, certs: &[&[Certificate]]| {
            for group in certs {
                for c in group.iter() {
                    dag.insert(c.clone());
                }
            }
        };

        // Validator X: receives everything, commits in one shot.
        let mut dag_full = DagStore::new();
        insert_all(&mut dag_full, &[&r0, &r1, &r2, &r3]);
        let order_full = ConsensusState::new().advance(&dag_full, &schedule);

        // Validator Y: same certificates, delivered incrementally across the
        // boundary. The committed order MUST be identical — delivery order can
        // never change what commits or in what order (the safety property).
        let mut dag_inc = DagStore::new();
        let mut state_y = ConsensusState::new();
        let mut order_inc = Vec::new();
        insert_all(&mut dag_inc, &[&r0, &r1, &r2]);
        order_inc.extend(state_y.advance(&dag_inc, &schedule));
        insert_all(&mut dag_inc, &[&r3]);
        order_inc.extend(state_y.advance(&dag_inc, &schedule));
        assert_eq!(order_full, order_inc, "committee change must not make the committed order depend on delivery order");

        // Validator Z: missing one committee-B round-2 certificate (v1's). Its
        // committed order must be a PREFIX of the full order — behind, never
        // divergent.
        let mut dag_partial = DagStore::new();
        insert_all(&mut dag_partial, &[&r0, &r1]);
        for c in r2.iter().filter(|c| c.vertex.author != b_ids[0]) {
            dag_partial.insert(c.clone());
        }
        insert_all(&mut dag_partial, &[&r3]);
        let order_partial = ConsensusState::new().advance(&dag_partial, &schedule);
        let n = order_partial.len().min(order_full.len());
        assert_eq!(order_partial[..n], order_full[..n], "a peer with a missing certificate must commit a prefix of the full order, never a fork");

        // Liveness across the boundary: the full order must include a committed
        // committee-B (epoch-1) round. Round 2's leader is chosen from committee
        // B; its certificate being in the committed order proves consensus
        // crossed the rotation and kept committing.
        let leader_2 = Bullshark::new(&dag_full, &schedule).leader_for_round(2).expect("epoch-1 committee elects a leader");
        let leader_2_digest = r2.iter().find(|c| c.vertex.author == leader_2).unwrap().digest();
        assert!(order_full.contains(&leader_2_digest), "consensus must cross the epoch boundary and commit a committee-B round (liveness under rotation)");
    }

    /// **Phase-3.3 stage-2b: the resolvable frontier holds back rounds of an
    /// epoch whose committee is not yet installed.** With a rotating schedule
    /// whose frontier is still at epoch 0, `advance` must resolve epoch-0 rounds
    /// but leave epoch-1 rounds untouched (their committee isn't known yet);
    /// raising the frontier to epoch 1 then lets them commit. This is what stops
    /// a single catch-up pass from committing a later epoch under the wrong
    /// (inherited) committee before the node has derived the real one.
    #[test]
    fn the_resolvable_frontier_holds_back_rounds_of_an_uninstalled_epoch() {
        use crate::ConsensusState;
        let kps: Vec<Keypair> = (0..4).map(|_| Keypair::generate().unwrap()).collect();
        let info = |i: usize| crate::quorum::ValidatorInfo { id: kps[i].pubkey(), pubkey_bundle: kps[i].public_key_bundle(), stake: 1 };
        let committee = ValidatorSet::new((0..4).map(info).collect());
        let ids: Vec<ValidatorId> = (0..4).map(|i| kps[i].pubkey()).collect();
        // Same committee both epochs (the guard is about *timing*, not a change);
        // frontier starts at epoch 0.
        let mut schedule = ValidatorSchedule::new(2, committee.clone());
        schedule.install_epoch(1, committee);

        // DAG spanning epochs 0 (rounds 0,1) and 1 (rounds 2,3).
        let r0: Vec<Certificate> = ids.iter().map(|id| cert(0, *id, vec![])).collect();
        let r0d: Vec<Digest> = r0.iter().map(|c| c.digest()).collect();
        let r1: Vec<Certificate> = ids.iter().map(|id| cert(1, *id, r0d.clone())).collect();
        let r1d: Vec<Digest> = r1.iter().map(|c| c.digest()).collect();
        let r2: Vec<Certificate> = ids.iter().map(|id| cert(2, *id, r1d.clone())).collect();
        let r2d: Vec<Digest> = r2.iter().map(|c| c.digest()).collect();
        let r3: Vec<Certificate> = ids.iter().map(|id| cert(3, *id, r2d.clone())).collect();
        let mut dag = DagStore::new();
        for c in r0.iter().chain(&r1).chain(&r2).chain(&r3) {
            dag.insert(c.clone());
        }

        // Frontier at epoch 0: advance resolves only epoch-0 rounds. None of the
        // epoch-1 certificates (rounds 2,3) may be committed yet.
        let order_capped = ConsensusState::new().advance(&dag, &schedule);
        let epoch1_digests: HashSet<Digest> = r2.iter().chain(&r3).map(|c| c.digest()).collect();
        assert!(
            order_capped.iter().all(|d| !epoch1_digests.contains(d)),
            "with the frontier at epoch 0, no epoch-1 round may be committed"
        );

        // Raise the frontier to epoch 1 (committee derived): now epoch-1 rounds
        // resolve, and the previously-committed prefix is unchanged (monotone).
        schedule.set_frontier_epoch(1);
        let order_open = ConsensusState::new().advance(&dag, &schedule);
        assert!(order_open.len() > order_capped.len(), "raising the frontier must let more rounds commit");
        assert_eq!(order_open[..order_capped.len()], order_capped[..], "raising the frontier must not change what already committed");
    }
}
