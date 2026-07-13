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
pub struct ConsensusState {
    seen: HashSet<Digest>,
    /// The round `advance` starts walking from - `0` for a fresh validator
    /// (`new`), `starting_round` for a restarted one (`resuming_from`), and
    /// only ever moved forward by `set_gc_floor` when the DAG is actually
    /// pruned. Deliberately NOT advanced to the finalized floor every call:
    /// `resolve` can return `Skipped` for a round whose leader certificate is
    /// merely not synced *yet* (it stays sound because `direct_status`
    /// guarantees such a round is also unreachable, so the skip is permanent
    /// *given current data*) - but under certificate loss a late resync can
    /// still legitimately revise a *recent* round, so `extend_order` must
    /// keep re-resolving from a fixed low point rather than racing its start
    /// round up to the frontier. A live DST reproduced a real safety
    /// violation (two honest validators diverging) when this was advanced
    /// eagerly. It is only safe to move it up to `gc_floor`, which lags the
    /// finalized floor by `DAG_RETENTION_ROUNDS` - far enough behind the
    /// frontier that no in-flight resync can still touch those rounds.
    from_round: Round,
    /// Tracks how far consensus has *permanently* finalized (first round not
    /// yet committed/skipped-permanently), advanced monotonically after each
    /// `advance`. Used only to decide how much of the DAG is safe to garbage-
    /// collect (`finalized_floor`); never used as the `extend_order` start
    /// round - see `from_round` for why racing the start round forward is
    /// unsafe under certificate loss.
    finalized_floor: Round,
    /// GC barrier handed to `Bullshark` (see its `gc_floor` field): rounds
    /// strictly below this have been pruned from the DAG and are treated as
    /// permanently-committed history during causal walks. Only ever raised,
    /// never lowered, and always kept far below the finalized floor.
    gc_floor: Round,
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusState {
    pub fn new() -> Self {
        ConsensusState { seen: HashSet::new(), from_round: 0, finalized_floor: 0, gc_floor: 0 }
    }

    /// For a validator resuming from a persisted round checkpoint whose DAG
    /// content isn't persisted (see `qchain-node::engine::propose_round`'s
    /// doc comment for the sibling proposal-side bug/fix this pairs with -
    /// same real restart scenario, found in the same live reproduction,
    /// different code path). Starting `advance` from `0` every time (what
    /// `new` does) is correct for a validator whose local DAG genuinely
    /// spans everything from round 0 - but for one resuming with an empty
    /// DAG and a `next_round` already far past 0, round 0 can never
    /// resolve (no certificate for it, and no peer left to ever supply
    /// one in a single-validator network), so `extend_order`'s "stop at
    /// the first undecided round" safety rule - correct in general -
    /// would block forever on a round that's actually just permanently
    /// unrecoverable, not transiently missing. Starting from
    /// `starting_round` instead skips re-deriving commit order for
    /// history this validator can no longer see; nothing unsafe about
    /// that (this validator's own account-state effects of those earlier
    /// rounds already persisted via `SledStore` independent of Bullshark
    /// ordering).
    ///
    /// **Caller obligation, found the hard way (live, not by inspection):
    /// only call this when this validator's own stake alone already meets
    /// `ValidatorSet::quorum_threshold` - the exact same condition
    /// `qchain-node::engine::propose_round` guards its own fast path on.**
    /// It is *not* enough that a peer's intact DAG already finalized the
    /// skipped history "elsewhere" - `walk_causal_history` follows
    /// `Certificate::parents` wherever they actually point, regardless of
    /// where `extend_order`'s round loop starts, and a peer who never
    /// restarted has REAL parent links reaching back past
    /// `starting_round`. For a validator that isn't alone/dominant, using
    /// `resuming_from` doesn't skip that walk - it just empties `seen`
    /// right before the walk needs to redo it, and unlike the round-by-
    /// round outer loop (whose `seen` cache fills in incrementally, one
    /// resolved round at a time - the reason `new()` stays cheap), a
    /// `walk_causal_history` call that fails partway through (an ancestor
    /// still being resynced) caches *nothing at all*, so the whole
    /// multi-round walk gets repeated from scratch on every single
    /// incoming message while resync is in progress. Confirmed live: a
    /// real 3-validator testnet with evenly-spread stake (no validator
    /// dominant), one validator restarted after a real gap - CPU pinned
    /// past 200%, RSS climbing into the hundreds of MB within seconds,
    /// RPC completely unresponsive; the identical scenario using `new()`
    /// recovered in under a second. For a validator that isn't dominant,
    /// nothing else could have progressed without it while it was down
    /// anyway (quorum requires it), so there's no history to skip in the
    /// first place - `new()` is not just safe there, it's the only
    /// correct choice.
    pub fn resuming_from(starting_round: Round) -> Self {
        ConsensusState { seen: HashSet::new(), from_round: starting_round, finalized_floor: starting_round, gc_floor: 0 }
    }

    /// The first round not yet permanently finalized - everything strictly
    /// below is committed/skipped and applied. The node's safe upper bound
    /// on what it may garbage-collect (it prunes well below this, by
    /// `DAG_RETENTION_ROUNDS`, so late causal walks still find any orphaned
    /// but referenced ancestor).
    pub fn finalized_floor(&self) -> Round {
        self.finalized_floor
    }

    pub fn gc_floor(&self) -> Round {
        self.gc_floor
    }

    /// Raise the GC barrier to `round` (monotonic - a lower value is
    /// ignored). Called two ways: live, right after `DagStore::prune_below`
    /// drops the matching old rounds; and once at startup, set to the
    /// reloaded DAG's `lowest_round` so a node that persisted a *pruned* DAG
    /// re-derives its retained window against the same barrier those rounds
    /// were finalized under (its `seen` set didn't survive the restart, so
    /// the barrier is what stops the re-derivation walking off the bottom of
    /// the pruned DAG - see `Bullshark::gc_floor`). Also nudges `from_round`
    /// up to the barrier: a round below the barrier has no certificates left
    /// to resolve, so `extend_order` must never start there.
    pub fn set_gc_floor(&mut self, round: Round) {
        if round > self.gc_floor {
            self.gc_floor = round;
        }
        if round > self.from_round {
            self.from_round = round;
        }
        if round > self.finalized_floor {
            self.finalized_floor = round;
        }
    }

    /// Re-evaluates leader commitment across the whole DAG (cheap at
    /// phase-1/testnet scale - see the `dag-consensus-design` skill for the
    /// tradeoff) and returns any certificate digests newly finalized into
    /// the total order since the last call.
    pub fn advance(&mut self, dag: &DagStore, validators: &ValidatorSet) -> Vec<Digest> {
        let bullshark = Bullshark::with_gc_floor(dag, validators, self.gc_floor);
        let (ordered, stopped_at) = bullshark.extend_order(self.from_round, dag.highest_round(), &mut self.seen);
        // Record how far consensus has permanently finalized (the first
        // still-unresolved round), monotonically. This drives DAG garbage
        // collection only - it is deliberately NOT fed back into `from_round`
        // (see that field's doc comment for the real safety violation eager
        // advancement caused under certificate loss). `extend_order` keeps
        // starting from the fixed `from_round` so a late resync can still
        // revise a recent round.
        if stopped_at > self.finalized_floor {
            self.finalized_floor = stopped_at;
        }
        ordered
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
    use qchain_crypto::{MultiSignature, Keypair};

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
        let signatures: Vec<(qchain_core::ValidatorId, MultiSignature)> =
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
                let vertex = Vertex { round, author: v.id, batch_digests: vec![(0, batch_digest)], parents: prev_round_digests.clone() };
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
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digests: vec![(0, [0u8; 32])], parents: vec![] };
        // Only one signer - below the quorum threshold of 3.
        let cert = certify(vertex, &tvs[..1]);
        assert!(!verify_certificate(&cert, &validators));
    }

    #[test]
    fn certificate_verification_accepts_quorum_signatures() {
        let (tvs, validators) = make_validators(4);
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digests: vec![(0, [0u8; 32])], parents: vec![] };
        let cert = certify(vertex, &tvs[..3]);
        assert!(verify_certificate(&cert, &validators));
    }

    #[test]
    fn certificate_verification_rejects_forged_signatures() {
        let (tvs, validators) = make_validators(4);
        let vertex = Vertex { round: 0, author: tvs[0].id, batch_digests: vec![(0, [0u8; 32])], parents: vec![] };
        let mut cert = certify(vertex, &tvs[..3]);
        cert.signatures[0].1.components[0].bytes[0] ^= 0xFF;
        assert!(!verify_certificate(&cert, &validators), "a quorum count that includes a forged signature must not pass");
    }

    #[test]
    fn round_advancement_requires_quorum_of_the_round() {
        let (tvs, validators) = make_validators(4);
        let mut dag = DagStore::new();
        assert!(!can_advance_round(&dag, &validators, 0));

        for v in &tvs[..2] {
            let vertex = Vertex { round: 0, author: v.id, batch_digests: vec![(0, [0u8; 32])], parents: vec![] };
            dag.insert(certify(vertex, &tvs));
        }
        assert!(!can_advance_round(&dag, &validators, 0), "2 of 4 is below the quorum threshold of 3");

        let vertex = Vertex { round: 0, author: tvs[2].id, batch_digests: vec![(0, [0u8; 32])], parents: vec![] };
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

    /// Garbage-collecting old rounds from the DAG below the finalized floor,
    /// with the matching `gc_floor` barrier raised in lock-step, must not
    /// change or lose any of the committed total order - the safety property
    /// the whole DAG-pruning scheme rests on. Models a live node: advance,
    /// prune, raise the barrier, advance again.
    #[test]
    fn pruning_below_the_finalized_floor_never_changes_the_committed_order() {
        let (tvs, validators) = make_validators(4);
        let dag = build_dag(&tvs, 12);
        let baseline = ConsensusState::new().advance(&dag, &validators);
        assert!(!baseline.is_empty());

        let mut state = ConsensusState::new();
        let mut got = state.advance(&dag, &validators);
        // Prune a couple of rounds below where consensus has finalized, and
        // raise the barrier exactly as `prune_stale_round_state` does.
        let gc = state.finalized_floor().saturating_sub(2);
        assert!(gc > 0, "the test DAG must finalize far enough to leave a real prune margin");
        let mut pruned = build_dag(&tvs, 12);
        let removed = pruned.prune_below(gc);
        assert!(!removed.is_empty(), "there must be old rounds to actually prune");
        state.set_gc_floor(gc);
        got.extend(state.advance(&pruned, &validators));

        assert_eq!(got, baseline, "a GC below the finalized floor (barrier raised in lock-step) must leave the committed order identical");
    }

    /// The restart path the GC barrier exists for: `seen` does not survive a
    /// process restart, so a node that persisted a *pruned* DAG must
    /// re-derive its retained window from scratch - and must stop cleanly at
    /// the barrier instead of walking a retained leader's ancestry off the
    /// bottom of the pruned DAG and stalling. The re-derived order must be
    /// exactly the retained tail of the full committed order.
    #[test]
    fn a_restart_re_derives_the_retained_window_against_the_barrier_without_stalling() {
        let (tvs, validators) = make_validators(4);
        let dag_full = build_dag(&tvs, 12);
        let baseline = ConsensusState::new().advance(&dag_full, &validators);
        assert!(!baseline.is_empty());

        let gc = 4;
        let mut pruned = build_dag(&tvs, 12);
        pruned.prune_below(gc);
        assert_eq!(pruned.lowest_round(), gc, "prune leaves the retained window starting exactly at gc");

        // Exactly what `main.rs` does on restart: fresh state (empty `seen`),
        // barrier set from the reloaded DAG's real lowest round.
        let mut restarted = ConsensusState::new();
        restarted.set_gc_floor(pruned.lowest_round());
        let after_restart = restarted.advance(&pruned, &validators);

        assert!(!after_restart.is_empty(), "a restarted node must re-derive its retained window, never stall at the barrier");
        let expected_tail: Vec<Digest> =
            baseline.iter().copied().filter(|d| pruned.get(d).map(|c| c.vertex.round >= gc).unwrap_or(false)).collect();
        assert_eq!(after_restart, expected_tail, "restart re-derivation must reproduce exactly the retained tail of the committed order");
        // And nothing below the barrier may sneak back in.
        for d in &after_restart {
            assert!(pruned.get(d).unwrap().vertex.round >= gc, "no digest below the GC barrier may appear in the re-derived order");
        }
    }

    /// One validator never proposes at all (a crashed/silent validator) -
    /// still gets a quorum-worth of the other 3 validators' signatures on
    /// every *other* author's certificate (so the direct rule works fine
    /// for rounds whose leader isn't the silent one), but never has a
    /// certificate of its own in any round. `leader_for_round` rotates
    /// deterministically across all 4 validators, so within enough rounds
    /// the silent validator is guaranteed to be elected leader at least
    /// once - exactly the real regression the indirect commit rule closes
    /// (see `bullshark.rs` module docs and `project-lessons-learned`):
    /// without it, that round's leader-slot can never satisfy the direct
    /// rule, and stopping (rather than unsafely skipping) at an
    /// unresolved round would otherwise halt the total order forever.
    fn build_dag_with_one_silent_validator(tvs: &[TestValidator], rounds: u64, silent_idx: usize) -> DagStore {
        let mut dag = DagStore::new();
        let mut prev_round_digests: Vec<Digest> = Vec::new();
        for round in 0..rounds {
            let mut this_round_digests = Vec::new();
            for (i, v) in tvs.iter().enumerate() {
                if i == silent_idx {
                    continue;
                }
                let mut batch_digest = Batch { transactions: vec![] }.digest();
                batch_digest[0] = batch_digest[0].wrapping_add(i as u8);
                let vertex = Vertex { round, author: v.id, batch_digests: vec![(0, batch_digest)], parents: prev_round_digests.clone() };
                let digest = vertex.digest();
                let signatures: Vec<(qchain_core::ValidatorId, MultiSignature)> = tvs
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != silent_idx)
                    .map(|(_, signer)| (signer.id, signer.keypair.sign(&digest[..]).unwrap()))
                    .collect();
                let cert = Certificate { vertex, signatures };
                this_round_digests.push(dag.insert(cert));
            }
            prev_round_digests = this_round_digests;
        }
        dag
    }

    #[test]
    fn a_leader_slot_whose_validator_never_proposes_commits_indirectly_instead_of_stalling_forever() {
        let (tvs, validators) = make_validators(4);
        let empty_dag = DagStore::new();
        let bullshark = Bullshark::new(&empty_dag, &validators);
        // Find a round within the first 20 where the silent validator (index
        // 0) is actually elected leader - guarantees this test exercises
        // the indirect rule, not just the direct one.
        let silent_id = tvs[0].id;
        let silent_leader_round = (0..20u64).find(|&r| bullshark.leader_for_round(r) == Some(silent_id));
        let silent_leader_round = silent_leader_round.expect("the silent validator must be elected leader within 20 rounds across a 4-validator set");

        let dag = build_dag_with_one_silent_validator(&tvs, silent_leader_round + 5, 0);
        let order = ConsensusState::new().advance(&dag, &validators);

        assert!(!order.is_empty(), "3 honest, live validators (2f+1 for f=1) must still make progress despite one never proposing");
        // The silent validator's own designated round must never appear in
        // the order at all - there's no certificate for it anywhere, by
        // construction, so it can only ever be legitimately skipped, never
        // committed.
        for digest in &order {
            let cert = dag.get(digest).unwrap();
            assert_ne!(
                (cert.vertex.round, cert.vertex.author),
                (silent_leader_round, silent_id),
                "a certificate that was never actually created must never appear in the committed order"
            );
        }
    }
}
