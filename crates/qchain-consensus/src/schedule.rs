//! Per-epoch validator membership — the choke point for phase-3.3 dynamic
//! validator rotation (design: `ARCHITECTURE.md` §1/§6, phase-3 roadmap).
//!
//! **Why consensus needs this.** Leader election (`Bullshark::leader_for_round`
//! = `SHA3(round) % n`) and every quorum computation are *membership-dependent*:
//! change who is in the set — or even how many — and the leader of a given
//! round and the quorum threshold both change. A DAG-BFT chain whose validator
//! set can grow/shrink over time therefore cannot pass a single static
//! `ValidatorSet` into consensus; it must resolve *which* set is in effect for
//! *which* round. `ValidatorSchedule` is that resolver, and it is deliberately
//! the *only* place round→committee mapping lives, so consensus code always
//! asks "the set for round r" rather than assuming one global set.
//!
//! **Committees change only at epoch boundaries, and each round is decided
//! entirely under its own epoch's committee.** An epoch is `epoch_rounds`
//! consecutive rounds; the committee is *frozen* for the whole epoch, so every
//! honest node resolves the same committee for the same round. Crucially,
//! `Bullshark::direct_status(r)` evaluates round `r`'s commit decision — leader,
//! quorum threshold, *and* the weighting of round `r+1`'s supporting
//! certificates — all under `for_round(r)` (see that function). It never mixes
//! two committees in one decision. That is what makes a committee change safe:
//!   - **Safety.** Round `r`'s direct decision is a pure function of
//!     `committee(epoch(r))` and the DAG, identical on every honest node, so two
//!     honest nodes can never diverge across a boundary. A round-`r+1`
//!     certificate authored by a validator that is in `committee(epoch(r+1))`
//!     but *not* in `committee(epoch(r))` simply contributes zero stake to round
//!     `r`'s decision — sound, not lost.
//!   - **Liveness under turnover.** Even if a boundary fully replaces the
//!     committee (no overlap), round `r+1` vertices still reference round `r`
//!     certificates as DAG parents, so the boundary round remains in the causal
//!     history of the next epoch's committed leaders and commits via the
//!     *indirect* rule. (Verified by the membership-change DST in
//!     `qchain-simulation`.)
//!
//! **Determinism of the committee itself is the caller's job.** This module
//! only *stores* per-epoch committees and resolves a round to one; who is in
//! `committee(e)` is decided upstream (the node derives it from committed
//! on-chain state — the validator registry as of the end of epoch `e-1` — so
//! all nodes install byte-identical committees). Epoch 0 is always the
//! bootstrap/genesis committee.
//!
//! `single` (a schedule with only epoch 0 installed) resolves every round to
//! that one committee regardless of `epoch_rounds`, i.e. the exact phase-1/2
//! single-`ValidatorSet` behavior — the shape stage 1 shipped and the DST
//! proved byte-identical.

use crate::quorum::ValidatorSet;
use qchain_core::Round;
use std::collections::BTreeMap;

/// Default epoch length when a schedule is built with `single` (where it is
/// irrelevant, since only epoch 0 exists). Matches
/// `qchain_execution::validator_registry::EPOCH_ROUNDS`; the node passes the
/// same value explicitly via `new` when it builds a rotating schedule.
pub const DEFAULT_EPOCH_ROUNDS: u64 = 1024;

/// Resolves the validator committee in effect for a given consensus round.
///
/// Holds one committee per epoch (keyed by epoch number); `for_round` maps a
/// round to its epoch and returns the committee of the highest installed epoch
/// `<=` that epoch, so an epoch with no explicit entry inherits the most recent
/// prior committee (i.e. "no change this epoch"). Epoch 0 is always present.
#[derive(Clone, Debug)]
pub struct ValidatorSchedule {
    /// Rounds per epoch — the granularity at which the committee may change.
    epoch_rounds: u64,
    /// Committee per epoch. Epoch 0 is always present (the bootstrap committee).
    committees: BTreeMap<u64, ValidatorSet>,
    /// The highest epoch whose committee is finalized/known — the "resolvable
    /// frontier". Consensus may resolve rounds up to the last round of this
    /// epoch, but not beyond, until a later epoch's committee is derived and
    /// installed. This is what makes the *live* rotation safe: a single
    /// resolution pass (even a large catch-up) can never commit a round whose
    /// epoch's committee is not yet known — which could otherwise let two nodes
    /// that derive that committee at different points diverge. `u64::MAX` means
    /// "unbounded / fixed membership" (a `single` schedule), i.e. no guard.
    frontier_epoch: u64,
}

impl ValidatorSchedule {
    /// A schedule with a single committee for every round (phase-1/2 behavior):
    /// only epoch 0 is installed, so `for_round` returns it for every round
    /// regardless of `epoch_rounds`. Stage 1 used this exclusively; it remains
    /// the correct choice for a fixed-membership deployment.
    pub fn single(set: ValidatorSet) -> Self {
        let mut committees = BTreeMap::new();
        committees.insert(0, set);
        // Unbounded frontier: fixed membership, every round always resolvable —
        // the guard is a no-op, so behavior is exactly the phase-1/2 consensus.
        ValidatorSchedule { epoch_rounds: DEFAULT_EPOCH_ROUNDS, committees, frontier_epoch: u64::MAX }
    }

    /// A rotating schedule with a given epoch length and a bootstrap (epoch-0)
    /// committee. Future epochs' committees are added with `install_epoch` once
    /// they are deterministically derivable from committed state.
    pub fn new(epoch_rounds: u64, bootstrap: ValidatorSet) -> Self {
        assert!(epoch_rounds > 0, "epoch_rounds must be positive");
        let mut committees = BTreeMap::new();
        committees.insert(0, bootstrap);
        // Only epoch 0 is known at genesis; consensus may not resolve later
        // epochs until the node derives and installs their committees and raises
        // the frontier (`set_frontier_epoch`).
        ValidatorSchedule { epoch_rounds, committees, frontier_epoch: 0 }
    }

    /// The highest epoch whose committee is finalized/known — the resolvable
    /// frontier. `u64::MAX` for a fixed-membership (`single`) schedule.
    pub fn frontier_epoch(&self) -> u64 {
        self.frontier_epoch
    }

    /// Whether `id` is a member of ANY installed committee (any epoch). Used by
    /// the node to authenticate the sender of an unauthenticated worker-batch
    /// gossip/response: legitimate batches only ever originate from validators,
    /// so a non-validator flooding junk batches can be rejected before it costs
    /// any RAM/disk. Checking *all* installed committees (not just the current
    /// one) keeps a batch from a just-departed or adjacent-epoch validator
    /// acceptable, preserving resync liveness under rotation. For a `single`
    /// schedule this is exactly the one fixed committee.
    pub fn is_known_in_any_committee(&self, id: &qchain_core::ValidatorId) -> bool {
        self.committees.values().any(|c| c.get(id).is_some())
    }

    /// Raise the resolvable frontier to `epoch` (monotonic; a lower value is
    /// ignored). **Caller obligation:** only raise the frontier to `epoch` after
    /// installing `epoch`'s committee, which must be a deterministic function of
    /// committed state at the end of epoch `epoch-1` (so every honest node
    /// installs the identical committee), or consensus would resolve that
    /// epoch's rounds under the wrong (inherited) committee and could fork.
    pub fn set_frontier_epoch(&mut self, epoch: u64) {
        if epoch > self.frontier_epoch {
            self.frontier_epoch = epoch;
        }
    }

    /// The last round consensus may resolve right now: the final round of the
    /// frontier epoch (`u64::MAX` — no bound — for a fixed-membership schedule).
    /// `ConsensusState::advance` clamps `extend_order`'s upper bound to this, so
    /// even a large catch-up never resolves a round whose epoch's committee is
    /// not yet known.
    pub fn resolvable_frontier_round(&self) -> Round {
        if self.frontier_epoch == u64::MAX {
            u64::MAX
        } else {
            // Last round of `frontier_epoch`. Saturating so a huge frontier can
            // never overflow (it just means "unbounded" in practice).
            self.frontier_epoch.saturating_add(1).saturating_mul(self.epoch_rounds).saturating_sub(1)
        }
    }

    /// Rounds per epoch.
    pub fn epoch_rounds(&self) -> u64 {
        self.epoch_rounds
    }

    /// Which epoch a round falls in.
    pub fn epoch_of(&self, round: Round) -> u64 {
        round / self.epoch_rounds
    }

    /// Install (or replace) the committee that takes effect at the start of
    /// `epoch`. Idempotent per epoch. The caller must only install `committee`
    /// for `epoch` once it is a deterministic function of committed state that
    /// every honest node agrees on (see the node's epoch-boundary derivation),
    /// or nodes would resolve different committees and fork. Installing a
    /// committee identical to the one an epoch already inherits is a harmless
    /// no-op change.
    pub fn install_epoch(&mut self, epoch: u64, committee: ValidatorSet) {
        self.committees.insert(epoch, committee);
    }

    /// Whether a committee has been explicitly installed for `epoch` (as opposed
    /// to inheriting a prior epoch's). Lets the node install each epoch's
    /// committee exactly once.
    pub fn has_epoch(&self, epoch: u64) -> bool {
        self.committees.contains_key(&epoch)
    }

    /// The highest epoch with an explicitly installed committee.
    pub fn latest_installed_epoch(&self) -> u64 {
        *self.committees.keys().next_back().expect("epoch 0 committee always present")
    }

    /// The committee in effect for `round`: the committee of the highest
    /// installed epoch `<=` the round's epoch. Epoch 0 is always installed, so
    /// this always resolves.
    pub fn for_round(&self, round: Round) -> &ValidatorSet {
        let e = self.epoch_of(round);
        self.committees
            .range(..=e)
            .next_back()
            .map(|(_, set)| set)
            .expect("epoch 0 committee always present, so any round resolves")
    }

    /// The bootstrap (epoch-0) committee. Used by call sites that operate on the
    /// genesis set specifically (e.g. some tests). NOTE: once later epochs are
    /// installed this is *not* "the current committee" — use `for_round` with a
    /// specific round for that.
    pub fn base(&self) -> &ValidatorSet {
        self.committees.get(&0).expect("epoch 0 committee always present")
    }

    /// Number of installed committees (for tests / the resource-limits bound).
    pub fn installed_epoch_count(&self) -> usize {
        self.committees.len()
    }

    /// Drop the committees of epochs whose *entire round range* is below
    /// `floor_round` — the round-window bound on the otherwise-unbounded
    /// `committees` map (task #18). A rotating schedule installs one committee
    /// per epoch for the node's whole life; without this the map (and its
    /// on-disk `committee_log` mirror) grows forever.
    ///
    /// **Why it's safe.** `floor_round` is the DAG garbage-collection floor
    /// (`gc_floor`): certificates below it are pruned and never re-requested or
    /// re-verified (`request_missing_parents` skips parents below `gc_floor`,
    /// and `extend_order` never re-resolves pruned rounds), so `for_round(r)` is
    /// only ever queried for `r >= floor_round`. We keep the committee *in
    /// effect at* `floor_round` (the highest installed epoch `<=` its epoch, the
    /// "anchor") and every epoch above it, so every still-resolvable round
    /// inherits the exact same committee it did before the prune — `for_round`
    /// is unchanged on `[floor_round, ∞)`. Epoch 0 is always retained (the
    /// bootstrap invariant `for_round`/`base` rely on). A `single`
    /// (fixed-membership) schedule installs only epoch 0, so this is a no-op for
    /// a non-rotating network. Idempotent.
    /// Returns the **anchor epoch** — the lowest epoch still retained above
    /// epoch 0 (the committee in effect at `floor_round`). The node deletes
    /// on-disk `committee_log` entries for epochs in `(0, anchor)` to keep the
    /// disk mirror in exact lock-step with this in-memory prune.
    pub fn prune_epochs_below(&mut self, floor_round: Round) -> u64 {
        if self.epoch_rounds == 0 {
            return 0;
        }
        let floor_epoch = floor_round / self.epoch_rounds;
        // The committee in effect at `floor_epoch` (highest installed epoch <=
        // it). Everything strictly below the anchor — except epoch 0 — is no
        // longer inherited by any resolvable round and can be dropped.
        let anchor = self
            .committees
            .range(..=floor_epoch)
            .next_back()
            .map(|(&e, _)| e)
            .unwrap_or(0);
        self.committees.retain(|&e, _| e == 0 || e >= anchor);
        anchor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quorum::ValidatorInfo;
    use qchain_crypto::Keypair;

    fn set(stake: u64) -> ValidatorSet {
        let kp = Keypair::generate().unwrap();
        ValidatorSet::new(vec![ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake }])
    }

    #[test]
    fn single_returns_the_same_set_for_every_round() {
        let s = ValidatorSchedule::single(set(5));
        // Only epoch 0 installed: every round resolves to it, regardless of the
        // (irrelevant) epoch length. This is the stage-1 no-op invariant.
        assert_eq!(s.for_round(0).total_stake(), 5);
        assert_eq!(s.for_round(1_000_000).total_stake(), 5);
        assert_eq!(s.for_round(0).ids_sorted(), s.for_round(999).ids_sorted());
        assert_eq!(s.base().ids_sorted(), s.for_round(42).ids_sorted());
        assert!(s.has_epoch(0));
        assert!(!s.has_epoch(1));
    }

    #[test]
    fn for_round_selects_the_committee_of_the_rounds_epoch() {
        // epoch length 5: epoch 0 = rounds 0..4, epoch 1 = 5..9, epoch 2 = 10..14
        let a = set(10);
        let a_ids = a.ids_sorted();
        let mut s = ValidatorSchedule::new(5, a);
        let b = set(20);
        let b_ids = b.ids_sorted();
        s.install_epoch(2, b);

        // Epoch 0 and 1 (no entry for 1) inherit A.
        assert_eq!(s.for_round(0).ids_sorted(), a_ids);
        assert_eq!(s.for_round(4).ids_sorted(), a_ids);
        assert_eq!(s.for_round(5).ids_sorted(), a_ids, "epoch 1 has no entry, inherits epoch 0");
        assert_eq!(s.for_round(9).ids_sorted(), a_ids);
        // Epoch 2 onward = B (epoch 3 inherits epoch 2).
        assert_eq!(s.for_round(10).ids_sorted(), b_ids);
        assert_eq!(s.for_round(14).ids_sorted(), b_ids);
        assert_eq!(s.for_round(15).ids_sorted(), b_ids, "epoch 3 inherits epoch 2");
        assert_eq!(s.latest_installed_epoch(), 2);
    }

    #[test]
    fn install_epoch_one_changes_the_committee_at_the_first_boundary() {
        let a = set(10);
        let a_ids = a.ids_sorted();
        let mut s = ValidatorSchedule::new(5, a);
        let b = set(20);
        let b_ids = b.ids_sorted();
        s.install_epoch(1, b);
        // Epoch 0 = A, epoch 1+ = B.
        assert_eq!(s.for_round(4).ids_sorted(), a_ids);
        assert_eq!(s.for_round(5).ids_sorted(), b_ids);
        assert_ne!(a_ids, b_ids);
    }

    #[test]
    fn base_is_always_epoch_zero_even_after_installing_later_epochs() {
        let a = set(10);
        let a_ids = a.ids_sorted();
        let mut s = ValidatorSchedule::new(5, a);
        s.install_epoch(1, set(99));
        assert_eq!(s.base().ids_sorted(), a_ids, "base() stays the genesis committee");
    }

    #[test]
    fn prune_epochs_below_bounds_the_map_without_changing_resolvable_rounds() {
        // epoch length 5. Distinct committees at epochs 0,1,2,3,4.
        let (c0, c1, c2, c3, c4) = (set(10), set(20), set(30), set(40), set(50));
        let (i0, i1, i2, i3, i4) =
            (c0.ids_sorted(), c1.ids_sorted(), c2.ids_sorted(), c3.ids_sorted(), c4.ids_sorted());
        let mut s = ValidatorSchedule::new(5, c0);
        s.install_epoch(1, c1);
        s.install_epoch(2, c2);
        s.install_epoch(3, c3);
        s.install_epoch(4, c4);
        assert_eq!(s.installed_epoch_count(), 5);

        // gc_floor at round 16 → epoch 3. The anchor (committee in effect at
        // epoch 3) is epoch 3 itself. Epochs 1,2 are dropped; 0 kept (bootstrap),
        // 3,4 kept.
        let anchor = s.prune_epochs_below(16);
        assert_eq!(anchor, 3, "committee in effect at round 16 (epoch 3) is the anchor");
        assert_eq!(s.installed_epoch_count(), 3, "epochs 1 and 2 dropped; 0, 3, 4 kept");
        assert!(s.has_epoch(0) && s.has_epoch(3) && s.has_epoch(4));
        assert!(!s.has_epoch(1) && !s.has_epoch(2));

        // for_round is UNCHANGED for every still-resolvable round (>= gc_floor).
        assert_eq!(s.for_round(15).ids_sorted(), i3, "epoch 3 round still resolves to C3");
        assert_eq!(s.for_round(19).ids_sorted(), i3);
        assert_eq!(s.for_round(20).ids_sorted(), i4, "epoch 4 still C4");
        assert_eq!(s.for_round(999).ids_sorted(), i4, "epochs above 4 inherit C4");
        assert_eq!(s.base().ids_sorted(), i0, "bootstrap committee preserved");
        // The dropped epochs are unrelated to the retained ones (proves distinct).
        assert_ne!(i1, i3);
        assert_ne!(i2, i4);

        // Idempotent, and pruning below an inherited (no-entry) epoch keeps the
        // committee that epoch inherits: gc_floor at round 27 → epoch 5, which
        // has no entry and inherits epoch 4 (the anchor) → 4 is kept.
        s.prune_epochs_below(27);
        assert!(s.has_epoch(0) && s.has_epoch(4));
        assert_eq!(s.for_round(30).ids_sorted(), i4, "epoch 6 still inherits C4 after prune");

        // A single (fixed-membership) schedule is untouched by a prune.
        let mut single = ValidatorSchedule::single(set(7));
        single.prune_epochs_below(1_000_000);
        assert_eq!(single.installed_epoch_count(), 1);
        assert_eq!(single.for_round(999).total_stake(), 7);
    }
}
