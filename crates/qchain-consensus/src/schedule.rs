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
}
