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
//! **Stage 1 (this increment) is inert plumbing — zero behavior change.**
//! `single` builds a schedule whose one committee covers every round, so
//! `for_round` ignores its argument and returns that set unconditionally —
//! byte-identical to the pre-3.3 single-`ValidatorSet` consensus. The proof it
//! changed nothing is the deterministic simulation test (`qchain-simulation`)
//! passing 9/9 unchanged, plus every consensus unit test. What Stage 1 buys is
//! that `Bullshark`, `ConsensusState::advance`, and `can_advance_round` now all
//! take a `&ValidatorSchedule` and resolve membership *per round*, so the later
//! stages that make the set actually vary by epoch (derive it from the on-chain
//! validator registry at each epoch boundary, freeze it for the epoch, persist
//! historical sets) change only *how a schedule is built* — never how consensus
//! reads it. Doing the risky signature threading first, as a proven no-op, is
//! what keeps the subsequent behavior change small and reviewable.

use crate::quorum::ValidatorSet;
use qchain_core::Round;

/// Resolves the validator committee in effect for a given consensus round.
///
/// Stage 1 holds exactly one committee for all rounds (`single`). A later stage
/// replaces `base` with an ordered set of per-epoch committees and makes
/// `for_round` pick by epoch — that is the single function that changes; every
/// consensus call site already routes through it.
#[derive(Clone, Debug)]
pub struct ValidatorSchedule {
    base: ValidatorSet,
}

impl ValidatorSchedule {
    /// A schedule with a single committee for every round — the phase-1/2
    /// behavior. Stage 1 always uses this.
    pub fn single(set: ValidatorSet) -> Self {
        ValidatorSchedule { base: set }
    }

    /// The validator set in effect for `round`. **Stage 1: always the base set,
    /// independent of the round** (hence the argument is unused). This is the
    /// one function a later stage changes to select a per-epoch committee.
    pub fn for_round(&self, _round: Round) -> &ValidatorSet {
        &self.base
    }

    /// The base committee — for call sites that operate on "the current set"
    /// without a specific round in hand (status readouts, the proposal fast
    /// path). Identical to `for_round(_)` in stage 1; a later stage points this
    /// at the newest epoch's committee.
    pub fn base(&self) -> &ValidatorSet {
        &self.base
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
        // Stage-1 invariant: round is ignored; every round resolves to `base`.
        assert_eq!(s.for_round(0).total_stake(), 5);
        assert_eq!(s.for_round(1_000_000).total_stake(), 5);
        assert_eq!(s.for_round(0).ids_sorted(), s.for_round(999).ids_sorted());
        assert_eq!(s.base().ids_sorted(), s.for_round(42).ids_sorted());
    }
}
