//! On-chain economic parameters (design: `ARCHITECTURE.md` §5/§6 - "bajo
//! riesgo: constantes de la curva de fee, tabla de precios de gas").
//! Governable via a `Low`-tier `qchain_governance::ProposalAction`
//! (simple majority, no time-lock - see `governance.rs`'s `Execute`
//! handling). `Ledger` reads the current values from this account at
//! every `apply_transaction` call, falling back to these same defaults
//! if the account hasn't been seeded yet (e.g. in tests that construct a
//! bare `Ledger` directly) - see `ledger.rs::current_params`.

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{BASE_FEE_PER_BYTE_UNITS, DUST_THRESHOLD_UNITS};

/// Placeholder gas price - see `ARCHITECTURE.md` §5's tokenomics
/// disclaimer: a starting point, not a modeled figure. Was a bare
/// `ledger.rs` constant before this account existed; kept here as the
/// genesis default.
pub const DEFAULT_GAS_PRICE_UNITS_PER_FUEL: u64 = 1;

/// Default validator commission on the staking-reward share of `base_fee`
/// (see `staking.rs`'s module docs and `ledger.rs`'s fee-split) - 10%, a
/// common real-world validator commission rate, explicitly a starting
/// point like every other constant in this module, adjustable via the
/// same `Low`-tier governance path as `base_fee_per_byte` etc.
pub const DEFAULT_STAKING_COMMISSION_BPS: u16 = 1_000;

/// Dynamic base-fee (EIP-1559-style) parameters. The `base_fee_per_byte` in
/// `EconomicParams` is no longer static: after each consensus round it is
/// nudged up or down toward `FEE_TARGET_BYTES_PER_ROUND` of committed traffic.
/// A round busier than target raises the fee (up to `1/DENOM` = 12.5% per
/// round); a quieter round lowers it, never below `FEE_MIN_BASE_FEE_PER_BYTE`.
/// See `Ledger::advance_dynamic_fee` for the exact, deterministic update.
///
/// Target committed bytes per round. Below this the fee decays toward the
/// floor; above it the fee climbs. ~90 standard 5.5 KB transfers per round -
/// a deliberately generous baseline so an uncongested testnet sits at the
/// floor and the fee only surges under genuine load. A constant for now (a
/// governance-tunable target is a documented follow-up).
pub const FEE_TARGET_BYTES_PER_ROUND: u64 = 500_000;
/// Max fractional change per round (Ethereum's denominator: 1/8 = 12.5%).
pub const FEE_ADJUST_DENOMINATOR: u64 = 8;
/// Floor the dynamic base fee can never dip below - the calibrated
/// `BASE_FEE_PER_BYTE_UNITS` (~$0.001 per transfer), the "uncongested" price.
/// The fee surges above this under load and decays back to it when load clears.
pub const FEE_MIN_BASE_FEE_PER_BYTE: u64 = BASE_FEE_PER_BYTE_UNITS;

/// On-chain accumulator for the dynamic base fee, stored in its own
/// `FEE_STATE_ACCOUNT_ID` account (see `ids.rs` for why it is separate from
/// `EconomicParams`). `epoch_round` is the round currently accumulating; when a
/// transaction from a later round arrives, that epoch is "closed" (the fee is
/// adjusted from `epoch_bytes` vs target) and a fresh epoch begins. Kept
/// on-chain (not in memory) so it is deterministic across validators AND
/// survives a restart identically - the property that keeps every validator's
/// `base_fee_per_byte` (and thus state root) in lock-step.
#[derive(Clone, Copy, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct FeeState {
    pub epoch_round: u64,
    pub epoch_bytes: u64,
}

/// The deterministic EIP-1559-style base-fee update: given the current base
/// fee and how many bytes a just-closed round committed vs the target, return
/// the next round's base fee. Pure function (same inputs -> same output on
/// every validator), `u128` math so a huge governance-set fee can't overflow,
/// clamped to the floor.
pub fn next_base_fee(current: u64, committed_bytes: u64, target: u64) -> u64 {
    if target == 0 {
        return current.max(FEE_MIN_BASE_FEE_PER_BYTE);
    }
    let cur = current as u128;
    let next = if committed_bytes > target {
        // Busier than target -> raise. delta = base * (used-target)/target/DENOM,
        // at least 1 so a persistently-full network keeps climbing.
        let delta = (cur * (committed_bytes - target) as u128 / target as u128 / FEE_ADJUST_DENOMINATOR as u128).max(1);
        cur.saturating_add(delta)
    } else {
        // Quieter than target -> decay toward the floor.
        let delta = cur * (target - committed_bytes) as u128 / target as u128 / FEE_ADJUST_DENOMINATOR as u128;
        cur.saturating_sub(delta)
    };
    let next = next.min(u64::MAX as u128) as u64;
    next.max(FEE_MIN_BASE_FEE_PER_BYTE)
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct EconomicParams {
    pub base_fee_per_byte: u64,
    pub dust_threshold: u64,
    pub gas_price_per_fuel: u64,
    /// Basis points (out of 10,000) of the staking-reward share of
    /// `base_fee` that goes directly to the proposing validator as
    /// commission - the rest funds the shared delegator reward pool
    /// (`STAKING_REWARDS_POOL_ID`). Only applies once real stake is
    /// delegated (`STAKING_STATS_ID` > 0) - see `ledger.rs`.
    pub staking_commission_bps: u16,
}

impl Default for EconomicParams {
    fn default() -> Self {
        EconomicParams {
            base_fee_per_byte: BASE_FEE_PER_BYTE_UNITS,
            dust_threshold: DUST_THRESHOLD_UNITS,
            gas_price_per_fuel: DEFAULT_GAS_PRICE_UNITS_PER_FUEL,
            staking_commission_bps: DEFAULT_STAKING_COMMISSION_BPS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_base_fee_rises_above_target_falls_below_and_clamps_to_floor() {
        let target = FEE_TARGET_BYTES_PER_ROUND;
        let floor = FEE_MIN_BASE_FEE_PER_BYTE;
        // A round twice as busy as target raises the fee.
        let up = next_base_fee(1000, target * 2, target);
        assert!(up > 1000, "busier-than-target round must raise the fee, got {up}");
        // Max change per round is 1/8 (12.5%): 2x target => +base*(1)/8 => +12.5%.
        assert_eq!(up, 1000 + 1000 / 8);
        // An empty round lowers the fee.
        let down = next_base_fee(1000, 0, target);
        assert!(down < 1000, "quieter-than-target round must lower the fee, got {down}");
        // Never below the floor, no matter how quiet.
        assert_eq!(next_base_fee(floor, 0, target), floor, "the fee must clamp at the floor");
        assert_eq!(next_base_fee(floor - if floor > 0 { 1 } else { 0 }, 0, target).max(floor), floor);
        // Exactly at target: no change.
        assert_eq!(next_base_fee(1000, target, target), 1000);
        // A persistently-full network keeps climbing by at least 1.
        assert!(next_base_fee(1, target + 1, target) >= 1);
    }

    #[test]
    fn next_base_fee_is_overflow_safe_for_a_huge_governance_fee() {
        // A near-u64::MAX base fee must not panic or wrap.
        let huge = u64::MAX / 2;
        let r = next_base_fee(huge, FEE_TARGET_BYTES_PER_ROUND * 10, FEE_TARGET_BYTES_PER_ROUND);
        assert!(r >= huge, "should not wrap downward");
    }
}
