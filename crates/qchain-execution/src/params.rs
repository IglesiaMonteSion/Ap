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

/// EIP-1559 elasticity: the per-round inclusion LIMIT is this multiple of the
/// target (`FEE_TARGET_BYTES_PER_ROUND`). Below the limit everything ready is
/// included and the base fee just drifts toward target; once demand exceeds the
/// limit the highest-`priority_fee` transactions win inclusion and the rest wait
/// a round - which is what makes the priority fee actually buy queue-jumping
/// under congestion (before this, with no cap, every ready tx was included every
/// round, so the tip only affected order, never inclusion). 2 = Ethereum's
/// gas-limit/gas-target ratio.
pub const FEE_ELASTICITY_MULTIPLIER: u64 = 2;
/// Hard cap on the bytes a validator packs into ONE round's own proposal
/// (target x elasticity ~= 1 MB ~= 180 standard transfers). This is a LOCAL
/// block-building policy, NOT a consensus rule: each validator caps its own
/// proposal independently off its own mempool view, so it can never fork state
/// (execution applies exactly what the committed batches contain, and the
/// dynamic base fee reads the real committed bytes either way). Honest limit:
/// it bounds one validator's proposal, so in a multi-proposer round the total
/// committed can still scale with the validator count - a finer global per-round
/// cap is a deeper fee-market design left as a follow-up.
pub const FEE_MAX_BYTES_PER_ROUND: u64 = FEE_TARGET_BYTES_PER_ROUND * FEE_ELASTICITY_MULTIPLIER;

/// On-chain accumulator for the dynamic base fee, stored in its own
/// `FEE_STATE_ACCOUNT_ID` account (see `ids.rs` for why it is separate from
/// `EconomicParams`). `epoch_round` is the round currently accumulating; when a
/// transaction from a later round arrives, that epoch is "closed" (the fee is
/// adjusted from `epoch_bytes` vs target) and a fresh epoch begins. Kept
/// on-chain (not in memory) so it is deterministic across validators AND
/// survives a restart identically - the property that keeps every validator's
/// `base_fee_per_byte` (and thus state root) in lock-step.
/// Default target annual staking yield (APR) funded by QCH emission, in basis
/// points - 12% (`ARCHITECTURE.md` §5's stated staking-reward goal). Unlike the
/// original fee-only reward model (which could not guarantee any particular
/// yield), emission mints new QCH each round straight into the delegator reward
/// pool so the yield is a real, governable target. A starting point like every
/// other constant here; adjustable via the same `Low`-tier governance path.
pub const DEFAULT_EMISSION_APR_BPS: u16 = 1_200;
/// Hard cap on the governance-settable emission APR (50%). Prevents a passed
/// proposal from setting a hyperinflationary rate; generous headroom over the
/// 12% default for any legitimate recalibration.
pub const MAX_EMISSION_APR_BPS: u16 = 5_000;
/// Rounds per year at the reference ~500 ms round interval (2 rounds/s × 3600 ×
/// 24 × 365). The emission APR is nominal at this reference rate; a network run
/// at a different `round_interval_ms` emits proportionally faster/slower per
/// wall-clock year, and governance can retune the APR to compensate (there is
/// no trusted wall-clock on-chain - rounds are the only deterministic clock).
pub const ROUNDS_PER_YEAR: u64 = 63_072_000;
/// Fixed-point scale for the emission carry (matches `staking::PRECISION`), so
/// the sub-unit emission of a single round accumulates exactly instead of
/// truncating to zero (a real risk: one round's emission on a modest stake is a
/// tiny fraction of one unit).
pub const EMISSION_PRECISION: u128 = 1_000_000_000_000;

/// Pure, deterministic emission for `rounds` elapsed rounds: mints
/// `total_staked × apr_bps / 10_000` per year, spread per round, carrying the
/// fractional remainder forward. Returns `(whole_units_to_mint, new_carry)`.
/// `saturating_mul` so an absurd `total_staked`/`rounds` can never overflow or
/// panic (it caps, under-minting in the impossible extreme - safe). Every
/// validator computes the identical `(whole, carry)` from the identical
/// committed `(total_staked, apr_bps, rounds, carry)`, which is what keeps
/// emission fork-free.
pub fn emission_for_rounds(total_staked: u64, apr_bps: u16, rounds: u64, carry: u128) -> (u64, u128) {
    let emission_fp = (total_staked as u128)
        .saturating_mul(apr_bps as u128)
        .saturating_mul(rounds as u128)
        .saturating_mul(EMISSION_PRECISION)
        / (10_000u128 * ROUNDS_PER_YEAR as u128);
    let total_fp = carry.saturating_add(emission_fp);
    let whole = (total_fp / EMISSION_PRECISION).min(u64::MAX as u128) as u64;
    let new_carry = total_fp - (whole as u128) * EMISSION_PRECISION;
    (whole, new_carry)
}

/// On-chain accumulator for the dynamic base fee AND the emission carry, stored
/// in `FEE_STATE_ACCOUNT_ID`. `epoch_round`/`epoch_bytes` drive the EIP-1559
/// base-fee update (see `next_base_fee`); `emission_carry` accumulates the
/// sub-unit QCH emission across rounds. Kept on-chain (not in memory) so it is
/// deterministic across validators and survives a restart identically - the
/// property that keeps every validator's `base_fee`/pool balance/state root in
/// lock-step. `emission_carry` was added in v4.0.0; `FeeState::read_or_legacy`
/// migrates a pre-v4 two-field record by defaulting the carry to 0.
#[derive(Clone, Copy, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct FeeState {
    pub epoch_round: u64,
    pub epoch_bytes: u64,
    pub emission_carry: u128,
}

impl FeeState {
    /// Decode a `FeeState`, migrating a legacy pre-v4 record (the two-field
    /// `epoch_round`/`epoch_bytes` layout, no `emission_carry`) by defaulting
    /// the carry to 0 - so a network that upgrades to v4.0.0 WITHOUT a fresh
    /// genesis keeps its live fee-epoch state and simply starts accumulating
    /// emission from a zero carry.
    pub fn read_or_legacy(data: &[u8]) -> Option<Self> {
        if let Ok(fs) = Self::try_from_slice(data) {
            return Some(fs);
        }
        // Legacy: exactly two u64s, nothing after.
        if data.len() == 16 {
            let epoch_round = u64::from_le_bytes(data[0..8].try_into().ok()?);
            let epoch_bytes = u64::from_le_bytes(data[8..16].try_into().ok()?);
            return Some(FeeState { epoch_round, epoch_bytes, emission_carry: 0 });
        }
        None
    }
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
    /// Target annual staking yield (APR) funded by QCH emission, in basis
    /// points (v4.0.0). Each round, `total_staked × emission_apr_bps / 10_000`
    /// of new QCH per year is minted straight into the delegator reward pool -
    /// see `emission_for_rounds` and `Ledger::advance_dynamic_fee`. `0` disables
    /// emission entirely (fee-only rewards, the pre-v4 behavior). Governable
    /// (`Low` tier), bounded to `MAX_EMISSION_APR_BPS`. Added after
    /// `staking_commission_bps`, so a pre-v4 `EconomicParams` record migrates
    /// via `read_or_legacy` (defaulting this field) rather than needing a fresh
    /// genesis.
    pub emission_apr_bps: u16,
}

impl Default for EconomicParams {
    fn default() -> Self {
        EconomicParams {
            base_fee_per_byte: BASE_FEE_PER_BYTE_UNITS,
            dust_threshold: DUST_THRESHOLD_UNITS,
            gas_price_per_fuel: DEFAULT_GAS_PRICE_UNITS_PER_FUEL,
            staking_commission_bps: DEFAULT_STAKING_COMMISSION_BPS,
            emission_apr_bps: DEFAULT_EMISSION_APR_BPS,
        }
    }
}

impl EconomicParams {
    /// Decode `EconomicParams`, migrating a legacy pre-v4 record (the four-field
    /// layout without `emission_apr_bps`) by defaulting the emission APR to
    /// `DEFAULT_EMISSION_APR_BPS`. This is what lets a live network upgrade to
    /// v4.0.0 WITHOUT a fresh genesis: its governance-set `base_fee`/`dust`/etc.
    /// survive, and emission simply switches on at the default APR (which the
    /// next write persists in the new five-field format).
    pub fn read_or_legacy(data: &[u8]) -> Option<Self> {
        if let Ok(p) = Self::try_from_slice(data) {
            return Some(p);
        }
        // Legacy: three u64s + one u16 = 26 bytes, nothing after.
        if data.len() == 26 {
            let base_fee_per_byte = u64::from_le_bytes(data[0..8].try_into().ok()?);
            let dust_threshold = u64::from_le_bytes(data[8..16].try_into().ok()?);
            let gas_price_per_fuel = u64::from_le_bytes(data[16..24].try_into().ok()?);
            let staking_commission_bps = u16::from_le_bytes(data[24..26].try_into().ok()?);
            return Some(EconomicParams {
                base_fee_per_byte,
                dust_threshold,
                gas_price_per_fuel,
                staking_commission_bps,
                emission_apr_bps: DEFAULT_EMISSION_APR_BPS,
            });
        }
        None
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

    #[test]
    fn emission_over_a_full_year_matches_the_apr_exactly() {
        // At APR = 100% (10,000 bps) over exactly one year the emission equals
        // the whole staked amount; at the 12% default it is 12% of it.
        let staked = 10_000_000_000u64;
        let (full, carry) = emission_for_rounds(staked, 10_000, ROUNDS_PER_YEAR, 0);
        assert_eq!(full, staked);
        assert_eq!(carry, 0);
        let (twelve, _) = emission_for_rounds(staked, DEFAULT_EMISSION_APR_BPS, ROUNDS_PER_YEAR, 0);
        assert_eq!(twelve, staked * 12 / 100);
    }

    #[test]
    fn emission_carries_sub_unit_remainders_across_rounds() {
        // Pick a stake where one round mints exactly half a unit: total_staked =
        // ROUNDS_PER_YEAR/2 at 100% APR => annual = ROUNDS_PER_YEAR/2, per round
        // = 0.5. Two rounds accumulate to one whole unit, nothing lost.
        let staked = ROUNDS_PER_YEAR / 2; // 31_536_000
        let (w0, carry0) = emission_for_rounds(staked, 10_000, 1, 0);
        assert_eq!(w0, 0, "half a unit rounds down to zero whole units");
        assert_eq!(carry0, EMISSION_PRECISION / 2, "the other half is carried");
        let (w1, carry1) = emission_for_rounds(staked, 10_000, 1, carry0);
        assert_eq!(w1, 1, "two halves make one whole unit - no emission lost to rounding");
        assert_eq!(carry1, 0);
    }

    #[test]
    fn emission_is_off_when_apr_or_stake_is_zero_and_is_overflow_safe() {
        assert_eq!(emission_for_rounds(1_000_000, 0, ROUNDS_PER_YEAR, 0), (0, 0));
        assert_eq!(emission_for_rounds(0, 1_200, ROUNDS_PER_YEAR, 0), (0, 0));
        // Extreme inputs must not panic/wrap (saturating math throughout).
        let (w, _) = emission_for_rounds(u64::MAX, MAX_EMISSION_APR_BPS, ROUNDS_PER_YEAR, 0);
        assert!(w > 0);
    }

    #[test]
    fn fee_state_read_or_legacy_round_trips_and_migrates() {
        // A v4 record round-trips exactly.
        let fs = FeeState { epoch_round: 42, epoch_bytes: 999, emission_carry: 12345 };
        let bytes = borsh::to_vec(&fs).unwrap();
        assert_eq!(FeeState::read_or_legacy(&bytes), Some(fs));
        // A legacy two-u64 record migrates with carry 0.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&42u64.to_le_bytes());
        legacy.extend_from_slice(&999u64.to_le_bytes());
        assert_eq!(
            FeeState::read_or_legacy(&legacy),
            Some(FeeState { epoch_round: 42, epoch_bytes: 999, emission_carry: 0 })
        );
    }

    #[test]
    fn economic_params_read_or_legacy_round_trips_and_migrates() {
        // A v4 record round-trips exactly.
        let p = EconomicParams { base_fee_per_byte: 200, dust_threshold: 1_000_000, gas_price_per_fuel: 1, staking_commission_bps: 1_000, emission_apr_bps: 800 };
        let bytes = borsh::to_vec(&p).unwrap();
        assert_eq!(EconomicParams::read_or_legacy(&bytes), Some(p));
        // A legacy four-field record migrates with the default emission APR,
        // keeping every governance-set value intact.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&200u64.to_le_bytes());
        legacy.extend_from_slice(&1_000_000u64.to_le_bytes());
        legacy.extend_from_slice(&1u64.to_le_bytes());
        legacy.extend_from_slice(&1_000u16.to_le_bytes());
        assert_eq!(legacy.len(), 26);
        let migrated = EconomicParams::read_or_legacy(&legacy).unwrap();
        assert_eq!(migrated.base_fee_per_byte, 200);
        assert_eq!(migrated.staking_commission_bps, 1_000);
        assert_eq!(migrated.emission_apr_bps, DEFAULT_EMISSION_APR_BPS);
    }
}
