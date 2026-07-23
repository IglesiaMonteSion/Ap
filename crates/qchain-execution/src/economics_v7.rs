//! v7 economic primitives — the pure, deterministic math the new tokenomics
//! rests on (SPEC: `docs/ECONOMIC-REDESIGN.md`). This module is the **Fase 1a
//! foundation**: constants + the staking-index arithmetic + the moniker rules.
//! It is purely additive and INERT — nothing wires it into `Ledger`/consensus
//! yet, so a v6 node is byte-identical. The shares/index staking model, the six
//! separated pools, fee split, and quanto close land in the following sub-phases
//! on top of this.
//!
//! ## The staking model in one paragraph (why shares + a global index)
//! A staker's position is stored as **shares**, not a nominal QCH amount. A
//! single global `staking_index` grows every quanto; a position's live value is
//! `shares × index / INDEX_SCALE`. The index growing IS the compounding of ALL
//! positions at once — so the per-quanto close is O(1) (advance one number, mint
//! the delta into the reserve), never O(number of stakers). No per-position
//! `reward_debt`, no claim required: the value is always `shares × index`.
//!
//! ## Arithmetic decision (MEASURED — resolves the flagged open item)
//! `INDEX_SCALE = 1e12` (the same scale the project already uses for
//! `staking::PRECISION`/`EMISSION_PRECISION`). With it, the widest intermediate
//! product `shares × index` stays under ~1e35 even in an extreme scenario
//! (~1e18 atoms staked — 100× the genesis supply — compounded for 100 years, so
//! `index ≈ 8.3e16`), well within `u128::MAX ≈ 3.4e38`. **No `u256` dependency is
//! needed** — verified by `no_overflow_at_extreme_bounds` below. A larger scale
//! (e.g. 1e27) would force 256-bit math for no precision benefit at this supply,
//! so we deliberately don't.

use qchain_core::UNITS_PER_QCH;

// ---------------------------------------------------------------------------
// Core scales
// ---------------------------------------------------------------------------

/// Fixed-point scale of the global staking index and of share↔value conversion.
/// See the module-level "Arithmetic decision" note for why 1e12 (and why not
/// wider). A position's value = `shares × index / INDEX_SCALE`.
pub const INDEX_SCALE: u128 = 1_000_000_000_000;

/// The staking index at genesis: exactly `INDEX_SCALE`, so 1 share = 1 unit when
/// the chain starts (a genesis deposit of N atoms mints N shares).
pub const INITIAL_STAKING_INDEX: u128 = INDEX_SCALE;

/// Fixed-point scale of the per-quanto compounding rate (`rate_fp`). Wider than
/// `INDEX_SCALE` purely to represent the small per-quanto fraction
/// (~3.1e-4 at 12%/365) with ample precision; the products stay in `u128`.
pub const QUANTO_RATE_SCALE: u128 = 1_000_000_000_000_000_000; // 1e18

// ---------------------------------------------------------------------------
// Staking yield (APY, not APR — compounds via the index)
// ---------------------------------------------------------------------------

/// Target maximum staking yield, in basis points: **1200 = 12% APY**. It is APY,
/// not APR, because the index compounds it automatically. The real yield is
/// always ≤ this (every rounding goes DOWN — see `derive_quanto_rate_fp`).
pub const STAKING_TARGET_APY_BPS: u16 = 1_200;

/// Default number of reward quantos per protocol year (≈ 1 quanto/day). This is
/// a GENESIS parameter (part of the config hash); changing it requires
/// recomputing `rate_fp` and is a consensus change. Small in tests.
pub const DEFAULT_QUANTOS_PER_YEAR: u64 = 365;

/// Default rounds per quanto at the reference ~500 ms round interval: one day =
/// 86_400 s / 0.5 s ≈ 172_800 rounds. GENESIS parameter (config hash); tests use
/// a tiny value to cross a quanto boundary fast. The 12% is defined over the
/// PROTOCOL calendar (`ROUNDS_PER_QUANTO × QUANTOS_PER_YEAR` rounds = one
/// "year"); if the network produces rounds slower than configured, the
/// wall-clock yield is LOWER than 12%, never higher.
pub const DEFAULT_ROUNDS_PER_QUANTO: u64 = 172_800;

/// Derive the per-quanto compounding rate as a `QUANTO_RATE_SCALE`-scaled integer
/// so that compounding it for `quantos_per_year` steps yields **≤** the target
/// APY (never more). Rounds DOWN, then integer-verifies the ≤APY property against
/// the real `advance_staking_index` and decrements if a floating-point last-ulp
/// made it a hair too high.
///
/// **OFF-CHAIN / genesis-build ONLY.** It uses `f64` (`powf`), which is NOT
/// guaranteed bit-identical across platforms — running it on-chain could fork.
/// The chain never calls this: the resulting integer is baked into the genesis
/// config, and every node runs only the fully-integer `advance_staking_index`.
pub fn derive_quanto_rate_fp(apy_bps: u16, quantos_per_year: u64) -> u128 {
    if apy_bps == 0 || quantos_per_year == 0 {
        return 0;
    }
    let apy = apy_bps as f64 / 10_000.0;
    let per = (1.0 + apy).powf(1.0 / quantos_per_year as f64) - 1.0;
    let mut fp = (per * QUANTO_RATE_SCALE as f64).floor().max(0.0) as u128;
    // Integer verification against the REAL advance: from index 1.0 (== base),
    // compounding for a full year must land at or below base × (1 + apy).
    let base: u128 = INDEX_SCALE;
    let cap = base.saturating_mul(10_000u128 + apy_bps as u128) / 10_000; // base × (1+apy), exact
    while fp > 0 {
        let mut idx = base;
        for _ in 0..quantos_per_year {
            idx = advance_staking_index(idx, fp);
        }
        if idx <= cap {
            break;
        }
        fp -= 1;
    }
    fp
}

/// One quanto of compounding: `index += floor(index × rate_fp / QUANTO_RATE_SCALE)`.
/// Pure, integer, deterministic (this is the ONLY index-advance the chain runs).
/// Saturating so an absurd index/rate can never panic under `overflow-checks`.
pub fn advance_staking_index(index: u128, rate_fp: u128) -> u128 {
    let delta = index.saturating_mul(rate_fp) / QUANTO_RATE_SCALE;
    index.saturating_add(delta)
}

/// Live value (in atoms) of a position holding `shares` at the current `index`.
pub fn position_value(shares: u128, index: u128) -> u128 {
    shares.saturating_mul(index) / INDEX_SCALE
}

/// Shares minted for a deposit of `amount` atoms at the current `index`. Rounds
/// DOWN so a deposit never mints shares worth more than it put in.
pub fn shares_for_deposit(amount: u64, index: u128) -> u128 {
    if index == 0 {
        return 0;
    }
    (amount as u128).saturating_mul(INDEX_SCALE) / index
}

/// QCH to mint into the staking reserve when the index moves `old_index →
/// new_index` for `total_shares` outstanding: EXACTLY the increase in total
/// FLOORED position value, `position_value(total, new) − position_value(total,
/// old)`. Using the floored value-delta (not `total × Δindex / SCALE`, which can
/// differ by 1 from it) is what keeps `reserve.balance == total position value`
/// an EXACT invariant after minting — the property the quanto close and the DST
/// depend on. Economically identical (it is the value auto-compounding adds).
pub fn emission_for_quanto(total_shares: u128, old_index: u128, new_index: u128) -> u128 {
    position_value(total_shares, new_index).saturating_sub(position_value(total_shares, old_index))
}

// ---------------------------------------------------------------------------
// Hard-cap supply (SPEC §5 — the "definitive supply" decision, task #221)
// ---------------------------------------------------------------------------

/// The canonical maximum total supply of QCH: **100 million**, in whole QCH.
/// This is the HARD-CAP model the project publishes: total supply is guaranteed
/// NEVER to exceed this, because under `hard_cap_supply` staking emission is
/// DRAWN from a pre-minted reserve (a transfer) instead of minted — so nothing is
/// created after genesis and `Σ balances` is constant at the genesis total, which
/// the genesis gate forces to be ≤ this cap. A network may bake a different cap;
/// this is the default and the value the tokenomics advertises.
pub const MAX_SUPPLY_QCH: u64 = 100_000_000;

/// The canonical maximum total supply in atoms (100M × 1e9 = 1e17). Stays far
/// below `u64::MAX` (~1.8e19), so a genesis supply at the cap fits a single u64.
pub const MAX_SUPPLY_ATOMS: u128 = MAX_SUPPLY_QCH as u128 * UNITS_PER_QCH as u128;

/// Hard-cap emission: given the target index (the full compounding rate) and a
/// finite `budget` of atoms available in the emission reserve, return
/// `(new_index, emission)` such that:
/// - `emission == emission_for_quanto(total_shares, old_index, new_index) ≤ budget`
///   (never draws more than the reserve holds),
/// - `new_index ≤ target_new_index` (never overshoots the target yield),
/// - if the desired emission fits the budget it is used exactly (fully backed at
///   the target rate),
/// - otherwise the index advances only by the largest floor-safe step the budget
///   backs, so the effective yield throttles smoothly down toward "fees only" as
///   the reserve depletes (budget 0 → no advance, no emission).
///
/// Crediting `STAKING_RESERVE` by exactly `emission` while advancing the index by
/// the corresponding amount keeps `reserve ≥ total position value` (the 1b
/// invariant) with **NO mint** — the emission is a transfer OUT of the emission
/// reserve. Deterministic integer math; no f64, no overflow (products stay far
/// below `u128::MAX` at any real supply — see `no_overflow_at_extreme_bounds`).
pub fn index_for_backed_emission(total_shares: u128, old_index: u128, target_new_index: u128, budget: u128) -> (u128, u128) {
    if total_shares == 0 {
        // No positions → advancing the index is harmless and mints nothing; match
        // the mint path (which advances to target with 0 emission).
        return (target_new_index, 0);
    }
    let desired = emission_for_quanto(total_shares, old_index, target_new_index);
    if desired <= budget {
        return (target_new_index, desired);
    }
    // Budget-bound. The largest index step whose value-delta is provably ≤ budget:
    // `total_shares · delta / SCALE ≤ budget` ⟺ `delta = floor(budget · SCALE / total_shares)`.
    // Then `emission = floor(total_shares·(old+delta)/SCALE) − floor(total_shares·old/SCALE)`
    //   `< budget + 1` (floor(a+b) − floor(a) < ⌈b⌉ ≤ b+1) ⟹ ≤ budget (integer).
    let delta = budget.saturating_mul(INDEX_SCALE) / total_shares;
    let new_index = old_index.saturating_add(delta);
    let emission = emission_for_quanto(total_shares, old_index, new_index);
    (new_index, emission)
}

// ---------------------------------------------------------------------------
// Validator bond
// ---------------------------------------------------------------------------

/// The validator bond: EXACTLY 500 QCH, in atoms. Pure collateral — locked in an
/// escrow, converts to no shares, earns no emission/yield, slashable on proven
/// equivocation, recovered after a valid exit + unbonding. Every active
/// validator posts the same bond → one equal unit of consensus power each.
pub const VALIDATOR_BOND_ATOMS: u64 = 500 * UNITS_PER_QCH;

// ---------------------------------------------------------------------------
// Unbonding / eligibility windows (GENESIS parameters — config hash)
// ---------------------------------------------------------------------------

/// Quantos a common staking position stays in `Unbonding` before it is
/// `Withdrawable`. Independent of the validator bond unbonding.
pub const STAKING_UNBONDING_QUANTOS: u64 = 1;
/// Quantos a validator bond stays in `Unbonding` after a valid exit before it
/// can be withdrawn (and during which it remains slashable — see the evidence
/// window).
pub const VALIDATOR_BOND_UNBONDING_QUANTOS: u64 = 1;
/// Max window to submit equivocation evidence against an exiting validator; must
/// be ≤ how long the bond stays slashable, so a departing equivocator cannot
/// outrun a report.
pub const SLASH_EVIDENCE_WINDOW_QUANTOS: u64 = 1;
/// Minimum participation (basis points) a validator must hit in a quanto to be
/// eligible for that quanto's fee share — 9000 = 90%. The exact metric ("what
/// counts as participation") is fixed in the node phase; this is the threshold.
pub const VALIDATOR_MIN_PARTICIPATION_BPS: u16 = 9_000;

// ---------------------------------------------------------------------------
// Moniker rules (deterministic across implementations)
// ---------------------------------------------------------------------------

pub const MIN_MONIKER_LEN: usize = 3;
pub const MAX_MONIKER_LEN: usize = 32;

/// Reserved monikers nobody may register (impersonation / confusion guards).
pub const RESERVED_MONIKERS: &[&str] = &["qchain", "genesis", "validator", "system", "faucet", "admin", "root", "staking", "governance"];

/// Normalize a moniker for storage/comparison: lowercase (comparison is
/// case-insensitive) and trim surrounding whitespace. The normalized form is the
/// unique consensus identifier; a fancy Unicode display name, if ever wanted,
/// would be a separate informational field.
pub fn normalize_moniker(m: &str) -> String {
    m.trim().to_ascii_lowercase()
}

/// Validate a moniker (apply `normalize_moniker` first): 3–32 chars,
/// `[a-z0-9_-]` only, not reserved. Returns true iff acceptable.
pub fn moniker_is_valid(normalized: &str) -> bool {
    let len = normalized.chars().count();
    if !(MIN_MONIKER_LEN..=MAX_MONIKER_LEN).contains(&len) {
        return false;
    }
    if !normalized
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return false;
    }
    if RESERVED_MONIKERS.contains(&normalized) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staking_index_never_exceeds_12_percent_apy_over_a_year() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        assert!(fp > 0, "rate must be positive for a 12% APY");
        // Compound the REAL on-chain advance for one protocol year from index 1.0.
        let mut idx = INDEX_SCALE;
        for _ in 0..DEFAULT_QUANTOS_PER_YEAR {
            idx = advance_staking_index(idx, fp);
        }
        // Must be ≤ 1.12 × (never more), and close to it (not leaving much on the
        // table — within 0.1% below the cap).
        let cap = INDEX_SCALE * 11_200 / 10_000; // 1.12
        let floor_ok = INDEX_SCALE * 11_190 / 10_000; // 1.1190
        assert!(idx <= cap, "yield exceeded 12% APY: index={idx} cap={cap}");
        assert!(idx >= floor_ok, "yield suspiciously low: index={idx} want≥{floor_ok}");
    }

    #[test]
    fn a_two_year_hold_compounds_not_simple() {
        // 12% compounded two years = 1.12^2 = 1.2544 (> 1.24 simple). Confirms the
        // index genuinely compounds.
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut idx = INDEX_SCALE;
        for _ in 0..(DEFAULT_QUANTOS_PER_YEAR * 2) {
            idx = advance_staking_index(idx, fp);
        }
        let two_year = INDEX_SCALE * 12_544 / 10_000; // 1.2544
        let simple = INDEX_SCALE * 12_400 / 10_000; // 1.24
        assert!(idx <= two_year, "compounded two-year cap");
        assert!(idx > simple, "must exceed simple interest (compounding works)");
    }

    #[test]
    fn shares_deposit_and_value_round_trip_at_genesis_and_after_growth() {
        // At genesis (index == INITIAL), a deposit of N mints N shares worth N.
        let dep = 5_000_000_000u64; // 5 QCH
        let sh = shares_for_deposit(dep, INITIAL_STAKING_INDEX);
        assert_eq!(sh, dep as u128);
        assert_eq!(position_value(sh, INITIAL_STAKING_INDEX), dep as u128);
        // After a year of growth the SAME shares are worth ~12% more; a NEW deposit
        // of the same size mints FEWER shares (each share now costs more).
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut idx = INITIAL_STAKING_INDEX;
        for _ in 0..DEFAULT_QUANTOS_PER_YEAR {
            idx = advance_staking_index(idx, fp);
        }
        let grown_value = position_value(sh, idx);
        assert!(grown_value > dep as u128 && grown_value <= dep as u128 * 1_12 / 100 + 1);
        let sh2 = shares_for_deposit(dep, idx);
        assert!(sh2 < sh, "a later deposit mints fewer shares as the index grows");
        // The new deposit is still worth ~what was put in.
        assert!(position_value(sh2, idx) <= dep as u128 && position_value(sh2, idx) >= dep as u128 - 1);
    }

    #[test]
    fn emission_for_quanto_equals_the_growth_in_total_value() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let total_shares = 10_000_000u128 * UNITS_PER_QCH as u128; // 10M QCH staked
        let old = INITIAL_STAKING_INDEX;
        let new = advance_staking_index(old, fp);
        let minted = emission_for_quanto(total_shares, old, new);
        // Equals the delta in total position value (auto-compounding everyone).
        let delta = position_value(total_shares, new) - position_value(total_shares, old);
        assert_eq!(minted, delta);
        assert!(minted > 0, "a quanto with real stake mints real emission");
    }

    #[test]
    fn no_overflow_at_extreme_bounds() {
        // The arithmetic-decision guard: ~1e18 atoms staked (100× genesis supply)
        // compounded for 100 years, then value/shares math must not wrap/panic.
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut idx = INITIAL_STAKING_INDEX;
        for _ in 0..(DEFAULT_QUANTOS_PER_YEAR * 100) {
            idx = advance_staking_index(idx, fp);
        }
        // index after 100y ≈ 1e12 × 1.12^100 ≈ 8.3e16 — still tiny for u128.
        assert!(idx < INDEX_SCALE * 100_000, "100y index stays bounded");
        let shares: u128 = 1_000_000_000_000_000_000; // 1e18 atoms of shares
        // shares × index ≈ 1e18 × 8.3e16 = 8.3e34 < u128::MAX (3.4e38): no wrap.
        let v = position_value(shares, idx);
        assert!(v > shares, "value grew");
        // And the saturating guards mean even the impossible extreme can't panic.
        let _ = position_value(u128::MAX, idx);
        let _ = advance_staking_index(u128::MAX, fp);
    }

    #[test]
    fn backed_emission_matches_the_full_rate_when_the_reserve_can_cover_it() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let total_shares = 10_000_000u128 * UNITS_PER_QCH as u128; // 10M QCH staked
        let old = INITIAL_STAKING_INDEX;
        let target = advance_staking_index(old, fp);
        let desired = emission_for_quanto(total_shares, old, target);
        // A budget larger than the desired emission → identical to the mint path:
        // full-rate index + exactly `desired` drawn.
        let (new_index, emission) = index_for_backed_emission(total_shares, old, target, desired + 1_000_000);
        assert_eq!(new_index, target, "fully-funded quanto advances to the full-rate index");
        assert_eq!(emission, desired, "fully-funded quanto emits exactly the target amount");
    }

    #[test]
    fn backed_emission_never_exceeds_the_budget_and_throttles_the_index() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let total_shares = 10_000_000u128 * UNITS_PER_QCH as u128;
        let old = INITIAL_STAKING_INDEX;
        let target = advance_staking_index(old, fp);
        let desired = emission_for_quanto(total_shares, old, target);
        // A budget SMALLER than desired → emission clamped to ≤ budget, index below
        // the full-rate target (yield throttled), and the reserve invariant still
        // holds (emission == the exact value-delta of the chosen index step).
        let budget = desired / 3;
        let (new_index, emission) = index_for_backed_emission(total_shares, old, target, budget);
        assert!(emission <= budget, "never draws more than the reserve holds: {emission} > {budget}");
        assert!(new_index <= target, "throttled index never overshoots the target");
        assert!(new_index >= old, "index never goes backwards");
        assert_eq!(emission, emission_for_quanto(total_shares, old, new_index), "emission is the exact value-delta of the chosen index (reserve invariant)");
        // And it uses as much of the budget as floor-arithmetic allows (tight).
        assert!(emission + 1 >= budget || budget == 0, "throttle is tight to the budget");
    }

    #[test]
    fn a_depleted_reserve_stops_yield_without_advancing_the_index() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let total_shares = 5_000_000u128 * UNITS_PER_QCH as u128;
        let old = INITIAL_STAKING_INDEX;
        let target = advance_staking_index(old, fp);
        // Budget 0 (reserve empty) → no advance, no emission = "fees only".
        let (new_index, emission) = index_for_backed_emission(total_shares, old, target, 0);
        assert_eq!(new_index, old, "empty reserve → index frozen");
        assert_eq!(emission, 0, "empty reserve → no emission");
    }

    #[test]
    fn backed_emission_with_no_shares_advances_and_emits_nothing() {
        let fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let old = INITIAL_STAKING_INDEX;
        let target = advance_staking_index(old, fp);
        // No positions → matches the mint path: advance to target, emit 0 (and never
        // divides by zero).
        let (new_index, emission) = index_for_backed_emission(0, old, target, 1_000_000);
        assert_eq!(new_index, target);
        assert_eq!(emission, 0);
    }

    #[test]
    fn max_supply_is_100_million_qch() {
        assert_eq!(MAX_SUPPLY_QCH, 100_000_000);
        assert_eq!(MAX_SUPPLY_ATOMS, 100_000_000u128 * UNITS_PER_QCH as u128);
        assert_eq!(MAX_SUPPLY_ATOMS, 100_000_000_000_000_000); // 1e17
    }

    #[test]
    fn emission_off_at_zero_apy() {
        assert_eq!(derive_quanto_rate_fp(0, DEFAULT_QUANTOS_PER_YEAR), 0);
        assert_eq!(advance_staking_index(INDEX_SCALE, 0), INDEX_SCALE, "no rate → no growth");
        assert_eq!(emission_for_quanto(1_000_000, INDEX_SCALE, INDEX_SCALE), 0);
    }

    #[test]
    fn validator_bond_is_exactly_500_qch() {
        assert_eq!(VALIDATOR_BOND_ATOMS, 500 * UNITS_PER_QCH);
        assert_eq!(VALIDATOR_BOND_ATOMS, 500_000_000_000);
    }

    #[test]
    fn moniker_rules() {
        assert!(moniker_is_valid(&normalize_moniker("Alice_01")));
        assert!(moniker_is_valid(&normalize_moniker("  node-1  "))); // trimmed
        assert!(!moniker_is_valid(&normalize_moniker("ab"))); // too short
        assert!(!moniker_is_valid(&normalize_moniker(&"x".repeat(33)))); // too long
        assert!(!moniker_is_valid(&normalize_moniker("has space"))); // space
        assert!(!moniker_is_valid(&normalize_moniker("emoji😀nod"))); // non-ascii
        assert!(!moniker_is_valid(&normalize_moniker("Genesis"))); // reserved (case-insensitive)
        assert!(!moniker_is_valid(&normalize_moniker("validator"))); // reserved
        // Case-insensitive: two monikers differing only in case normalize equal.
        assert_eq!(normalize_moniker("MyNode"), normalize_moniker("mynode"));
    }
}
