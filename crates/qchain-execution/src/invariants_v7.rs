//! v7 economic invariants + differential reference model (SPEC:
//! `docs/ECONOMIC-REDESIGN.md` §13/§19). **Fase 1f.** Self-contained + tested;
//! nothing wires it into `Ledger`, consensus, or the node → a v6 node is
//! byte-identical. This is the verification harness the v7 spec makes mandatory:
//! the per-block economic invariants (§13) as checkable functions, plus an O(N)
//! reference model exercised against the O(1) accumulator implementation so the
//! differential DST (§19) asserts they never diverge.
//!
//! What §13 requires, and how it maps here:
//! - **Supply:** `Δsupply = emission − fees_burned − bonds_slashed`. Pool-to-pool
//!   transfers never change supply. Encoded as `SupplyTally` + `check_supply`:
//!   the sum of every account balance must equal
//!   `genesis + minted − fee_burned − slashed`.
//! - **Staking:** the reserve is never underfunded — `reserve ≥ Σ position_value`
//!   — and the aggregate accumulator value floors *no lower* than the sum of the
//!   per-position floors (`floor(Σ shares × index) ≥ Σ floor(sharesᵢ × index)`).
//!   This is NOT strict equality: a floor-valued deposit leaves a sub-unit residue
//!   *in the reserve* (the honest 1b invariant), never mints.
//! - **Validators:** `Σ bonds still in escrow == validator_bond_escrow balance`,
//!   and every escrowed bond is exactly `VALIDATOR_BOND_ATOMS`.
//! - **Fees:** `validator + burn + admin == fee` for every fee (the v7 45/45/10
//!   split), and after a quanto close `pool_before + fees_new = distributed +
//!   remainder_new`.
//! - **Rounding:** no rounding op creates QCH; residues stay in an identifiable
//!   pool (the reserve for staking, the fee pool for the 1/N split).
//!
//! The **economic state root** is a read-order-independent hash of the sorted
//! economic accounts, so "the order of reading accounts does not change the state
//! root" (§19) is a checkable property, not a hope.

use crate::economics_v7::{position_value, VALIDATOR_BOND_ATOMS};
use crate::fees_v7::{fee_split, FeeSplit};
use crate::ids::VALIDATOR_BOND_ESCROW_ID;
use crate::validator_v7::{ValidatorV7Registry, ValidatorV7State};
use qchain_core::Account;
use qchain_crypto::Pubkey;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::collections::HashMap;

/// A violated economic invariant, with the two numbers that disagreed so a DST
/// failure names the exact break instead of a bare assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// `Σ balances != genesis + minted − fee_burned − slashed`.
    Supply { expected: u128, actual: u128 },
    /// The staking reserve holds less than the total value of active positions.
    ReserveUnderfunded { reserve: u128, positions_value: u128 },
    /// The O(1) aggregate value floored *below* the O(N) sum of per-position
    /// floors — impossible under correct floor arithmetic; would mean the
    /// accumulator lost value the per-position view kept.
    AccumulatorBelowReference { aggregate: u128, reference_sum: u128 },
    /// `Σ escrowed bonds != validator_bond_escrow balance`.
    BondEscrowMismatch { registry_sum: u64, escrow_balance: u64 },
    /// An escrowed validator's bond is not exactly `VALIDATOR_BOND_ATOMS`.
    BondNotExact { validator: Pubkey, bond: u64 },
    /// `validator + burn + admin != fee` for some fee.
    FeeSplitBroken { fee: u64, split: FeeSplit },
    /// A quanto close did not conserve the pool: `pool_before + fees_new !=
    /// distributed + remainder_new`.
    FeePoolNotConserved { pool_before: u64, fees_new: u64, distributed: u64, remainder_new: u64 },
}

/// Running supply accounting for the whole economy. Genesis mints the founder
/// allocation; staking emission is the ONLY other source; fee burns and slashed
/// bonds are the ONLY sinks. Everything else (staking deposits, fee routing to
/// pools, the 1/N distribution, bond escrow moves) is a transfer that conserves
/// supply, so it never touches these counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct SupplyTally {
    pub genesis: u128,
    pub minted: u128,
    pub fee_burned: u128,
    pub slashed: u128,
}

impl SupplyTally {
    /// The total balance the whole account set must sum to right now.
    pub fn expected_total(&self) -> u128 {
        // Saturating: an invariant check must never itself panic under
        // `overflow-checks`; a real break surfaces as a mismatch, not a crash.
        self.genesis
            .saturating_add(self.minted)
            .saturating_sub(self.fee_burned)
            .saturating_sub(self.slashed)
    }
}

/// Sum every account's balance (u128 — the economy can exceed u64 across pools).
pub fn total_supply(accounts: &HashMap<Pubkey, Account>) -> u128 {
    accounts.values().fold(0u128, |acc, a| acc.saturating_add(a.balance as u128))
}

/// Supply invariant: `Σ balances == genesis + minted − fee_burned − slashed`.
pub fn check_supply(accounts: &HashMap<Pubkey, Account>, tally: &SupplyTally) -> Result<(), InvariantViolation> {
    let actual = total_supply(accounts);
    let expected = tally.expected_total();
    if actual == expected {
        Ok(())
    } else {
        Err(InvariantViolation::Supply { expected, actual })
    }
}

/// A validator's bond is in the escrow account exactly while it is registered and
/// has not yet begun exiting (BeginExit moves it to the unbonding pool; a slash
/// burns it; withdrawal returns it). So escrow holds the bonds of these states.
fn bond_is_in_escrow(state: ValidatorV7State) -> bool {
    matches!(state, ValidatorV7State::BondedPending | ValidatorV7State::Active | ValidatorV7State::Jailed)
}

/// Validator invariant: `Σ escrowed bonds == validator_bond_escrow balance`, and
/// every escrowed bond is exactly `VALIDATOR_BOND_ATOMS`.
pub fn check_bond_escrow(accounts: &HashMap<Pubkey, Account>, registry: &ValidatorV7Registry) -> Result<(), InvariantViolation> {
    let mut sum: u64 = 0;
    for v in &registry.validators {
        if bond_is_in_escrow(v.state) {
            if v.bond != VALIDATOR_BOND_ATOMS {
                return Err(InvariantViolation::BondNotExact { validator: v.address, bond: v.bond });
            }
            sum = sum.saturating_add(v.bond);
        }
    }
    let escrow_balance = accounts.get(&VALIDATOR_BOND_ESCROW_ID).map(|a| a.balance).unwrap_or(0);
    if sum == escrow_balance {
        Ok(())
    } else {
        Err(InvariantViolation::BondEscrowMismatch { registry_sum: sum, escrow_balance })
    }
}

/// Fee invariant: `validator + burn + admin == fee` for this fee.
pub fn check_fee_split(fee: u64) -> Result<(), InvariantViolation> {
    let split = fee_split(fee);
    // saturating_add: the check must not panic; a real break is a mismatch.
    if split.validator.saturating_add(split.burn).saturating_add(split.admin) == fee {
        Ok(())
    } else {
        Err(InvariantViolation::FeeSplitBroken { fee, split })
    }
}

/// Staking invariant: the reserve is never underfunded and the O(1) aggregate
/// never floors below the O(N) reference sum. `reserve_value` is the reserve's
/// balance; `aggregate_value = position_value(total_shares, index)`;
/// `reference_sum = Σ position_value(sharesᵢ, index)` computed per position.
pub fn check_staking_reserve(reserve_value: u128, aggregate_value: u128, reference_sum: u128) -> Result<(), InvariantViolation> {
    if aggregate_value < reference_sum {
        return Err(InvariantViolation::AccumulatorBelowReference { aggregate: aggregate_value, reference_sum });
    }
    if reserve_value < aggregate_value {
        return Err(InvariantViolation::ReserveUnderfunded { reserve: reserve_value, positions_value: aggregate_value });
    }
    Ok(())
}

/// The O(1) accumulator value of all active shares (`floor(total_shares × index)`).
pub fn accumulator_total_value(total_shares: u128, index: u128) -> u128 {
    position_value(total_shares, index)
}

/// The O(N) reference value: sum of each position's floored value. This is the
/// slow model §19 requires; `check_staking_reserve` asserts the O(1) aggregate
/// dominates it (floor-of-sum ≥ sum-of-floors).
pub fn reference_total_value(shares_per_position: &[u128], index: u128) -> u128 {
    shares_per_position.iter().fold(0u128, |acc, &s| acc.saturating_add(position_value(s, index)))
}

/// A canonical, read-order-independent hash of the economic account set: sort by
/// address, fold `(address ++ balance_le ++ owner ++ nonce_le)` into SHA3-256.
/// Because it sorts first, two account maps with identical contents but different
/// `HashMap` iteration orders produce the same root (§19).
pub fn economic_state_root(accounts: &HashMap<Pubkey, Account>) -> [u8; 32] {
    let ordered: BTreeMap<[u8; 32], &Account> = accounts.iter().map(|(k, v)| (k.0, v)).collect();
    let mut h = Sha3_256::new();
    for (addr, acct) in ordered {
        h.update(addr);
        h.update(acct.balance.to_le_bytes());
        h.update(acct.owner.0);
        h.update(acct.nonce.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics_v7::{advance_staking_index, derive_quanto_rate_fp, emission_for_quanto, shares_for_deposit, INDEX_SCALE, STAKING_TARGET_APY_BPS};
    use crate::fees_v7::{distribute_fee_pool, route_fee};
    use crate::ids::{ADMIN_FEE_WALLET, STAKING_RESERVE_ID, VALIDATOR_FEE_POOL_ID};
    use crate::validator_v7::ValidatorV7Entry;
    use qchain_core::UNITS_PER_QCH;
    use qchain_crypto::PublicKeyBundle;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new([b; 32])
    }
    fn wallet(balance: u64) -> Account {
        let mut a = Account::new_wallet(Pubkey::system_program_id());
        a.balance = balance;
        a
    }

    /// A deterministic LCG (no `Math.random`/`Date::now`, both forbidden here and
    /// consistent with the rest of the project's DST discipline).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo + 1)
        }
    }

    /// The full economic world for the differential DST: real accounts (founder,
    /// pools, per-staker wallets), the O(1) global (index + total_shares), a
    /// parallel O(N) view of every position's shares, a validator registry, and
    /// the supply tally. Everything moves through the *pure* v7 functions
    /// (`shares_for_deposit`, `advance_staking_index`, `emission_for_quanto`,
    /// `route_fee`, `distribute_fee_pool`, `fee_split`) — this IS the reference
    /// economic model §19 asks for.
    struct EconWorld {
        accounts: HashMap<Pubkey, Account>,
        index: u128,
        total_shares: u128,
        /// address → active shares (the O(N) reference view).
        positions: BTreeMap<Pubkey, u128>,
        registry: ValidatorV7Registry,
        tally: SupplyTally,
        rate_fp: u128,
    }

    impl EconWorld {
        fn new(founder_qch: u64) -> Self {
            let genesis = founder_qch as u128 * UNITS_PER_QCH as u128;
            let mut accounts = HashMap::new();
            accounts.insert(pk(1), wallet((genesis) as u64)); // founder holds all genesis supply
            let rate_fp = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, 365);
            EconWorld {
                accounts,
                index: INDEX_SCALE,
                total_shares: 0,
                positions: BTreeMap::new(),
                registry: ValidatorV7Registry { validators: vec![] },
                tally: SupplyTally { genesis, ..Default::default() },
                rate_fp,
            }
        }

        fn bal(&self, pk: &Pubkey) -> u64 {
            self.accounts.get(pk).map(|a| a.balance).unwrap_or(0)
        }
        fn credit(&mut self, pk: Pubkey, amount: u64) {
            self.accounts.entry(pk).or_insert_with(|| wallet(0)).balance += amount;
        }

        /// Stake `amount` from the founder into the reserve, minting shares.
        /// Wallet→reserve is a transfer (supply unchanged).
        fn stake(&mut self, staker: Pubkey, amount: u64) {
            if self.bal(&pk(1)) < amount || amount == 0 {
                return;
            }
            self.accounts.get_mut(&pk(1)).unwrap().balance -= amount;
            self.credit(STAKING_RESERVE_ID, amount);
            let minted = shares_for_deposit(amount, self.index);
            self.total_shares += minted;
            *self.positions.entry(staker).or_insert(0) += minted;
        }

        /// Close a quanto: advance the index, mint emission into the reserve
        /// (supply += minted). Emission is the exact floored value delta so the
        /// reserve stays `≥ Σ position_value` (the 1b invariant).
        fn close_quanto(&mut self) {
            let old_index = self.index;
            let new_index = advance_staking_index(self.index, self.rate_fp);
            let minted = emission_for_quanto(self.total_shares, old_index, new_index);
            self.index = new_index;
            if minted > 0 {
                self.credit(STAKING_RESERVE_ID, minted as u64);
                self.tally.minted += minted;
            }
        }

        /// Charge `fee` to the founder and route it 45/45/10. The founder pays
        /// (supply −= fee momentarily), route credits validator pool + admin
        /// (transfer back into supply), and the burn is destroyed (supply −=
        /// burn net). Tracked so the supply invariant holds.
        fn route_fee(&mut self, fee: u64) {
            if self.bal(&pk(1)) < fee || fee == 0 {
                return;
            }
            self.accounts.get_mut(&pk(1)).unwrap().balance -= fee;
            let split = route_fee(&mut self.accounts, fee);
            // burn leaves circulation; validator+admin were credited into accounts.
            self.tally.fee_burned += split.burn as u128;
        }

        /// Distribute the fee pool 1/N among eligible validators at a quanto close.
        /// Pure transfer (pool → validators), supply unchanged.
        fn distribute_fees(&mut self, quanto: u64) -> (u64, usize, u64) {
            distribute_fee_pool(&mut self.accounts, &self.registry, quanto)
        }

        /// Register a validator: lock exactly the bond from the founder into escrow.
        fn register_validator(&mut self, addr: Pubkey) {
            if self.bal(&pk(1)) < VALIDATOR_BOND_ATOMS {
                return;
            }
            self.accounts.get_mut(&pk(1)).unwrap().balance -= VALIDATOR_BOND_ATOMS;
            self.credit(VALIDATOR_BOND_ESCROW_ID, VALIDATOR_BOND_ATOMS);
            self.registry.validators.push(ValidatorV7Entry {
                address: addr,
                moniker: format!("v{}", addr.0[0]),
                pubkey_bundle: PublicKeyBundle { components: vec![] },
                p2p_address: "1.2.3.4:9000".into(),
                bond: VALIDATOR_BOND_ATOMS,
                state: ValidatorV7State::Active,
                registered_quanto: 0,
                activation_quanto: 0,
                exit_requested_quanto: 0,
                bond_release_quanto: 0,
                participation_credits: 100,
                participation_opportunities: 100,
            });
        }

        /// Slash a registered validator's full bond (burn from escrow).
        fn slash(&mut self, addr: Pubkey) {
            if let Some(v) = self.registry.validators.iter_mut().find(|v| v.address == addr && bond_is_in_escrow(v.state)) {
                let bond = v.bond;
                v.state = ValidatorV7State::Slashed;
                self.accounts.get_mut(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance -= bond;
                self.tally.slashed += bond as u128;
            }
        }

        fn reference_shares(&self) -> Vec<u128> {
            self.positions.values().copied().collect()
        }

        /// Run EVERY §13 invariant. Called after each quanto in the DST.
        fn check_all(&self) -> Result<(), InvariantViolation> {
            check_supply(&self.accounts, &self.tally)?;
            check_bond_escrow(&self.accounts, &self.registry)?;
            let reserve = self.bal(&STAKING_RESERVE_ID) as u128;
            let aggregate = accumulator_total_value(self.total_shares, self.index);
            let reference = reference_total_value(&self.reference_shares(), self.index);
            check_staking_reserve(reserve, aggregate, reference)?;
            Ok(())
        }
    }

    #[test]
    fn supply_invariant_tracks_emission_and_burns_over_a_full_run() {
        let mut w = EconWorld::new(10_000_000);
        // Baseline: genesis supply is exactly the founder allocation.
        assert_eq!(total_supply(&w.accounts), 10_000_000u128 * UNITS_PER_QCH as u128);
        w.check_all().unwrap();

        w.stake(pk(2), 1_000_000 * UNITS_PER_QCH); // transfer: supply unchanged
        w.check_all().unwrap();
        w.close_quanto(); // mints emission → supply grows
        w.check_all().unwrap();
        w.route_fee(1_002_780); // burns 45% → supply shrinks
        w.check_all().unwrap();
        w.register_validator(pk(20)); // transfer to escrow
        w.check_all().unwrap();
        w.slash(pk(20)); // burns the bond → supply shrinks
        w.check_all().unwrap();
    }

    #[test]
    fn differential_o1_never_floors_below_on_reference_over_years_of_quantos() {
        let mut w = EconWorld::new(10_000_000);
        let mut rng = Lcg(0xC0FFEE);
        // Several stakers with varied deposits.
        for i in 0..8u8 {
            w.stake(pk(30 + i), rng.in_range(1, 500_000) * UNITS_PER_QCH);
        }
        // Simulate two years of quantos with occasional mid-run stakes + fees.
        for q in 0..(365 * 2) {
            w.close_quanto();
            // The mandatory differential + all §13 invariants, every quanto.
            w.check_all().unwrap_or_else(|e| panic!("quanto {q}: {e:?}"));
            // O(1) aggregate must dominate the O(N) sum (floor-of-sum ≥ sum-of-floors).
            let agg = accumulator_total_value(w.total_shares, w.index);
            let refsum = reference_total_value(&w.reference_shares(), w.index);
            assert!(agg >= refsum, "quanto {q}: aggregate {agg} < reference {refsum}");
            if q % 50 == 0 {
                w.stake(pk(40 + (q % 5) as u8), rng.in_range(1, 100_000) * UNITS_PER_QCH);
                w.route_fee(rng.in_range(1, 2_000_000));
            }
        }
    }

    #[test]
    fn fee_split_conserves_and_pool_close_conserves() {
        // Every fee splits with conservation.
        for fee in [0u64, 1, 3, 7, 10, 99, 100, 1_002_780, u64::MAX] {
            check_fee_split(fee).unwrap();
        }
        // Quanto-close pool conservation: pool_before + fees_new == distributed + remainder_new.
        let mut w = EconWorld::new(10_000_000);
        for i in 0..3u8 {
            w.register_validator(pk(20 + i));
        }
        // Seed a pool balance, then add fresh fees, then distribute.
        w.route_fee(1_000_000); // credits ~45% to the pool
        let pool_before = w.bal(&VALIDATOR_FEE_POOL_ID);
        w.route_fee(500_003); // more fees into the pool
        let fees_new = w.bal(&VALIDATOR_FEE_POOL_ID) - pool_before;
        let pool_total = w.bal(&VALIDATOR_FEE_POOL_ID);
        let (reward, n, remainder) = w.distribute_fees(5);
        let distributed = reward * n as u64;
        assert_eq!(distributed + remainder, pool_total, "distributed + remainder == pool");
        assert_eq!(pool_before + fees_new, distributed + remainder, "pool_before + fees_new == distributed + remainder_new");
        // Nothing was minted or burned by distribution — supply invariant still holds.
        w.check_all().unwrap();
    }

    #[test]
    fn bond_escrow_invariant_follows_register_and_slash() {
        let mut w = EconWorld::new(10_000_000);
        w.register_validator(pk(20));
        w.register_validator(pk(21));
        // Two active bonds → escrow holds exactly 2 × bond.
        assert_eq!(w.bal(&VALIDATOR_BOND_ESCROW_ID), 2 * VALIDATOR_BOND_ATOMS);
        check_bond_escrow(&w.accounts, &w.registry).unwrap();
        // Slash one → escrow drops by exactly one bond, invariant still holds.
        w.slash(pk(20));
        assert_eq!(w.bal(&VALIDATOR_BOND_ESCROW_ID), VALIDATOR_BOND_ATOMS);
        check_bond_escrow(&w.accounts, &w.registry).unwrap();
        // A tampered escrow (an extra unit that no bond backs) is caught.
        w.accounts.get_mut(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance += 1;
        assert!(matches!(check_bond_escrow(&w.accounts, &w.registry), Err(InvariantViolation::BondEscrowMismatch { .. })));
    }

    #[test]
    fn economic_state_root_is_read_order_independent() {
        // Build the same logical state via two different insertion orders.
        let entries = [
            (pk(5), wallet(123)),
            (STAKING_RESERVE_ID, wallet(999_999)),
            (VALIDATOR_FEE_POOL_ID, wallet(451_251)),
            (ADMIN_FEE_WALLET, wallet(100_278)),
            (pk(9), wallet(0)),
        ];
        let mut a: HashMap<Pubkey, Account> = HashMap::new();
        for (k, v) in entries.iter() {
            a.insert(*k, v.clone());
        }
        let mut b: HashMap<Pubkey, Account> = HashMap::new();
        for (k, v) in entries.iter().rev() {
            b.insert(*k, v.clone());
        }
        assert_eq!(economic_state_root(&a), economic_state_root(&b), "root is independent of read/insert order");
        // A single changed balance changes the root.
        b.get_mut(&pk(5)).unwrap().balance += 1;
        assert_ne!(economic_state_root(&a), economic_state_root(&b));
    }

    #[test]
    fn a_broken_supply_is_detected() {
        let mut w = EconWorld::new(1_000);
        w.check_all().unwrap();
        // Mint a unit out of thin air (no counter bump) → supply invariant fails.
        w.accounts.get_mut(&pk(1)).unwrap().balance += 1;
        assert!(matches!(check_supply(&w.accounts, &w.tally), Err(InvariantViolation::Supply { .. })));
    }

    #[test]
    fn a_reserve_underfunded_by_bad_emission_is_detected() {
        // If emission credited LESS than the value the index growth implies, the
        // reserve would be underfunded — the invariant must catch it.
        let reserve = 100u128;
        let aggregate = 150u128; // positions are worth more than the reserve holds
        let reference = 150u128;
        assert!(matches!(
            check_staking_reserve(reserve, aggregate, reference),
            Err(InvariantViolation::ReserveUnderfunded { .. })
        ));
        // And an accumulator that floored below the per-position sum is caught.
        assert!(matches!(
            check_staking_reserve(1000, 90, 100),
            Err(InvariantViolation::AccumulatorBelowReference { .. })
        ));
    }
}
