//! v7 fees — the split, eligibility, and 1/N distribution (SPEC:
//! `docs/ECONOMIC-REDESIGN.md` §11/§12). **Fase 1e.** Self-contained + tested;
//! nothing wires it into `Ledger` yet (the fee-charging change + the quanto-close
//! hook go with the node wiring), so a v6 node is byte-identical.
//!
//! Per fee: `burn = ceil(fee/2)`, `validator = floor(fee/2)` — so the burned
//! share is never below 50% and `fee == burn + validator` always. The validator
//! half accumulates in `VALIDATOR_FEE_POOL_ID` during a quanto and is split
//! **equally** among the ELIGIBLE validators at the close; the remainder stays in
//! the pool for the next quanto (never burned, never given to the proposer).
//!
//! Eligibility (SPEC §11): a validator must be `Active`, past its activation
//! quanto, not jailed/slashed, and meet `VALIDATOR_MIN_PARTICIPATION_BPS`. A node
//! that was down for the quanto simply doesn't collect (it isn't burned — it
//! stays in the pool). The exact participation metric is finalized in the node
//! phase (SPEC §21.2); this module reads `ValidatorV7Entry::participation_bps`.
//!
//! The validator's fee share is **liquid**: it credits the validator's own
//! account balance directly (spendable with a normal transfer), so there is no
//! separate claim — matching "la comisión directa se acredita al balance".

use crate::economics_v7::VALIDATOR_MIN_PARTICIPATION_BPS;
use crate::ids::{STAKING_PROGRAM_ID, VALIDATOR_FEE_POOL_ID};
use crate::validator_v7::{ValidatorV7Entry, ValidatorV7Registry, ValidatorV7State};
use qchain_core::Account;
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// Split a fee into `(burn, validator_share)`. `burn = ceil(fee/2)` so the burned
/// fraction is never below 50% on an odd amount; `validator_share = floor(fee/2)`.
/// Invariant: `fee == burn + validator_share`.
pub fn fee_split(fee: u64) -> (u64, u64) {
    let burn = fee.div_ceil(2);
    let validator_share = fee - burn;
    (burn, validator_share)
}

/// Whether `entry` is eligible for `quanto`'s fee share.
pub fn is_eligible(entry: &ValidatorV7Entry, quanto: u64) -> bool {
    entry.state == ValidatorV7State::Active
        && entry.activation_quanto <= quanto
        && entry.participation_bps() >= VALIDATOR_MIN_PARTICIPATION_BPS
}

/// The eligible validator addresses for `quanto`, in registry order (deterministic).
pub fn eligible_addresses(registry: &ValidatorV7Registry, quanto: u64) -> Vec<Pubkey> {
    registry.validators.iter().filter(|v| is_eligible(v, quanto)).map(|v| v.address).collect()
}

fn credit(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, amount: u64) {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
    acct.balance = acct.balance.saturating_add(amount);
}

/// Distribute the current `VALIDATOR_FEE_POOL_ID` balance 1/N among the eligible
/// validators of `quanto`, crediting each one's account balance (liquid). The
/// remainder (`pool − reward × N`) stays in the pool for the next quanto. If
/// there are no eligible validators, nothing moves (the pool carries forward).
/// Returns `(reward_each, num_eligible, remainder)`. Deterministic (registry
/// order + integer division).
pub fn distribute_fee_pool(accounts: &mut HashMap<Pubkey, Account>, registry: &ValidatorV7Registry, quanto: u64) -> (u64, usize, u64) {
    let eligible = eligible_addresses(registry, quanto);
    let pool = accounts.get(&VALIDATOR_FEE_POOL_ID).map(|a| a.balance).unwrap_or(0);
    if eligible.is_empty() || pool == 0 {
        return (0, eligible.len(), pool);
    }
    let n = eligible.len() as u64;
    let reward = pool / n;
    let paid = reward * n;
    if reward > 0 {
        // Debit the pool by exactly what's paid; the remainder stays.
        accounts.get_mut(&VALIDATOR_FEE_POOL_ID).unwrap().balance -= paid;
        for addr in &eligible {
            credit(accounts, addr, reward);
        }
    }
    let remainder = pool - paid;
    (reward, eligible.len(), remainder)
}

/// Route a just-charged fee under v7: burn `ceil(fee/2)` (leaves circulation) and
/// send `floor(fee/2)` to `VALIDATOR_FEE_POOL_ID`. Returns `(burned, to_pool)`.
/// (The ledger calls this in place of the v6 fee split when economics_v7 is on;
/// `burned` is added to the burn counter, `to_pool` credited to the fee pool.)
pub fn route_fee(accounts: &mut HashMap<Pubkey, Account>, fee: u64) -> (u64, u64) {
    let (burn, validator_share) = fee_split(fee);
    if validator_share > 0 {
        let acct = accounts.entry(VALIDATOR_FEE_POOL_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
        acct.balance = acct.balance.saturating_add(validator_share);
    }
    (burn, validator_share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_v7::ValidatorV7Entry;
    use qchain_crypto::PublicKeyBundle;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new([b; 32])
    }
    fn entry(addr: Pubkey, state: ValidatorV7State, credits: u64, opps: u64, activation: u64) -> ValidatorV7Entry {
        ValidatorV7Entry {
            address: addr,
            moniker: "n".into(),
            pubkey_bundle: PublicKeyBundle { components: vec![] },
            p2p_address: "1.2.3.4:9000".into(),
            bond: 500_000_000_000,
            state,
            registered_quanto: 0,
            activation_quanto: activation,
            exit_requested_quanto: 0,
            bond_release_quanto: 0,
            participation_credits: credits,
            participation_opportunities: opps,
        }
    }

    #[test]
    fn fee_split_burns_at_least_half_and_conserves() {
        for fee in [0u64, 1, 2, 3, 100, 101, 1_000_000, 1_002_780, u64::MAX] {
            let (burn, val) = fee_split(fee);
            assert_eq!(burn + val, fee, "fee = burn + validator (conservation)");
            assert!(burn >= val, "burn is never below 50% (fee={fee})");
        }
        // Odd amount: burn takes the extra unit.
        assert_eq!(fee_split(3), (2, 1));
        assert_eq!(fee_split(101), (51, 50));
        // Even amount: exact halves.
        assert_eq!(fee_split(100), (50, 50));
    }

    #[test]
    fn distribution_is_equal_with_remainder_kept_in_the_pool() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        // 3 eligible validators, pool = 100 → each gets 33, remainder 1 stays.
        let mut a = Account::new_wallet(STAKING_PROGRAM_ID);
        a.balance = 100;
        accounts.insert(VALIDATOR_FEE_POOL_ID, a);
        let registry = ValidatorV7Registry {
            validators: vec![
                entry(pk(20), ValidatorV7State::Active, 100, 100, 0),
                entry(pk(21), ValidatorV7State::Active, 100, 100, 0),
                entry(pk(22), ValidatorV7State::Active, 100, 100, 0),
            ],
        };
        let (reward, n, remainder) = distribute_fee_pool(&mut accounts, &registry, 5);
        assert_eq!((reward, n, remainder), (33, 3, 1));
        for v in [pk(20), pk(21), pk(22)] {
            assert_eq!(accounts.get(&v).unwrap().balance, 33, "each eligible validator gets the same 1/N");
        }
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, 1, "remainder stays in the pool");
    }

    #[test]
    fn ineligible_validators_dont_collect_and_funds_stay() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let mut a = Account::new_wallet(STAKING_PROGRAM_ID);
        a.balance = 90;
        accounts.insert(VALIDATOR_FEE_POOL_ID, a);
        let registry = ValidatorV7Registry {
            validators: vec![
                entry(pk(20), ValidatorV7State::Active, 100, 100, 0),        // eligible
                entry(pk(21), ValidatorV7State::Jailed, 100, 100, 0),        // jailed → out
                entry(pk(22), ValidatorV7State::Active, 50, 100, 0),         // 50% participation < 90% → out
                entry(pk(23), ValidatorV7State::Active, 100, 100, 9),        // activated quanto 9 > 5 → out
                entry(pk(24), ValidatorV7State::Slashed, 100, 100, 0),       // slashed → out
            ],
        };
        let (reward, n, remainder) = distribute_fee_pool(&mut accounts, &registry, 5);
        assert_eq!(n, 1, "only one validator is eligible");
        assert_eq!(reward, 90);
        assert_eq!(remainder, 0);
        assert_eq!(accounts.get(&pk(20)).unwrap().balance, 90);
        assert_eq!(accounts.get(&pk(21)).map(|a| a.balance).unwrap_or(0), 0, "jailed collects nothing");
        assert_eq!(accounts.get(&pk(22)).map(|a| a.balance).unwrap_or(0), 0, "low-participation collects nothing");
    }

    #[test]
    fn no_eligible_validators_leaves_the_pool_untouched() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let mut a = Account::new_wallet(STAKING_PROGRAM_ID);
        a.balance = 500;
        accounts.insert(VALIDATOR_FEE_POOL_ID, a);
        let registry = ValidatorV7Registry {
            validators: vec![entry(pk(20), ValidatorV7State::Jailed, 100, 100, 0)],
        };
        let (reward, n, remainder) = distribute_fee_pool(&mut accounts, &registry, 5);
        assert_eq!((reward, n, remainder), (0, 0, 500));
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, 500, "no eligible → pool carries forward, nothing burned");
    }

    #[test]
    fn route_fee_burns_half_and_pools_half() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let (burned, to_pool) = route_fee(&mut accounts, 1_002_780);
        assert_eq!(burned + to_pool, 1_002_780);
        assert_eq!(burned, 501_390);
        assert_eq!(to_pool, 501_390);
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, to_pool);
        // Odd fee: burn takes the extra unit, pool never over-credited.
        let (b2, p2) = route_fee(&mut accounts, 3);
        assert_eq!((b2, p2), (2, 1));
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, 501_390 + 1);
    }

    #[test]
    fn participation_bps_ratio_and_no_data_default() {
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 0, 0, 0).participation_bps(), 10_000, "no data → full (not penalized)");
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 90, 100, 0).participation_bps(), 9_000);
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 100, 100, 0).participation_bps(), 10_000);
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 45, 100, 0).participation_bps(), 4_500);
    }
}
