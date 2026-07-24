//! v7 fees — the split, eligibility, and 1/N distribution (SPEC:
//! `docs/ECONOMIC-REDESIGN.md` §11/§12). **Fase 1e.** Self-contained + tested;
//! nothing wires it into `Ledger` yet (the fee-charging change + the quanto-close
//! hook go with the node wiring), so a v6 node is byte-identical.
//!
//! Per fee the split is **45% validators / 45% burn / 10% admin**: `admin =
//! floor(fee/10)`, then the remaining 90% is split with the burn taking the extra
//! unit (`burn = ceil(rest/2)`, `validator = floor(rest/2)`), so burn is never
//! below the validator share (a deflationary bias) and `fee == validator + burn +
//! admin` always. The validator share accumulates in `VALIDATOR_FEE_POOL_ID`
//! during a quanto and is split **equally** among the ELIGIBLE validators at the
//! close; the remainder stays in the pool for the next quanto (never burned,
//! never given to the proposer). The admin 10% credits `ADMIN_FEE_WALLET`
//! directly (liquid, spendable — administrative expenses).
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
use crate::ids::{ADMIN_FEE_WALLET, STAKING_PROGRAM_ID, VALIDATOR_FEE_POOL_ID};
use crate::validator_v7::{ValidatorV7Entry, ValidatorV7Registry, ValidatorV7State};
use qchain_core::Account;
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// The three-way split of one fee: `validator` (pooled and shared 1/N),
/// `burn` (leaves circulation), `admin` (to `ADMIN_FEE_WALLET`, liquid).
/// Invariant: `validator + burn + admin == fee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    pub validator: u64,
    pub burn: u64,
    pub admin: u64,
}

/// Split a fee **45% validators / 45% burn / 10% admin** with integer arithmetic,
/// the burn absorbing the sub-unit remainder so `burn >= validator` (deflationary)
/// and `validator + burn + admin == fee` always. `admin = floor(fee/10)`; the
/// remaining 90% splits `burn = ceil(rest/2)`, `validator = floor(rest/2)`.
pub fn fee_split(fee: u64) -> FeeSplit {
    let admin = fee / 10; // floor(10%)
    let rest = fee - admin; // 90%
    let burn = rest.div_ceil(2); // ceil(45%) — burn takes the extra unit
    let validator = rest - burn; // floor(45%)
    FeeSplit { validator, burn, admin }
}

/// Whether `entry` is eligible for `quanto`'s fee share.
pub fn is_eligible(entry: &ValidatorV7Entry, quanto: u64) -> bool {
    entry.state == ValidatorV7State::Active
        && entry.activation_quanto <= quanto
        && entry.participation_bps() >= VALIDATOR_MIN_PARTICIPATION_BPS
        // (#20) A revoked/expired consensus key is excluded from the fee split too
        // — the same deterministic gate `active_committee` uses.
        && !entry.consensus_key_disabled(quanto)
}

/// The eligible validators' **withdrawal (cold) addresses** for `quanto`, in
/// registry order (deterministic). The fee commissions accrue to the offline
/// withdrawal address — NOT the online consensus key — so a leak of the block-
/// signing key can't spend what the validator earned (role separation, #193-B).
/// (`withdrawal_address` defaults to the operator at registration; genesis
/// founders default it to their own consensus address unless a cold withdrawal
/// address is configured.)
pub fn eligible_addresses(registry: &ValidatorV7Registry, quanto: u64) -> Vec<Pubkey> {
    registry.validators.iter().filter(|v| is_eligible(v, quanto)).map(|v| v.withdrawal_address).collect()
}

fn credit(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, amount: u64) {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
    // #218: checked money, NOT saturating. This is fee-routing plumbing with a
    // tiny bounded amount (a share of one tx's fee) that cannot overflow at any
    // realistic supply; on the impossible overflow, fail loud rather than
    // silently cap (which would lose value).
    acct.balance = acct.balance.checked_add(amount).expect("v7 fee credit overflow — corrupt/attacked state");
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
        { let a = accounts.get_mut(&VALIDATOR_FEE_POOL_ID).unwrap(); a.balance = a.balance.checked_sub(paid).expect("v7 fee-pool debit underflow — corrupt state"); }
        for addr in &eligible {
            credit(accounts, addr, reward);
        }
    }
    let remainder = pool - paid;
    (reward, eligible.len(), remainder)
}

/// Route a just-charged fee under v7: burn 45% (leaves circulation), send 45% to
/// `VALIDATOR_FEE_POOL_ID` (split 1/N at the quanto close), and credit 10%
/// directly to `ADMIN_FEE_WALLET` (liquid — administrative expenses). Returns the
/// `FeeSplit`. (The ledger calls this in place of the v6 fee split when
/// economics_v7 is on; `split.burn` is added to the burn counter, `split.validator`
/// is left in the fee pool, `split.admin` lands in the admin wallet.) The admin
/// share crediting `ADMIN_FEE_WALLET` here is what keeps `validator + burn + admin
/// == fee` a true conservation statement over the accounts touched + the counter.
pub fn route_fee(accounts: &mut HashMap<Pubkey, Account>, fee: u64) -> FeeSplit {
    let split = fee_split(fee);
    if split.validator > 0 {
        let acct = accounts.entry(VALIDATOR_FEE_POOL_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
        acct.balance = acct.balance.checked_add(split.validator).expect("v7 fee-pool credit overflow — corrupt state");
    }
    if split.admin > 0 {
        credit(accounts, &ADMIN_FEE_WALLET, split.admin);
    }
    split
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
            // In these tests operator == withdrawal == the consensus address, so
            // eligible_addresses (which returns withdrawal_address) yields `addr`.
            operator_address: addr,
            withdrawal_address: addr,
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
            consensus_key_expiry_quanto: 0,
            consensus_key_revoked: false,
            retired_consensus_keys: Vec::new(),
        }
    }

    #[test]
    fn fee_split_45_45_10_conserves_and_burn_is_never_below_validator() {
        for fee in [0u64, 1, 2, 3, 9, 10, 11, 100, 101, 1_000_000, 1_002_780, u64::MAX] {
            let s = fee_split(fee);
            assert_eq!(s.validator + s.burn + s.admin, fee, "validator+burn+admin==fee (conservation), fee={fee}");
            assert!(s.burn >= s.validator, "burn never below the validator share (fee={fee})");
            assert_eq!(s.admin, fee / 10, "admin is exactly floor(10%) (fee={fee})");
        }
        // Clean split on a multiple of 20 → exact 45/45/10.
        assert_eq!(fee_split(100), FeeSplit { validator: 45, burn: 45, admin: 10 });
        // The calibrated single-transfer fee: 10% admin, 45%/45% with burn +1 on the odd 90%.
        let s = fee_split(1_002_780);
        assert_eq!(s, FeeSplit { validator: 451_251, burn: 451_251, admin: 100_278 });
        assert_eq!(s.validator + s.burn + s.admin, 1_002_780);
        // Tiny amounts: admin floors to 0, burn absorbs the odd unit.
        assert_eq!(fee_split(3), FeeSplit { validator: 1, burn: 2, admin: 0 });
        assert_eq!(fee_split(10), FeeSplit { validator: 4, burn: 5, admin: 1 });
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
    fn route_fee_pools_validator_share_burns_and_credits_admin_wallet() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let s = route_fee(&mut accounts, 1_002_780);
        assert_eq!(s.validator + s.burn + s.admin, 1_002_780, "conservation over the split");
        assert_eq!(s, FeeSplit { validator: 451_251, burn: 451_251, admin: 100_278 });
        // Validator share is left in the fee pool; admin share lands in the admin wallet.
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, s.validator);
        assert_eq!(accounts.get(&ADMIN_FEE_WALLET).unwrap().balance, s.admin);
        // The only funds moved into accounts are validator+admin; the burn is a
        // counter the ledger applies, not credited anywhere.
        assert_eq!(
            accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance + accounts.get(&ADMIN_FEE_WALLET).unwrap().balance,
            1_002_780 - s.burn,
            "credited accounts hold exactly the non-burned portion"
        );
        // A second fee accumulates in both destinations.
        let s2 = route_fee(&mut accounts, 100);
        assert_eq!(s2, FeeSplit { validator: 45, burn: 45, admin: 10 });
        assert_eq!(accounts.get(&VALIDATOR_FEE_POOL_ID).unwrap().balance, 451_251 + 45);
        assert_eq!(accounts.get(&ADMIN_FEE_WALLET).unwrap().balance, 100_278 + 10);
    }

    #[test]
    fn participation_bps_ratio_and_no_data_default() {
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 0, 0, 0).participation_bps(), 10_000, "no data → full (not penalized)");
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 90, 100, 0).participation_bps(), 9_000);
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 100, 100, 0).participation_bps(), 10_000);
        assert_eq!(entry(pk(1), ValidatorV7State::Active, 45, 100, 0).participation_bps(), 4_500);
    }
}
