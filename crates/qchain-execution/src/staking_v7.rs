//! v7 staking — the shares + global-index model (SPEC: `docs/ECONOMIC-REDESIGN.md`
//! §2/§4/§5). **Fase 1b.** Self-contained and INERT: nothing wires it into
//! `Ledger`/consensus yet (the gated dispatch + genesis seeding land alongside
//! the quanto close, 1c), so a v6 node is byte-identical. Operates on a working
//! set of accounts exactly like the existing `StakingProgram`.
//!
//! ## Model
//! A position holds **shares**, not a nominal amount. Its live value is
//! `shares × index / INDEX_SCALE` (see `economics_v7`). One global
//! `staking_index` grows each quanto (`settle_quanto` below) — that growth IS
//! the auto-compounding of every position at once, O(1), no per-position claim.
//!
//! - `Stake`/`IncreaseStake` move principal into the **staking reserve**
//!   (`STAKING_RESERVE_ID`) and mint shares.
//! - the quanto close mints emission into the reserve AND advances the index, so
//!   the reserve balance stays equal to the total position value.
//! - `BeginUnstake` converts value to a fixed amount in the **unbonding pool**
//!   (`STAKING_UNBONDING_POOL_ID`), stops it earning, and starts the unbonding
//!   clock; `WithdrawUnbonded` pays it out once the clock elapses.
//!
//! "Withdraw rewards" in the wallet is just a partial `BeginUnstake` of the
//! grown value above `net_deposited` — there is no separate reward source.
//!
//! ## v1 simplification (documented, not hidden)
//! A position carries at most ONE unbonding chunk at a time (a second
//! `BeginUnstake` while one is pending is rejected) — mirrors the existing
//! two-step self-stake unbonding and keeps the state machine small. Multiple
//! concurrent unbonding chunks per position are a later refinement.

use crate::economics_v7::{
    position_value, shares_for_deposit, INITIAL_STAKING_INDEX, STAKING_UNBONDING_QUANTOS,
};
use crate::error::ExecError;
use crate::ids::{STAKING_GLOBAL_ID, STAKING_PROGRAM_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID};
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, Instruction};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// The global staking state singleton (`STAKING_GLOBAL_ID.data`). Everything the
/// O(1) per-quanto close needs; holds no funds itself (the reserve does).
#[derive(Clone, Copy, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct GlobalStakingState {
    /// `staking_index`, `INDEX_SCALE`-scaled. Starts at `INITIAL_STAKING_INDEX`.
    pub index: u128,
    /// Total ACTIVE (earning) shares across all positions.
    pub total_shares: u128,
    /// The quanto currently accruing.
    pub current_quanto: u64,
    /// The last quanto whose emission was settled (idempotency guard for 1c).
    pub last_settled_quanto: u64,
}

impl GlobalStakingState {
    /// The genesis state: index at 1.0, nothing staked, quanto 0.
    pub fn genesis() -> Self {
        GlobalStakingState { index: INITIAL_STAKING_INDEX, total_shares: 0, current_quanto: 0, last_settled_quanto: 0 }
    }
}

/// UI/state label for a position (SPEC §5). The authoritative economic facts are
/// `active_shares` (earning) and the unbonding chunk; this is derived from them.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum PositionState {
    Active,
    Unbonding,
    Withdrawable,
    Closed,
}

/// A staker's position (stored in a stake account's `data`; the account is owned
/// by `STAKING_PROGRAM_ID` and holds no balance — the real QCH lives in the
/// reserve/unbonding pools).
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct StakePositionV7 {
    pub owner: Pubkey,
    /// Earning shares. `value = position_value(active_shares, index)`.
    pub active_shares: u128,
    pub created_quanto: u64,
    pub last_modified_quanto: u64,
    /// Sum of principal ever deposited (for the wallet's capital-vs-reward
    /// split; not used in any economic computation).
    pub net_deposited: u64,
    /// The single pending unbonding chunk, in atoms (0 = none). Held in the
    /// unbonding pool, no longer earning.
    pub unbonding_amount: u64,
    /// Quanto at which `unbonding_amount` becomes withdrawable (0 = none).
    pub unbonding_ready_quanto: u64,
    pub state: PositionState,
}

/// v7 staking instructions. Borsh discriminants are stable within v7 (a fresh
/// genesis; not shared with the v6 `StakingInstruction`).
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum StakingV7Instruction {
    /// Open a NEW position. accounts = [staker(payer), fresh position pk,
    /// STAKING_GLOBAL_ID, STAKING_RESERVE_ID].
    Stake { amount: u64 },
    /// Add to an EXISTING position (owned by the payer). accounts = [staker,
    /// position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID].
    IncreaseStake { amount: u64 },
    /// Move `amount` (atoms of value) into unbonding. accounts = [staker,
    /// position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID].
    BeginUnstake { amount: u64 },
    /// Pay out the matured unbonding chunk. accounts = [staker, position,
    /// STAKING_UNBONDING_POOL_ID].
    WithdrawUnbonded,
}

pub struct StakingV7Program;

fn read_global(accounts: &HashMap<Pubkey, Account>) -> GlobalStakingState {
    accounts
        .get(&STAKING_GLOBAL_ID)
        .and_then(|a| GlobalStakingState::try_from_slice(&a.data).ok())
        .unwrap_or_else(GlobalStakingState::genesis)
}

fn write_global(accounts: &mut HashMap<Pubkey, Account>, g: &GlobalStakingState) -> Result<(), ExecError> {
    let acct = accounts
        .entry(STAKING_GLOBAL_ID)
        .or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.data = borsh::to_vec(g).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

fn read_position(accounts: &HashMap<Pubkey, Account>, pk: &Pubkey) -> Option<StakePositionV7> {
    accounts.get(pk).and_then(|a| StakePositionV7::try_from_slice(&a.data).ok())
}

fn write_position(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, p: &StakePositionV7) -> Result<(), ExecError> {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.owner = STAKING_PROGRAM_ID;
    acct.balance = 0; // value is virtual (shares × index); funds live in the pools
    acct.data = borsh::to_vec(p).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

fn credit(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, owner_if_new: Pubkey, amount: u64) {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(owner_if_new));
    acct.balance = acct.balance.saturating_add(amount);
}

impl StakingV7Program {
    /// Apply a v7 staking instruction to the working set. Pure over `accounts`
    /// (+ the pinned singletons), same contract as `StakingProgram::process`.
    pub fn process(accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey) -> Result<(), ExecError> {
        let instr = StakingV7Instruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad v7 staking instruction: {e}")))?;
        match instr {
            StakingV7Instruction::Stake { amount } => Self::stake(accounts, instruction, payer, amount, false),
            StakingV7Instruction::IncreaseStake { amount } => Self::stake(accounts, instruction, payer, amount, true),
            StakingV7Instruction::BeginUnstake { amount } => Self::begin_unstake(accounts, instruction, payer, amount),
            StakingV7Instruction::WithdrawUnbonded => Self::withdraw_unbonded(accounts, instruction, payer),
        }
    }

    fn stake(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, amount: u64, increase: bool) -> Result<(), ExecError> {
        let staker = *ix.accounts.first().ok_or_else(|| ExecError::ProgramError("Stake requires accounts[0]".into()))?;
        let position_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Stake requires accounts[1]".into()))?;
        let global_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Stake requires accounts[2]".into()))?;
        let reserve_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("Stake requires accounts[3]".into()))?;
        if global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("Stake must name the canonical global staking account".into()));
        }
        if reserve_pk != STAKING_RESERVE_ID {
            return Err(ExecError::Unauthorized("Stake must name the canonical staking reserve".into()));
        }
        if staker != *payer {
            return Err(ExecError::Unauthorized("the staking funding account must be the transaction payer".into()));
        }
        if amount == 0 {
            return Err(ExecError::ProgramError("cannot stake zero".into()));
        }

        let mut g = read_global(accounts);
        let index = g.index;

        // A validator's registered address may not open a staking position (SPEC
        // §5/§6). Enforced at the ledger boundary (needs the validator registry);
        // this module handles the staking mechanics.

        let existing = read_position(accounts, &position_pk);
        if increase {
            let mut pos = existing.ok_or_else(|| ExecError::ProgramError("IncreaseStake requires an existing position".into()))?;
            if pos.owner != *payer {
                return Err(ExecError::Unauthorized("only the position owner can increase it".into()));
            }
            if pos.state == PositionState::Closed {
                return Err(ExecError::ProgramError("cannot increase a closed position".into()));
            }
            let staker_balance = accounts.get(&staker).ok_or(ExecError::AccountNotFound(staker))?.balance;
            if staker_balance < amount {
                return Err(ExecError::InsufficientFunds);
            }
            accounts.get_mut(&staker).unwrap().balance -= amount;
            let new_shares = shares_for_deposit(amount, index);
            pos.active_shares = pos.active_shares.saturating_add(new_shares);
            pos.net_deposited = pos.net_deposited.saturating_add(amount);
            pos.last_modified_quanto = g.current_quanto;
            pos.state = PositionState::Active;
            g.total_shares = g.total_shares.saturating_add(new_shares);
            credit(accounts, &reserve_pk, STAKING_PROGRAM_ID, amount);
            write_global(accounts, &g)?;
            write_position(accounts, &position_pk, &pos)?;
        } else {
            if existing.is_some() {
                return Err(ExecError::ProgramError("position account already exists - Stake opens a fresh one".into()));
            }
            let staker_balance = accounts.get(&staker).ok_or(ExecError::AccountNotFound(staker))?.balance;
            if staker_balance < amount {
                return Err(ExecError::InsufficientFunds);
            }
            accounts.get_mut(&staker).unwrap().balance -= amount;
            let new_shares = shares_for_deposit(amount, index);
            let pos = StakePositionV7 {
                owner: staker,
                active_shares: new_shares,
                created_quanto: g.current_quanto,
                last_modified_quanto: g.current_quanto,
                net_deposited: amount,
                unbonding_amount: 0,
                unbonding_ready_quanto: 0,
                state: PositionState::Active,
            };
            g.total_shares = g.total_shares.saturating_add(new_shares);
            credit(accounts, &reserve_pk, STAKING_PROGRAM_ID, amount);
            write_global(accounts, &g)?;
            write_position(accounts, &position_pk, &pos)?;
        }
        Ok(())
    }

    fn begin_unstake(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, amount: u64) -> Result<(), ExecError> {
        let _staker = *ix.accounts.first().ok_or_else(|| ExecError::ProgramError("BeginUnstake requires accounts[0]".into()))?;
        let position_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("BeginUnstake requires accounts[1]".into()))?;
        let global_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("BeginUnstake requires accounts[2]".into()))?;
        let reserve_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("BeginUnstake requires accounts[3]".into()))?;
        let unbonding_pk = *ix.accounts.get(4).ok_or_else(|| ExecError::ProgramError("BeginUnstake requires accounts[4]".into()))?;
        if global_pk != STAKING_GLOBAL_ID || reserve_pk != STAKING_RESERVE_ID || unbonding_pk != STAKING_UNBONDING_POOL_ID {
            return Err(ExecError::Unauthorized("BeginUnstake must name the canonical global/reserve/unbonding accounts".into()));
        }
        let mut g = read_global(accounts);
        let index = g.index;
        let mut pos = read_position(accounts, &position_pk).ok_or_else(|| ExecError::ProgramError("no such position".into()))?;
        if pos.owner != *payer {
            return Err(ExecError::Unauthorized("only the position owner can unstake".into()));
        }
        if pos.unbonding_amount > 0 {
            return Err(ExecError::ProgramError("this position already has a pending unbonding chunk - withdraw it first".into()));
        }
        if amount == 0 {
            return Err(ExecError::ProgramError("cannot unstake zero".into()));
        }
        let current_value = position_value(pos.active_shares, index);
        if (amount as u128) > current_value {
            return Err(ExecError::ProgramError("cannot unstake more than the position's current value".into()));
        }
        // Shares to remove for `amount` of value; the value actually removed is
        // recomputed from those shares (floor), so we never move more out of the
        // reserve than the shares we burned represent.
        let shares_to_remove = if (amount as u128) == current_value {
            pos.active_shares
        } else {
            shares_for_deposit(amount, index).min(pos.active_shares)
        };
        let value_removed = position_value(shares_to_remove, index).min(amount as u128) as u64;

        pos.active_shares = pos.active_shares.saturating_sub(shares_to_remove);
        g.total_shares = g.total_shares.saturating_sub(shares_to_remove);
        pos.unbonding_amount = value_removed;
        pos.unbonding_ready_quanto = g.current_quanto.saturating_add(STAKING_UNBONDING_QUANTOS);
        pos.last_modified_quanto = g.current_quanto;
        pos.state = if pos.active_shares > 0 { PositionState::Active } else { PositionState::Unbonding };

        // Move the value out of the reserve into the unbonding pool.
        let reserve_bal = accounts.get(&reserve_pk).map(|a| a.balance).unwrap_or(0);
        if reserve_bal < value_removed {
            return Err(ExecError::ProgramError("staking reserve underfunded (invariant violation)".into()));
        }
        accounts.get_mut(&reserve_pk).unwrap().balance -= value_removed;
        credit(accounts, &unbonding_pk, STAKING_PROGRAM_ID, value_removed);

        write_global(accounts, &g)?;
        write_position(accounts, &position_pk, &pos)?;
        Ok(())
    }

    fn withdraw_unbonded(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey) -> Result<(), ExecError> {
        let staker = *ix.accounts.first().ok_or_else(|| ExecError::ProgramError("WithdrawUnbonded requires accounts[0]".into()))?;
        let position_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("WithdrawUnbonded requires accounts[1]".into()))?;
        let unbonding_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("WithdrawUnbonded requires accounts[2]".into()))?;
        if unbonding_pk != STAKING_UNBONDING_POOL_ID {
            return Err(ExecError::Unauthorized("WithdrawUnbonded must name the canonical unbonding pool".into()));
        }
        let g = read_global(accounts);
        let mut pos = read_position(accounts, &position_pk).ok_or_else(|| ExecError::ProgramError("no such position".into()))?;
        if pos.owner != *payer || staker != *payer {
            return Err(ExecError::Unauthorized("only the position owner can withdraw".into()));
        }
        if pos.unbonding_amount == 0 {
            return Err(ExecError::ProgramError("nothing is unbonding on this position".into()));
        }
        if g.current_quanto < pos.unbonding_ready_quanto {
            return Err(ExecError::ProgramError(format!(
                "still unbonding until quanto {} (now {})",
                pos.unbonding_ready_quanto, g.current_quanto
            )));
        }
        let amount = pos.unbonding_amount;
        let pool_bal = accounts.get(&unbonding_pk).map(|a| a.balance).unwrap_or(0);
        if pool_bal < amount {
            return Err(ExecError::ProgramError("unbonding pool underfunded (invariant violation)".into()));
        }
        accounts.get_mut(&unbonding_pk).unwrap().balance -= amount;
        credit(accounts, &staker, qchain_crypto::Pubkey::system_program_id(), amount);

        pos.unbonding_amount = 0;
        pos.unbonding_ready_quanto = 0;
        pos.last_modified_quanto = g.current_quanto;
        pos.state = if pos.active_shares > 0 { PositionState::Active } else { PositionState::Closed };
        write_position(accounts, &position_pk, &pos)?;
        Ok(())
    }
}

/// Settle the quanto close on the STAKING side (previews Fase 1c so 1b can be
/// verified end-to-end): advance the global index by one quanto's compounding,
/// mint the emission into the reserve, and bump `current_quanto`. **Idempotent
/// per quanto** via `last_settled_quanto`. Deterministic (pure over committed
/// state). Returns the emission minted (0 if nothing staked or already settled).
///
/// `rate_fp` is the genesis-baked per-quanto rate (`economics_v7::derive_quanto_rate_fp`).
pub fn settle_quanto(accounts: &mut HashMap<Pubkey, Account>, closing_quanto: u64, rate_fp: u128) -> Result<u64, ExecError> {
    let mut g = read_global(accounts);
    // Idempotency + ordering: only the currently-accruing quanto can close. Once
    // it does, `current_quanto` advances, so a repeat call with the same
    // `closing_quanto` no longer matches → no-op (never settles a quanto twice,
    // never settles out of order). The node drives this sequentially, closing the
    // quanto that just ended (== the one that was accruing).
    if closing_quanto != g.current_quanto {
        return Ok(0);
    }
    let old_index = g.index;
    let new_index = crate::economics_v7::advance_staking_index(old_index, rate_fp);
    let minted = crate::economics_v7::emission_for_quanto(g.total_shares, old_index, new_index);
    g.index = new_index;
    g.last_settled_quanto = closing_quanto;
    g.current_quanto = closing_quanto.saturating_add(1);
    let minted_u64 = minted.min(u64::MAX as u128) as u64;
    if minted_u64 > 0 {
        credit(accounts, &STAKING_RESERVE_ID, STAKING_PROGRAM_ID, minted_u64);
    }
    write_global(accounts, &g)?;
    Ok(minted_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics_v7::{derive_quanto_rate_fp, DEFAULT_QUANTOS_PER_YEAR, STAKING_TARGET_APY_BPS};
    use qchain_core::UNITS_PER_QCH;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new([b; 32])
    }
    fn wallet(balance: u64) -> Account {
        let mut a = Account::new_wallet(Pubkey::system_program_id());
        a.balance = balance;
        a
    }
    fn ix(data: &StakingV7Instruction, accts: Vec<Pubkey>) -> Instruction {
        Instruction { program_id: STAKING_PROGRAM_ID, accounts: accts, data: borsh::to_vec(data).unwrap() }
    }

    fn reserve_value_invariant(accounts: &HashMap<Pubkey, Account>) {
        // The reserve must always hold AT LEAST the total active position value
        // (never underfunded — everyone can withdraw). A deposit adds exact QCH
        // but mints floor-valued shares, and the aggregate floors once vs the
        // per-position sum flooring N times, so a tiny sub-unit residue can
        // accumulate IN the reserve (an identifiable pool, per SPEC §14). The gap
        // is bounded and negligible (sub-QCH), never a shortfall.
        let g = read_global(accounts);
        let reserve = accounts.get(&STAKING_RESERVE_ID).map(|a| a.balance).unwrap_or(0);
        let total_value = position_value(g.total_shares, g.index) as u64;
        assert!(reserve >= total_value, "reserve underfunded: {reserve} < {total_value}");
        assert!(reserve - total_value < 1000, "reserve residue must stay tiny: {}", reserve - total_value);
    }

    #[test]
    fn stake_mints_shares_and_funds_the_reserve() {
        let staker = pk(50);
        let position = pk(60);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(10 * UNITS_PER_QCH));

        let amount = 5 * UNITS_PER_QCH;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();

        assert_eq!(accounts.get(&staker).unwrap().balance, 5 * UNITS_PER_QCH);
        assert_eq!(accounts.get(&STAKING_RESERVE_ID).unwrap().balance, amount);
        let pos = read_position(&accounts, &position).unwrap();
        // At genesis index, shares == amount and value == amount.
        assert_eq!(pos.active_shares, amount as u128);
        assert_eq!(pos.net_deposited, amount);
        assert_eq!(position_value(pos.active_shares, read_global(&accounts).index), amount as u128);
        reserve_value_invariant(&accounts);
    }

    #[test]
    fn a_year_of_quanto_closes_compounds_the_position_and_reserve_to_12_percent() {
        let staker = pk(50);
        let position = pk(60);
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        let amount = 100 * UNITS_PER_QCH;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();

        // Close one quanto per day for a protocol year.
        for q in 0..DEFAULT_QUANTOS_PER_YEAR {
            let minted = settle_quanto(&mut accounts, q, rate).unwrap();
            assert!(minted > 0, "quanto {q} with real stake mints emission");
            reserve_value_invariant(&accounts); // holds every step (reserve grows with the index)
        }
        let g = read_global(&accounts);
        let pos = read_position(&accounts, &position).unwrap();
        let value = position_value(pos.active_shares, g.index) as u64;
        // ~12% APY, never more; and clearly grown.
        assert!(value <= amount * 112 / 100, "yield exceeded 12%: {value} vs {}", amount);
        assert!(value >= amount * 1119 / 1000, "yield too low: {value}");
        // The reserve backs the grown value exactly.
        assert_eq!(accounts.get(&STAKING_RESERVE_ID).unwrap().balance, value);
    }

    #[test]
    fn settle_quanto_is_idempotent() {
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let staker = pk(50);
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: 100 * UNITS_PER_QCH }, vec![staker, pk(60), STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let m1 = settle_quanto(&mut accounts, 0, rate).unwrap();
        let idx1 = read_global(&accounts).index;
        // Re-settling the SAME quanto mints nothing and doesn't move the index.
        let m2 = settle_quanto(&mut accounts, 0, rate).unwrap();
        assert_eq!(m2, 0, "re-settling the same quanto mints nothing");
        assert_eq!(read_global(&accounts).index, idx1, "index unchanged on repeat");
        assert!(m1 > 0);
    }

    #[test]
    fn increase_after_growth_mints_fewer_shares() {
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let staker = pk(50);
        let position = pk(60);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(200 * UNITS_PER_QCH));
        let amount = 100 * UNITS_PER_QCH;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let shares0 = read_position(&accounts, &position).unwrap().active_shares;
        // Grow the index a full year, then add the same principal again.
        for q in 0..DEFAULT_QUANTOS_PER_YEAR {
            settle_quanto(&mut accounts, q, rate).unwrap();
        }
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::IncreaseStake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let pos = read_position(&accounts, &position).unwrap();
        let added_shares = pos.active_shares - shares0;
        assert!(added_shares < shares0, "the same principal mints fewer shares once the index grew");
        assert_eq!(pos.net_deposited, 2 * amount);
        reserve_value_invariant(&accounts);
    }

    #[test]
    fn begin_unstake_then_withdraw_after_the_window_pays_out() {
        let staker = pk(50);
        let position = pk(60);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        let amount = 40 * UNITS_PER_QCH;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();

        // Unstake half.
        let half = 20 * UNITS_PER_QCH;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::BeginUnstake { amount: half }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID]), &staker).unwrap();
        assert_eq!(accounts.get(&STAKING_UNBONDING_POOL_ID).unwrap().balance, half);
        assert_eq!(accounts.get(&STAKING_RESERVE_ID).unwrap().balance, amount - half);
        reserve_value_invariant(&accounts);

        // Withdraw before the window closes → rejected.
        let e = StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::WithdrawUnbonded, vec![staker, position, STAKING_UNBONDING_POOL_ID]), &staker);
        assert!(e.is_err(), "cannot withdraw before the unbonding window elapses");

        // Advance a quanto (settle) so current_quanto reaches the ready quanto.
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        settle_quanto(&mut accounts, 0, rate).unwrap(); // current_quanto -> 1 >= ready (0+1)
        let before = accounts.get(&staker).unwrap().balance;
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::WithdrawUnbonded, vec![staker, position, STAKING_UNBONDING_POOL_ID]), &staker).unwrap();
        assert_eq!(accounts.get(&staker).unwrap().balance, before + half, "the unbonded funds are paid out");
        assert_eq!(accounts.get(&STAKING_UNBONDING_POOL_ID).unwrap().balance, 0);
        // Still has the other half active.
        assert_eq!(read_position(&accounts, &position).unwrap().state, PositionState::Active);
    }

    #[test]
    fn auth_and_pin_checks() {
        let staker = pk(50);
        let attacker = pk(51);
        let position = pk(60);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        accounts.insert(attacker, wallet(100 * UNITS_PER_QCH));
        // Wrong global singleton → rejected.
        let bad = StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, pk(99), STAKING_RESERVE_ID]), &staker);
        assert!(bad.is_err());
        // funding account != payer → rejected.
        let bad2 = StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &attacker);
        assert!(bad2.is_err());
        // Open a real position, then attacker tries to unstake it → rejected.
        StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let bad3 = StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::BeginUnstake { amount: UNITS_PER_QCH }, vec![attacker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID]), &attacker);
        assert!(bad3.is_err(), "only the owner can unstake");
    }

    #[test]
    fn differential_o1_total_matches_on_sum_of_positions() {
        // The O(1) global total_shares/index must agree with an O(N) sum over
        // every position — the core property the full DST (1f) will assert.
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let positions: Vec<Pubkey> = (0..5).map(|i| pk(100 + i)).collect();
        for (i, p) in positions.iter().enumerate() {
            let staker = pk(60 + i as u8);
            accounts.insert(staker, wallet(1000 * UNITS_PER_QCH));
            let amt = (i as u64 + 1) * 10 * UNITS_PER_QCH;
            StakingV7Program::process(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: amt }, vec![staker, *p, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        }
        // Some quantos pass.
        for q in 0..30 {
            settle_quanto(&mut accounts, q, rate).unwrap();
        }
        let g = read_global(&accounts);
        let o1_total = position_value(g.total_shares, g.index);
        let o_n_total: u128 = positions.iter().map(|p| position_value(read_position(&accounts, p).unwrap().active_shares, g.index)).sum();
        // Aggregate (floor once) ≥ per-position sum (floor N times); the gap is a
        // sub-unit rounding residue bounded by the position count. This is the
        // core O(1)-vs-O(N) agreement the full DST (1f) will assert.
        assert!(o1_total >= o_n_total, "aggregate must cover the per-position sum");
        assert!(o1_total - o_n_total < positions.len() as u128, "the O(1)/O(N) gap is at most a sub-unit per position");
        // The reserve covers every position's withdrawable value.
        let reserve = accounts.get(&STAKING_RESERVE_ID).unwrap().balance as u128;
        assert!(reserve >= o_n_total, "reserve must cover all withdrawals");
        assert!(reserve >= o1_total, "reserve backs at least the aggregate value");
    }
}
