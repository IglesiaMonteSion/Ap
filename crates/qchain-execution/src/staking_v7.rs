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
    /// The genesis-baked per-quanto compounding rate (`quanto_rate_fp`). Stored
    /// here so `stake()` can price a fresh deposit's shares at the NEXT quanto's
    /// index (`advance_staking_index`) — deposits earn from the next quanto, not
    /// the partial one they joined during (epoch-aligned activation).
    pub rate_fp: u128,
    /// Shares deposited during the CURRENTLY-accruing quanto that are NOT yet
    /// earning. They activate (fold into `total_shares`) at the next quanto close,
    /// AFTER that quanto's emission is computed — so a deposit never collects the
    /// reward of the quanto it joined during. O(1): one accumulator, no per-position
    /// iteration at the close.
    pub pending_shares: u128,
}

impl GlobalStakingState {
    /// The genesis state: index at 1.0, nothing staked, quanto 0. `rate_fp` unset
    /// (0) — use `genesis_with_rate` when seeding a real network so `stake()` can
    /// align activation.
    pub fn genesis() -> Self {
        GlobalStakingState { index: INITIAL_STAKING_INDEX, total_shares: 0, current_quanto: 0, last_settled_quanto: 0, rate_fp: 0, pending_shares: 0 }
    }

    /// Genesis state carrying the network's per-quanto rate, so a fresh deposit's
    /// shares are priced at the next quanto's index (epoch-aligned activation).
    pub fn genesis_with_rate(rate_fp: u128) -> Self {
        GlobalStakingState { rate_fp, ..Self::genesis() }
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
    /// Shares from a deposit made during the current quanto that are NOT yet
    /// earning (epoch-aligned activation). Priced at the NEXT quanto's index, so
    /// once they activate their value is exactly the principal (no reward for the
    /// partial join quanto). 0 = none.
    pub pending_shares: u128,
    /// Principal (atoms) behind `pending_shares` — shown at face value while the
    /// deposit is still in its join quanto (so a just-made deposit never displays
    /// below what was put in, and can be cancelled without loss).
    pub pending_amount: u64,
    /// Quanto at which `pending_shares` start earning (= join quanto + 1). Once
    /// `current_quanto >= this`, the pending folds into `active_shares`. 0 = none.
    pub pending_activation_quanto: u64,
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
    match accounts.get(&STAKING_GLOBAL_ID) {
        // Not in the working set → genesis (a v7 network always seeds it, so this
        // is only the pre-seed / not-yet-created case).
        None => GlobalStakingState::genesis(),
        // Present but undecodable is NOT a recoverable state: it means corrupted or
        // version-skewed staking bytes (e.g. a new binary reading a pre-6.3.31 v7
        // `data_dir`). Silently falling back to `genesis()` would ZERO all staking
        // (total_shares=0, rate_fp=0) — value-destroying and, worse, would let a
        // deposit collect its join-quanto reward unbacked (rate_fp=0 vs the real
        // settle rate). Refuse to run instead (same fail-loud philosophy as the
        // SledStore corruption guard); the fresh-v7-genesis + same-binary deployment
        // never hits this.
        Some(a) => GlobalStakingState::try_from_slice(&a.data).unwrap_or_else(|e| {
            panic!("STAKING_GLOBAL is present but does not decode ({e}); refusing to run on corrupted/version-skewed staking state (a v7 binary needs a fresh v7 genesis — see the v6.3.31 deploy note)")
        }),
    }
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

/// Read the global staking state from a working set (or `genesis()` if absent).
/// Public so the ledger's quanto-close hook can read `current_quanto`.
pub fn global_state(accounts: &HashMap<Pubkey, Account>) -> GlobalStakingState {
    read_global(accounts)
}

/// Fold a position's activated pending deposit into its earning shares. A deposit
/// made during quanto `Q` is pending until `Q+1` starts; once `current_quanto`
/// reaches `pending_activation_quanto` the pending shares were already added to
/// the global `total_shares` (at that quanto's close, in `settle_quanto`), so
/// here we only move the position's own bookkeeping — never touching the global —
/// keeping `Σ position shares == total_shares`. Idempotent (no-op if nothing
/// pending or not yet activated). Call at the start of any position mutation.
pub fn settle_position(pos: &mut StakePositionV7, g: &GlobalStakingState) {
    if pos.pending_shares > 0 && g.current_quanto >= pos.pending_activation_quanto {
        pos.active_shares = pos.active_shares.saturating_add(pos.pending_shares);
        pos.pending_shares = 0;
        pos.pending_amount = 0;
        pos.pending_activation_quanto = 0;
    }
}

/// A position's current worth (atoms): its earning value, plus any pending
/// deposit — valued by the live index once activated, or at face (the deposited
/// principal) while still in its join quanto so a fresh deposit never shows below
/// what was put in. This is what the wallet displays and what a withdrawal frees.
pub fn position_current_value(pos: &StakePositionV7, g: &GlobalStakingState) -> u128 {
    let active = crate::economics_v7::position_value(pos.active_shares, g.index);
    let pending = if pos.pending_shares > 0 {
        if g.current_quanto >= pos.pending_activation_quanto {
            crate::economics_v7::position_value(pos.pending_shares, g.index)
        } else {
            pos.pending_amount as u128
        }
    } else {
        0
    };
    active.saturating_add(pending)
}

/// True while a position has a deposit that hasn't started earning yet (still in
/// its join quanto). The wallet shows this as "Activándose" and defers the reward
/// progress bar to the next quanto.
pub fn is_activating(pos: &StakePositionV7, g: &GlobalStakingState) -> bool {
    pos.pending_shares > 0 && g.current_quanto < pos.pending_activation_quanto
}

/// Record a mid-quanto deposit as PENDING: its shares are priced at the NEXT
/// quanto's index (`advance_staking_index`), so once they activate the position's
/// value is exactly the principal — the deposit earns from the next quanto, never
/// the partial one it joined during (epoch-aligned activation, the fairness fix).
/// Same-quanto deposits accumulate into the single pending chunk. Returns the
/// shares that were added (the caller adds them to the GLOBAL `pending_shares`).
fn add_pending_deposit(pos: &mut StakePositionV7, g: &GlobalStakingState, amount: u64) -> u128 {
    let activation_index = crate::economics_v7::advance_staking_index(g.index, g.rate_fp);
    let shares = shares_for_deposit(amount, activation_index);
    pos.pending_shares = pos.pending_shares.saturating_add(shares);
    pos.pending_amount = pos.pending_amount.saturating_add(amount);
    pos.pending_activation_quanto = g.current_quanto.saturating_add(1);
    pos.net_deposited = pos.net_deposited.saturating_add(amount);
    shares
}

impl crate::native::NativeProgram for StakingV7Program {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, _current_round: qchain_core::Round) -> Result<(), ExecError> {
        // v7 staking has no notion of "round" — its clock is the quanto, read
        // from the global state — so `current_round` is ignored.
        StakingV7Program::execute(accounts, instruction, payer)
    }
}

impl StakingV7Program {
    /// Apply a v7 staking instruction to the working set. Pure over `accounts`
    /// (+ the pinned singletons), same contract as `StakingProgram::process`.
    pub fn execute(accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey) -> Result<(), ExecError> {
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
            // Fold any prior pending that has since activated into the earning
            // shares, then record THIS deposit as pending for the current quanto
            // (it starts earning next quanto — the added principal doesn't collect
            // the partial join quanto's reward either).
            settle_position(&mut pos, &g);
            accounts.get_mut(&staker).unwrap().balance -= amount;
            let added = add_pending_deposit(&mut pos, &g, amount);
            g.pending_shares = g.pending_shares.saturating_add(added);
            pos.last_modified_quanto = g.current_quanto;
            pos.state = PositionState::Active;
            credit(accounts, &reserve_pk, STAKING_PROGRAM_ID, amount);
            write_global(accounts, &g)?;
            write_position(accounts, &position_pk, &pos)?;
        } else {
            if existing.is_some() {
                return Err(ExecError::ProgramError("position account already exists - Stake opens a fresh one".into()));
            }
            // SECURITY (pre-launch audit): `write_position` is a BLIND overwrite
            // (sets balance=0, owner=STAKING_PROGRAM_ID, data=<position>). Without
            // this guard, a 1-unit Stake naming ANY occupied account as accounts[1]
            // — a user wallet, the reserve, the bond escrow, any pool, the global
            // singleton — would wipe it (its `data` doesn't decode as a position, so
            // `existing` is None and the check above passes). A fresh position must
            // therefore be a genuinely NEW/EMPTY, system-owned account (never seen,
            // so the ledger left it absent from the working set — or present only as
            // an empty system wallet), never a protocol singleton, and never the
            // payer's own funding wallet. This is the Solana "account being created
            // must be empty" rule; `IncreaseStake`/`BeginUnstake`/`WithdrawUnbonded`
            // are unaffected (they require a pre-existing valid position).
            if position_pk == *payer {
                return Err(ExecError::Unauthorized("the staking position must be a fresh account, not the payer's wallet".into()));
            }
            const RESERVED: [Pubkey; 8] = [
                STAKING_GLOBAL_ID,
                STAKING_RESERVE_ID,
                STAKING_UNBONDING_POOL_ID,
                crate::ids::VALIDATOR_BOND_ESCROW_ID,
                crate::ids::VALIDATOR_UNBONDING_POOL_ID,
                crate::ids::VALIDATOR_FEE_POOL_ID,
                crate::ids::VALIDATOR_REGISTRY_ACCOUNT_ID,
                crate::ids::STAKING_STATS_ID,
            ];
            if RESERVED.contains(&position_pk) {
                return Err(ExecError::Unauthorized("the staking position must not be a protocol singleton account".into()));
            }
            if let Some(occupied) = accounts.get(&position_pk) {
                if occupied.balance != 0 || !occupied.data.is_empty() || occupied.owner != Pubkey::system_program_id() {
                    return Err(ExecError::Unauthorized("Stake opens a FRESH position — the named account is already in use".into()));
                }
            }
            let staker_balance = accounts.get(&staker).ok_or(ExecError::AccountNotFound(staker))?.balance;
            if staker_balance < amount {
                return Err(ExecError::InsufficientFunds);
            }
            accounts.get_mut(&staker).unwrap().balance -= amount;
            let mut pos = StakePositionV7 {
                owner: staker,
                active_shares: 0,
                created_quanto: g.current_quanto,
                last_modified_quanto: g.current_quanto,
                net_deposited: 0,
                unbonding_amount: 0,
                unbonding_ready_quanto: 0,
                state: PositionState::Active,
                pending_shares: 0,
                pending_amount: 0,
                pending_activation_quanto: 0,
            };
            // A fresh deposit is PENDING: it starts earning next quanto, so it
            // never collects the reward of the partial quanto it joined during.
            let added = add_pending_deposit(&mut pos, &g, amount);
            g.pending_shares = g.pending_shares.saturating_add(added);
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
        // Fold any activated pending into the earning shares first.
        settle_position(&mut pos, &g);
        // What the owner can pull out: the earning value, plus any deposit still in
        // its join quanto (at face — it never earned, and cancelling it must never
        // lose principal). The still-pending shares were never in `total_shares`,
        // so cancelling them only decrements the global `pending_shares` accumulator.
        let active_value = position_value(pos.active_shares, index);
        let pending_face = pos.pending_amount as u128; // 0 unless a deposit is still in its join quanto
        let available = active_value.saturating_add(pending_face);
        if (amount as u128) > available {
            return Err(ExecError::ProgramError("cannot unstake more than the position's current value".into()));
        }
        // Take from the active (earning) shares first; value actually removed is
        // recomputed from those shares (floor), so we never move more out of the
        // reserve than the burned shares represent.
        let take_active = (amount as u128).min(active_value);
        let shares_to_remove = if take_active == active_value {
            pos.active_shares
        } else {
            shares_for_deposit(take_active as u64, index).min(pos.active_shares)
        };
        let active_removed = position_value(shares_to_remove, index).min(take_active) as u64;
        pos.active_shares = pos.active_shares.saturating_sub(shares_to_remove);
        g.total_shares = g.total_shares.saturating_sub(shares_to_remove);
        // Any remainder comes from the still-pending (join-quanto) chunk at face.
        let mut pending_removed = 0u64;
        let remaining = amount.saturating_sub(active_removed);
        if remaining > 0 && pos.pending_amount > 0 {
            let take = remaining.min(pos.pending_amount);
            let ps_remove = if take == pos.pending_amount {
                pos.pending_shares
            } else {
                pos.pending_shares.saturating_mul(take as u128) / (pos.pending_amount as u128)
            };
            pos.pending_shares = pos.pending_shares.saturating_sub(ps_remove);
            pos.pending_amount = pos.pending_amount.saturating_sub(take);
            g.pending_shares = g.pending_shares.saturating_sub(ps_remove);
            if pos.pending_amount == 0 {
                pos.pending_activation_quanto = 0;
            }
            pending_removed = take;
        }
        let value_removed = active_removed.saturating_add(pending_removed);
        pos.unbonding_amount = value_removed;
        pos.unbonding_ready_quanto = g.current_quanto.saturating_add(STAKING_UNBONDING_QUANTOS);
        pos.last_modified_quanto = g.current_quanto;
        pos.state = if pos.active_shares > 0 || pos.pending_shares > 0 { PositionState::Active } else { PositionState::Unbonding };

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
        // The global staking account MUST be named (accounts[3]) and pinned:
        // `read_global` reads it from the working set, and the ledger only loads
        // DECLARED accounts. Without it, `read_global` silently falls back to
        // `genesis()` (current_quanto=0), so the maturity check `0 < ready` is
        // always true and EVERY legitimate withdrawal is rejected forever
        // (fails safe — no theft — but broken). Pre-launch audit fix.
        let global_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("WithdrawUnbonded requires accounts[3] (the global staking account)".into()))?;
        if unbonding_pk != STAKING_UNBONDING_POOL_ID {
            return Err(ExecError::Unauthorized("WithdrawUnbonded must name the canonical unbonding pool".into()));
        }
        if global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("WithdrawUnbonded must name the canonical global staking account".into()));
        }
        let g = read_global(accounts);
        let mut pos = read_position(accounts, &position_pk).ok_or_else(|| ExecError::ProgramError("no such position".into()))?;
        if pos.owner != *payer || staker != *payer {
            return Err(ExecError::Unauthorized("only the position owner can withdraw".into()));
        }
        // Fold any activated pending into the earning shares (keeps the position's
        // active/pending bookkeeping current; global total_shares already updated).
        settle_position(&mut pos, &g);
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
        pos.state = if pos.active_shares > 0 || pos.pending_shares > 0 { PositionState::Active } else { PositionState::Closed };
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
/// The compounding rate is read from `g.rate_fp` (the genesis-baked per-quanto
/// rate, `economics_v7::derive_quanto_rate_fp`). This is the SINGLE SOURCE OF
/// TRUTH: `stake()`/`add_pending_deposit` price a pending deposit's shares at
/// `advance_staking_index(g.index, g.rate_fp)`, and this function advances the
/// live index with the SAME `g.rate_fp` — so pricing and advancing provably use
/// one number, and a late-joining deposit's activation index matches the index
/// it was priced at exactly (never over/under-funded). Taking the rate from a
/// caller-supplied parameter risked a divergence where a deposit could collect a
/// join-quanto reward unbacked by emission (auditor finding, closed here).
pub fn settle_quanto(accounts: &mut HashMap<Pubkey, Account>, closing_quanto: u64) -> Result<u64, ExecError> {
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
    let new_index = crate::economics_v7::advance_staking_index(old_index, g.rate_fp);
    // Emission for the CLOSING quanto is computed on the shares that were EARNING
    // during it — i.e. BEFORE folding in this quanto's pending deposits, so a
    // deposit made during the closing quanto never collects its reward.
    let minted = crate::economics_v7::emission_for_quanto(g.total_shares, old_index, new_index);
    g.index = new_index;
    g.last_settled_quanto = closing_quanto;
    g.current_quanto = closing_quanto.saturating_add(1);
    // Now ACTIVATE the deposits that were pending during the quanto that just
    // closed: they start earning from the next quanto. Their shares were priced at
    // this `new_index` (`advance` of the deposit-quanto index) — so at this index
    // each is worth exactly its principal, and they compound from here.
    g.total_shares = g.total_shares.saturating_add(g.pending_shares);
    g.pending_shares = 0;
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

    #[test]
    fn staking_v7_instruction_encoding_is_stable() {
        // The WASM wallet (crates/qchain-wasm) hand-rolls these encodings to sign
        // v7 staking without depending on this crate. If the enum ever changes,
        // this guard fails so the wallet's signV7* helpers are updated in the
        // same batch (the lesson from v3.0.4: a stale wasm artifact silently
        // produces txs the node rejects).
        let amount = 0x0102_0304_0506_0708u64;
        let mk = |disc: u8| {
            let mut v = vec![disc];
            v.extend_from_slice(&amount.to_le_bytes());
            v
        };
        assert_eq!(borsh::to_vec(&StakingV7Instruction::Stake { amount }).unwrap(), mk(0), "wasm v7 Stake encoding out of sync");
        assert_eq!(borsh::to_vec(&StakingV7Instruction::IncreaseStake { amount }).unwrap(), mk(1), "wasm v7 IncreaseStake encoding out of sync");
        assert_eq!(borsh::to_vec(&StakingV7Instruction::BeginUnstake { amount }).unwrap(), mk(2), "wasm v7 BeginUnstake encoding out of sync");
        assert_eq!(borsh::to_vec(&StakingV7Instruction::WithdrawUnbonded).unwrap(), vec![3u8], "wasm v7 WithdrawUnbonded encoding out of sync");
    }

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

    /// Seed the global staking singleton carrying the per-quanto `rate`, so
    /// `stake()` prices a fresh deposit at the NEXT quanto's index (epoch-aligned
    /// activation). Unit tests build accounts by hand, so they must seed this.
    fn seed_global(accounts: &mut HashMap<Pubkey, Account>, rate: u128) {
        let mut a = Account::new_wallet(STAKING_PROGRAM_ID);
        a.data = borsh::to_vec(&GlobalStakingState::genesis_with_rate(rate)).unwrap();
        accounts.insert(STAKING_GLOBAL_ID, a);
    }

    fn reserve_value_invariant(accounts: &HashMap<Pubkey, Account>) {
        // The reserve must always hold AT LEAST what backs every position: the
        // active (earning) value PLUS the principal of any deposit still pending
        // activation (waiting for its next-quanto start). A deposit adds exact QCH
        // but mints floor-valued shares, so a tiny sub-unit residue can accumulate
        // IN the reserve (an identifiable pool, per SPEC §14) — bounded, never a
        // shortfall. `pending_shares` were priced at `advance(index)`, so valuing
        // them there recovers the deposited principal held in the reserve.
        let g = read_global(accounts);
        let reserve = accounts.get(&STAKING_RESERVE_ID).map(|a| a.balance).unwrap_or(0);
        let active = position_value(g.total_shares, g.index) as u64;
        let pending_principal =
            position_value(g.pending_shares, crate::economics_v7::advance_staking_index(g.index, g.rate_fp)) as u64;
        let backed = active.saturating_add(pending_principal);
        assert!(reserve >= backed, "reserve underfunded: {reserve} < {backed}");
        assert!(reserve - backed < 1000, "reserve residue must stay tiny: {}", reserve - backed);
    }

    #[test]
    fn a_fresh_deposit_is_pending_and_earns_from_the_next_quanto_not_the_join_one() {
        let staker = pk(50);
        let position = pk(60);
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(10 * UNITS_PER_QCH));
        seed_global(&mut accounts, rate);

        let amount = 5 * UNITS_PER_QCH;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();

        assert_eq!(accounts.get(&staker).unwrap().balance, 5 * UNITS_PER_QCH);
        assert_eq!(accounts.get(&STAKING_RESERVE_ID).unwrap().balance, amount, "principal is in the reserve immediately");
        let g0 = read_global(&accounts);
        let pos = read_position(&accounts, &position).unwrap();
        // The deposit is PENDING (not earning yet), shown at face during the join quanto.
        assert_eq!(pos.active_shares, 0, "a fresh deposit does not earn its join quanto");
        assert!(pos.pending_shares > 0, "the deposit is held as pending shares");
        assert_eq!(pos.pending_amount, amount);
        assert_eq!(pos.net_deposited, amount);
        assert!(is_activating(&pos, &g0), "still activating during the join quanto");
        assert_eq!(position_current_value(&pos, &g0), amount as u128, "shown at exactly the principal (never below) while activating");
        reserve_value_invariant(&accounts);

        // Close the join quanto (0): the deposit activates. Emission for quanto 0 is
        // ZERO (nobody was earning), so the position is worth EXACTLY its principal —
        // it did NOT collect the reward of the partial quanto it joined during.
        let minted0 = settle_quanto(&mut accounts, 0).unwrap();
        assert_eq!(minted0, 0, "no emission for the join quanto — the deposit wasn't earning yet");
        let g1 = read_global(&accounts);
        let pos1 = read_position(&accounts, &position).unwrap();
        assert!(!is_activating(&pos1, &g1), "now active");
        // Worth the principal (modulo a sub-unit floor residue) — NOT the principal
        // plus a quanto's reward, which the old immediate-activation model gave.
        let v1 = position_current_value(&pos1, &g1);
        assert!(v1 <= amount as u128 && v1 + 10 >= amount as u128, "worth ~principal, no join-quanto reward: {v1} vs {amount}");
        reserve_value_invariant(&accounts);

        // Close the NEXT quanto (1): NOW it earns.
        let minted1 = settle_quanto(&mut accounts, 1).unwrap();
        assert!(minted1 > 0, "the activated deposit earns from the next quanto");
        let g2 = read_global(&accounts);
        assert!(position_current_value(&pos1, &g2) > amount as u128, "value grew once actually earning");
        reserve_value_invariant(&accounts);
    }

    #[test]
    fn a_year_of_quanto_closes_compounds_the_position_and_reserve_to_12_percent() {
        let staker = pk(50);
        let position = pk(60);
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        seed_global(&mut accounts, rate);
        let amount = 100 * UNITS_PER_QCH;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();

        // Close one quanto per day for a protocol year. Quanto 0 (the join quanto)
        // mints nothing (the deposit wasn't earning yet); every quanto after does.
        for q in 0..DEFAULT_QUANTOS_PER_YEAR {
            let minted = settle_quanto(&mut accounts, q).unwrap();
            if q == 0 {
                assert_eq!(minted, 0, "the join quanto mints no reward for the just-made deposit");
            } else {
                assert!(minted > 0, "quanto {q} with an active stake mints emission");
            }
            reserve_value_invariant(&accounts); // holds every step (reserve grows with the index)
        }
        let g = read_global(&accounts);
        let pos = read_position(&accounts, &position).unwrap();
        // Value includes the (now activated) deposit; the deposit earned every
        // quanto EXCEPT its join quanto, so ~12% APY, never more, and clearly grown.
        let value = position_current_value(&pos, &g) as u64;
        assert!(value <= amount * 112 / 100, "yield exceeded 12%: {value} vs {}", amount);
        assert!(value >= amount * 1118 / 1000, "yield too low: {value}");
        // The reserve backs the grown value (modulo a sub-unit floor residue).
        let reserve = accounts.get(&STAKING_RESERVE_ID).unwrap().balance;
        assert!(reserve >= value && reserve - value < 1000, "reserve backs the value: {reserve} vs {value}");
    }

    #[test]
    fn settle_quanto_is_idempotent() {
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        let staker = pk(50);
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        seed_global(&mut accounts, rate);
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: 100 * UNITS_PER_QCH }, vec![staker, pk(60), STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        settle_quanto(&mut accounts, 0).unwrap(); // close the join quanto → the deposit activates
        // Quanto 1 is the first the deposit earns: it mints, and re-settling it is a no-op.
        let m1 = settle_quanto(&mut accounts, 1).unwrap();
        let idx1 = read_global(&accounts).index;
        let m2 = settle_quanto(&mut accounts, 1).unwrap();
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
        seed_global(&mut accounts, rate);
        let amount = 100 * UNITS_PER_QCH;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let shares0 = read_position(&accounts, &position).unwrap().pending_shares; // the initial deposit's shares
        assert!(shares0 > 0);
        // Grow the index a full year (the initial deposit activates at quanto 1's close).
        for q in 0..DEFAULT_QUANTOS_PER_YEAR {
            settle_quanto(&mut accounts, q).unwrap();
        }
        // Add the same principal again: the prior (activated) deposit folds into
        // active shares, and the NEW deposit is pending — priced at the now-higher
        // index, so it mints FEWER shares for the same principal.
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::IncreaseStake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let pos = read_position(&accounts, &position).unwrap();
        assert_eq!(pos.active_shares, shares0, "the first deposit's shares folded into active");
        assert!(pos.pending_shares < shares0, "the same principal mints fewer shares once the index grew");
        assert_eq!(pos.net_deposited, 2 * amount);
        reserve_value_invariant(&accounts);
    }

    #[test]
    fn begin_unstake_then_withdraw_after_the_window_pays_out() {
        let staker = pk(50);
        let position = pk(60);
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(staker, wallet(100 * UNITS_PER_QCH));
        seed_global(&mut accounts, rate);
        let amount = 40 * UNITS_PER_QCH;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        // Activate the deposit (close its join quanto → current_quanto = 1).
        settle_quanto(&mut accounts, 0).unwrap();

        // Unstake half of the now-active position.
        let half = 20 * UNITS_PER_QCH;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::BeginUnstake { amount: half }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID]), &staker).unwrap();
        let unb = accounts.get(&STAKING_UNBONDING_POOL_ID).unwrap().balance;
        assert!(unb <= half && unb + 10 >= half, "~half moved to unbonding (floor residue): {unb} vs {half}");
        let reserve = accounts.get(&STAKING_RESERVE_ID).unwrap().balance;
        assert!(reserve >= amount - half && reserve <= amount - half + 10, "~half left in reserve: {reserve}");
        reserve_value_invariant(&accounts);

        // Withdraw before the window closes → rejected.
        let e = StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::WithdrawUnbonded, vec![staker, position, STAKING_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &staker);
        assert!(e.is_err(), "cannot withdraw before the unbonding window elapses");

        // Advance a quanto so current_quanto reaches the ready quanto (unstake was at
        // quanto 1 → ready = 2).
        settle_quanto(&mut accounts, 1).unwrap(); // current_quanto -> 2 >= ready (1+1)
        let before = accounts.get(&staker).unwrap().balance;
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::WithdrawUnbonded, vec![staker, position, STAKING_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &staker).unwrap();
        let paid = accounts.get(&staker).unwrap().balance - before;
        assert!(paid <= half && paid + 10 >= half, "the unbonded funds are paid out (~half): {paid}");
        assert_eq!(accounts.get(&STAKING_UNBONDING_POOL_ID).unwrap().balance, 0);
        // Still has the other half active.
        assert_eq!(read_position(&accounts, &position).unwrap().state, PositionState::Active);
    }

    /// SECURITY REGRESSION (pre-launch audit): a fresh-open `Stake` must NOT be
    /// able to name an OCCUPIED account (a user wallet, a pool, a singleton) as
    /// its position and thereby wipe it (`write_position` blindly overwrites
    /// balance/owner/data). The guard rejects it and the victim is untouched.
    #[test]
    fn stake_cannot_wipe_an_occupied_account_or_a_singleton() {
        let attacker = pk(70);
        let victim = pk(71);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        accounts.insert(attacker, wallet(100 * UNITS_PER_QCH));
        accounts.insert(victim, wallet(50 * UNITS_PER_QCH)); // a real user wallet with funds

        // Attack: Stake 1 unit naming the victim wallet as the position account.
        let e = StakingV7Program::execute(
            &mut accounts,
            &ix(&StakingV7Instruction::Stake { amount: 1 }, vec![attacker, victim, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]),
            &attacker,
        );
        assert!(e.is_err(), "Stake onto an occupied wallet must be rejected");
        assert_eq!(accounts.get(&victim).unwrap().balance, 50 * UNITS_PER_QCH, "victim balance untouched");
        assert_eq!(accounts.get(&victim).unwrap().owner, Pubkey::system_program_id(), "victim owner untouched");

        // Attack: name a protocol singleton (the reserve) as the position.
        accounts.insert(STAKING_RESERVE_ID, {
            let mut a = Account::new_wallet(STAKING_PROGRAM_ID);
            a.balance = 999;
            a
        });
        let e2 = StakingV7Program::execute(
            &mut accounts,
            &ix(&StakingV7Instruction::Stake { amount: 1 }, vec![attacker, STAKING_RESERVE_ID, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]),
            &attacker,
        );
        assert!(e2.is_err(), "Stake onto a singleton (the reserve) must be rejected");
        assert_eq!(accounts.get(&STAKING_RESERVE_ID).unwrap().balance, 999, "reserve untouched");

        // A genuinely fresh position (never-seen address, absent from the set) still works.
        let fresh = pk(72);
        StakingV7Program::execute(
            &mut accounts,
            &ix(&StakingV7Instruction::Stake { amount: 10 * UNITS_PER_QCH }, vec![attacker, fresh, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]),
            &attacker,
        )
        .unwrap();
        assert!(read_position(&accounts, &fresh).is_some(), "a fresh position opens normally");
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
        let bad = StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, pk(99), STAKING_RESERVE_ID]), &staker);
        assert!(bad.is_err());
        // funding account != payer → rejected.
        let bad2 = StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &attacker);
        assert!(bad2.is_err());
        // Open a real position, then attacker tries to unstake it → rejected.
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: UNITS_PER_QCH }, vec![staker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        let bad3 = StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::BeginUnstake { amount: UNITS_PER_QCH }, vec![attacker, position, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID]), &attacker);
        assert!(bad3.is_err(), "only the owner can unstake");
    }

    /// THE FAIRNESS FIX (epoch-aligned activation): a deposit made LATE in a quanto
    /// must NOT collect that quanto's full reward — it earns from the next quanto,
    /// same as one that was staked since the quanto began. Two stakers put in the
    /// same amount in the SAME quanto (one "early", one "late" — indistinguishable
    /// on-chain since the index is flat within a quanto): after the quanto closes,
    /// both are worth exactly their principal (neither earned it), and both earn
    /// equally from the next quanto. Before the fix, both would have collected the
    /// full quanto reward for a partial stake.
    #[test]
    fn a_late_join_does_not_collect_the_quanto_reward_and_earns_equally_next_quanto() {
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        seed_global(&mut accounts, rate);
        let (early, late) = (pk(50), pk(51));
        let (pe, pl) = (pk(60), pk(61));
        accounts.insert(early, wallet(100 * UNITS_PER_QCH));
        accounts.insert(late, wallet(100 * UNITS_PER_QCH));
        let amount = 50 * UNITS_PER_QCH;
        // Both stake the same amount during quanto 0 (the index is flat within a
        // quanto, so "early" and "late" in the same quanto are identical on-chain).
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![early, pe, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &early).unwrap();
        StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount }, vec![late, pl, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &late).unwrap();

        // Close quanto 0: NEITHER earns it (they weren't active during it).
        assert_eq!(settle_quanto(&mut accounts, 0).unwrap(), 0, "no reward is paid for the join quanto");
        let g1 = read_global(&accounts);
        let (v_e1, v_l1) = (
            position_current_value(&read_position(&accounts, &pe).unwrap(), &g1),
            position_current_value(&read_position(&accounts, &pl).unwrap(), &g1),
        );
        assert!(v_e1 <= amount as u128 && v_e1 + 10 >= amount as u128, "worth ~principal, no join-quanto reward: {v_e1}");
        assert_eq!(v_e1, v_l1, "both stakers are worth the same (neither got a free quanto)");

        // Close quanto 1: NOW both earn, equally.
        assert!(settle_quanto(&mut accounts, 1).unwrap() > 0);
        let g2 = read_global(&accounts);
        let (v_e2, v_l2) = (
            position_current_value(&read_position(&accounts, &pe).unwrap(), &g2),
            position_current_value(&read_position(&accounts, &pl).unwrap(), &g2),
        );
        assert!(v_e2 > amount as u128, "both now earn from the next quanto");
        assert_eq!(v_e2, v_l2, "both earn equally");
    }

    #[test]
    fn differential_o1_total_matches_on_sum_of_positions() {
        // The O(1) global total_shares/index must agree with an O(N) sum over
        // every position — the core property the full DST (1f) will assert.
        let rate = derive_quanto_rate_fp(STAKING_TARGET_APY_BPS, DEFAULT_QUANTOS_PER_YEAR);
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        seed_global(&mut accounts, rate);
        let positions: Vec<Pubkey> = (0..5).map(|i| pk(100 + i)).collect();
        for (i, p) in positions.iter().enumerate() {
            let staker = pk(60 + i as u8);
            accounts.insert(staker, wallet(1000 * UNITS_PER_QCH));
            let amt = (i as u64 + 1) * 10 * UNITS_PER_QCH;
            StakingV7Program::execute(&mut accounts, &ix(&StakingV7Instruction::Stake { amount: amt }, vec![staker, *p, STAKING_GLOBAL_ID, STAKING_RESERVE_ID]), &staker).unwrap();
        }
        // Some quantos pass (all five deposits activate at quanto 0's close, then earn).
        for q in 0..30 {
            settle_quanto(&mut accounts, q).unwrap();
        }
        let g = read_global(&accounts);
        let o1_total = position_value(g.total_shares, g.index);
        let o_n_total: u128 = positions.iter().map(|p| position_current_value(&read_position(&accounts, p).unwrap(), &g)).sum();
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
