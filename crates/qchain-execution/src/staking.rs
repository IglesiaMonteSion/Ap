//! Delegated staking (design: `ARCHITECTURE.md` §5 - "Delegated staking
//! desde fase 1... cualquier holder puede delegar a un validador"). This
//! was declared in scope for phase 1 but never actually built then (see
//! `project-lessons-learned`); it's implemented now because phase 2's
//! governance needs a *real* stake-weighted voting base, not the small
//! hardcoded validator set `qchain-consensus` uses for BFT quorum - that
//! set is a fixed, config-loaded list of ~10-20 validators, deliberately
//! separate from "how many QCH does an arbitrary holder have bonded,"
//! which is what governance §6 actually means by "votación ponderada por
//! stake."
//!
//! Each `Delegate` call opens a brand-new stake account (no top-up/reuse
//! of an existing position, mirroring how `CreateAccount` already works
//! elsewhere in this codebase) - a staker can hold several. `Undelegate`
//! closes a position immediately: no unbonding delay yet (out of scope
//! per `ARCHITECTURE.md` §5's "fuera de alcance en fase 1: calibración
//! fina de la tasa de emisión/staking" - an unbonding period is exactly
//! that kind of economic calibration, not modeled here). A closed stake
//! account is zeroed rather than deleted, since this execution model has
//! no account-deletion primitive yet (see `Ledger`'s working-set
//! commit loop) - a documented phase-2 limitation, not an oversight.

use crate::error::ExecError;
use crate::ids::STAKING_PROGRAM_ID;
use crate::native::NativeProgram;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, Instruction, Round};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct StakeAccountData {
    /// The withdraw authority - only this pubkey (checked against the
    /// transaction payer) can `Undelegate`, and this is who casts votes
    /// with this position's weight in governance.
    pub owner: Pubkey,
    /// Informational only in this increment: doesn't yet feed
    /// `qchain-consensus`'s BFT quorum weighting, which still reads
    /// validator stake from the node's static config (see module docs).
    pub validator: Pubkey,
    /// 0 once undelegated - the account is a zeroed tombstone, not
    /// deleted (see module docs).
    pub amount: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum StakingInstruction {
    /// accounts[0] = staker wallet (funding source; must equal the
    /// transaction payer), accounts[1] = a fresh pubkey for the new stake
    /// account, accounts[2] = the staking-stats singleton
    /// (`STAKING_STATS_ID`).
    Delegate { validator: Pubkey, amount: u64 },
    /// accounts[0] = the stake account to close (its stored `owner` must
    /// equal the transaction payer), accounts[1] = the staking-stats
    /// singleton. Returned funds go to the payer's own wallet.
    Undelegate,
}

fn read_stats(account: &Account) -> Result<u64, ExecError> {
    u64::try_from_slice(&account.data).map_err(|e| ExecError::ProgramError(format!("corrupt staking stats: {e}")))
}

pub struct StakingProgram;

impl NativeProgram for StakingProgram {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, _current_round: Round) -> Result<(), ExecError> {
        let instr = StakingInstruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad instruction data: {e}")))?;
        match instr {
            StakingInstruction::Delegate { validator, amount } => {
                let staker = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[0]".into()))?;
                let stake_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[1]".into()))?;
                let stats_pk = *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[2]".into()))?;

                if staker != *payer {
                    return Err(ExecError::Unauthorized("Delegate's funding account must be the transaction payer".into()));
                }
                if accounts.contains_key(&stake_pk) {
                    return Err(ExecError::ProgramError("stake account already exists - Delegate always opens a fresh position".into()));
                }

                let staker_balance = accounts.get(&staker).ok_or(ExecError::AccountNotFound(staker))?.balance;
                if staker_balance < amount {
                    return Err(ExecError::InsufficientFunds);
                }
                accounts.get_mut(&staker).unwrap().balance -= amount;

                let mut stake_account = Account::new_wallet(STAKING_PROGRAM_ID);
                stake_account.balance = amount;
                stake_account.data = borsh::to_vec(&StakeAccountData { owner: staker, validator, amount })
                    .map_err(|e| ExecError::ProgramError(e.to_string()))?;
                accounts.insert(stake_pk, stake_account);

                let stats = accounts
                    .entry(stats_pk)
                    .or_insert_with(|| Account { data: borsh::to_vec(&0u64).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) });
                let total = read_stats(stats)?.saturating_add(amount);
                stats.data = borsh::to_vec(&total).map_err(|e| ExecError::ProgramError(e.to_string()))?;
            }
            StakingInstruction::Undelegate => {
                let stake_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Undelegate requires accounts[0]".into()))?;
                let stats_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Undelegate requires accounts[1]".into()))?;

                let stake_account = accounts.get(&stake_pk).ok_or(ExecError::AccountNotFound(stake_pk))?;
                let mut data = StakeAccountData::try_from_slice(&stake_account.data)
                    .map_err(|e| ExecError::ProgramError(format!("corrupt stake account: {e}")))?;
                if data.owner != *payer {
                    return Err(ExecError::Unauthorized("Undelegate must be signed by the stake account's owner".into()));
                }
                let amount = data.amount;

                data.amount = 0;
                let stake_account = accounts.get_mut(&stake_pk).unwrap();
                stake_account.balance = 0;
                stake_account.data = borsh::to_vec(&data).map_err(|e| ExecError::ProgramError(e.to_string()))?;

                accounts.entry(*payer).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id())).balance += amount;

                let stats = accounts.get_mut(&stats_pk).ok_or(ExecError::AccountNotFound(stats_pk))?;
                let total = read_stats(stats)?.saturating_sub(amount);
                stats.data = borsh::to_vec(&total).map_err(|e| ExecError::ProgramError(e.to_string()))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::STAKING_STATS_ID;

    fn wallet_with(balance: u64) -> Account {
        Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) }
    }

    fn stats_account() -> Account {
        Account { data: borsh::to_vec(&0u64).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) }
    }

    #[test]
    fn delegate_moves_funds_into_a_new_stake_account_and_updates_stats() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let validator = Pubkey::new([21u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account())]);

        let ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &ix, &staker, 0).unwrap();

        assert_eq!(accounts[&staker].balance, 6_000);
        assert_eq!(accounts[&stake_pk].balance, 4_000);
        let data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(data, StakeAccountData { owner: staker, validator, amount: 4_000 });
        assert_eq!(read_stats(&accounts[&STAKING_STATS_ID]).unwrap(), 4_000);
    }

    #[test]
    fn delegating_someone_elses_wallet_is_rejected() {
        let staker = Pubkey::new([22u8; 32]);
        let attacker = Pubkey::new([23u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account())]);

        let ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
    }

    #[test]
    fn undelegate_returns_funds_and_zeroes_the_position() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let validator = Pubkey::new([21u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        StakingProgram.process(&mut accounts, &undelegate_ix, &staker, 0).unwrap();

        assert_eq!(accounts[&staker].balance, 10_000, "funds must return in full, no unbonding delay in this increment");
        assert_eq!(accounts[&stake_pk].balance, 0);
        assert_eq!(read_stats(&accounts[&STAKING_STATS_ID]).unwrap(), 0);
    }

    #[test]
    fn undelegate_by_a_non_owner_is_rejected() {
        let staker = Pubkey::new([22u8; 32]);
        let attacker = Pubkey::new([23u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (attacker, wallet_with(0)), (STAKING_STATS_ID, stats_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
        assert_eq!(accounts[&stake_pk].balance, 4_000, "an unauthorized undelegate must not touch the position");
    }
}
