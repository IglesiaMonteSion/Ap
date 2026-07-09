use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashMap;
use supersol_core::{Account, Instruction, ProgramProcessor, StakeState, StakeStatus, TxError, STAKE_PROGRAM_ID};
use supersol_crypto::Pubkey;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum StakeInstruction {
    /// accounts[0] = a stake account that must already exist (typically
    /// created moments earlier, in the same transaction, via
    /// `SystemInstruction::CreateAccount { owner: STAKE_PROGRAM_ID, .. }`),
    /// funded with however much you want staked. Marks it Active and
    /// delegated to `validator`, controlled by `authority`.
    Initialize { authority: Pubkey, validator: Pubkey },
    /// accounts[0] = the stake account. Only its authority may do this.
    /// Stops it from earning further rewards and unlocks it for withdrawal.
    Deactivate,
    /// accounts[0] = the stake account, accounts[1] = destination wallet.
    /// Only allowed once the stake has been deactivated.
    Withdraw { amount: u64 },
}

/// Handles staking instructions. Reward *distribution* (paying active
/// stakes from the rewards reserve) is protocol-level bookkeeping across all
/// accounts at once, not expressible through this per-instruction interface
/// - see `supersol_core::Ledger::distribute_staking_rewards`, which the node
/// calls directly once per epoch.
pub struct StakeProgram;

impl StakeProgram {
    fn get_stake<'a>(accounts: &'a HashMap<Pubkey, Account>, pk: &Pubkey) -> Result<(&'a Account, StakeState), TxError> {
        let account = accounts.get(pk).ok_or(TxError::AccountNotFound(*pk))?;
        if account.owner != STAKE_PROGRAM_ID {
            return Err(TxError::ProgramError("account not owned by the stake program".into()));
        }
        let state = StakeState::try_from_slice(&account.data)
            .map_err(|e| TxError::ProgramError(format!("corrupt stake account data: {e}")))?;
        Ok((account, state))
    }
}

impl ProgramProcessor for StakeProgram {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), TxError> {
        let instr = StakeInstruction::try_from_slice(&instruction.data)
            .map_err(|e| TxError::ProgramError(format!("bad instruction data: {e}")))?;
        match instr {
            StakeInstruction::Initialize { authority, validator } => {
                let stake_pk = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| TxError::ProgramError("Initialize requires accounts[0]".into()))?;
                let account = accounts.get_mut(stake_pk).ok_or(TxError::AccountNotFound(*stake_pk))?;
                if account.owner != STAKE_PROGRAM_ID {
                    return Err(TxError::ProgramError("stake account not owned by the stake program".into()));
                }
                let state = StakeState {
                    authority,
                    validator,
                    status: StakeStatus::Active,
                };
                account.data = borsh::to_vec(&state).map_err(|e| TxError::ProgramError(e.to_string()))?;
                Ok(())
            }
            StakeInstruction::Deactivate => {
                let stake_pk = *instruction
                    .accounts
                    .first()
                    .ok_or_else(|| TxError::ProgramError("Deactivate requires accounts[0]".into()))?;
                let (_, mut state) = Self::get_stake(accounts, &stake_pk)?;
                if state.authority != *payer {
                    return Err(TxError::ProgramError("only the stake authority may deactivate".into()));
                }
                state.status = StakeStatus::Deactivated;
                accounts.get_mut(&stake_pk).unwrap().data =
                    borsh::to_vec(&state).map_err(|e| TxError::ProgramError(e.to_string()))?;
                Ok(())
            }
            StakeInstruction::Withdraw { amount } => {
                let stake_pk = *instruction
                    .accounts
                    .first()
                    .ok_or_else(|| TxError::ProgramError("Withdraw requires accounts[0]".into()))?;
                let dest_pk = *instruction
                    .accounts
                    .get(1)
                    .ok_or_else(|| TxError::ProgramError("Withdraw requires accounts[1]".into()))?;
                let (stake_account, state) = Self::get_stake(accounts, &stake_pk)?;
                if state.authority != *payer {
                    return Err(TxError::ProgramError("only the stake authority may withdraw".into()));
                }
                if state.status != StakeStatus::Deactivated {
                    return Err(TxError::ProgramError("stake must be deactivated before withdrawing".into()));
                }
                if stake_account.balance < amount {
                    return Err(TxError::InsufficientFunds);
                }
                accounts.get_mut(&stake_pk).unwrap().balance -= amount;
                accounts
                    .entry(dest_pk)
                    .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()))
                    .balance += amount;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stake_account(authority: Pubkey, balance: u64, status: StakeStatus) -> Account {
        let state = StakeState {
            authority,
            validator: Pubkey::system_program_id(),
            status,
        };
        Account {
            balance,
            owner: STAKE_PROGRAM_ID,
            data: borsh::to_vec(&state).unwrap(),
            executable: false,
        }
    }

    #[test]
    fn initialize_sets_active_state() {
        let authority = supersol_crypto::Keypair::generate().pubkey();
        let stake_pk = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(stake_pk, Account::new_wallet(STAKE_PROGRAM_ID));

        let ix = Instruction {
            program_id: STAKE_PROGRAM_ID,
            accounts: vec![stake_pk],
            data: borsh::to_vec(&StakeInstruction::Initialize {
                authority,
                validator: Pubkey::system_program_id(),
            })
            .unwrap(),
        };
        StakeProgram.process(&mut accounts, &ix, &authority).unwrap();

        let state = StakeState::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(state.status, StakeStatus::Active);
        assert_eq!(state.authority, authority);
    }

    #[test]
    fn only_authority_can_deactivate() {
        let authority = supersol_crypto::Keypair::generate().pubkey();
        let attacker = supersol_crypto::Keypair::generate().pubkey();
        let stake_pk = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(stake_pk, stake_account(authority, 1_000, StakeStatus::Active));

        let ix = Instruction {
            program_id: STAKE_PROGRAM_ID,
            accounts: vec![stake_pk],
            data: borsh::to_vec(&StakeInstruction::Deactivate).unwrap(),
        };
        assert!(StakeProgram.process(&mut accounts, &ix, &attacker).is_err());
        StakeProgram.process(&mut accounts, &ix, &authority).unwrap();
        let state = StakeState::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(state.status, StakeStatus::Deactivated);
    }

    #[test]
    fn withdraw_requires_deactivation_first() {
        let authority = supersol_crypto::Keypair::generate().pubkey();
        let stake_pk = supersol_crypto::Keypair::generate().pubkey();
        let dest = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(stake_pk, stake_account(authority, 1_000, StakeStatus::Active));

        let withdraw_ix = Instruction {
            program_id: STAKE_PROGRAM_ID,
            accounts: vec![stake_pk, dest],
            data: borsh::to_vec(&StakeInstruction::Withdraw { amount: 500 }).unwrap(),
        };
        assert!(
            StakeProgram.process(&mut accounts, &withdraw_ix, &authority).is_err(),
            "withdrawing an active (not yet deactivated) stake must fail"
        );

        let deactivate_ix = Instruction {
            program_id: STAKE_PROGRAM_ID,
            accounts: vec![stake_pk],
            data: borsh::to_vec(&StakeInstruction::Deactivate).unwrap(),
        };
        StakeProgram.process(&mut accounts, &deactivate_ix, &authority).unwrap();
        StakeProgram.process(&mut accounts, &withdraw_ix, &authority).unwrap();

        assert_eq!(accounts[&stake_pk].balance, 500);
        assert_eq!(accounts[&dest].balance, 500);
    }
}
