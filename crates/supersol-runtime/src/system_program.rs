use borsh::{BorshDeserialize, BorshSerialize};
use supersol_core::{Account, Instruction, ProgramProcessor, TxError};
use supersol_crypto::Pubkey;
use std::collections::HashMap;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum SystemInstruction {
    /// accounts[0] = new account. Creates it (if absent) owned by `owner`
    /// and funds it with `units` transferred from the payer.
    CreateAccount { units: u64, owner: Pubkey },
    /// accounts[0] = from, accounts[1] = to.
    Transfer { amount: u64 },
}

pub struct SystemProgram;

impl SystemProgram {
    fn transfer_internal(
        accounts: &mut HashMap<Pubkey, Account>,
        from: &Pubkey,
        to: &Pubkey,
        amount: u64,
    ) -> Result<(), TxError> {
        let from_balance = accounts.get(from).ok_or(TxError::AccountNotFound(*from))?.balance;
        if from_balance < amount {
            return Err(TxError::InsufficientFunds);
        }
        accounts.get_mut(from).unwrap().balance = from_balance - amount;
        let to_account = accounts
            .entry(*to)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        to_account.balance = to_account.balance.saturating_add(amount);
        Ok(())
    }
}

impl ProgramProcessor for SystemProgram {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), TxError> {
        let instr = SystemInstruction::try_from_slice(&instruction.data)
            .map_err(|e| TxError::ProgramError(format!("bad instruction data: {e}")))?;
        match instr {
            SystemInstruction::CreateAccount { units, owner } => {
                let new_pubkey = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| TxError::ProgramError("CreateAccount requires accounts[0]".into()))?;
                accounts
                    .entry(*new_pubkey)
                    .or_insert_with(|| Account::new_wallet(owner));
                Self::transfer_internal(accounts, payer, new_pubkey, units)?;
            }
            SystemInstruction::Transfer { amount } => {
                let from = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| TxError::ProgramError("Transfer requires accounts[0]".into()))?;
                let to = instruction
                    .accounts
                    .get(1)
                    .ok_or_else(|| TxError::ProgramError("Transfer requires accounts[1]".into()))?;
                Self::transfer_internal(accounts, from, to, amount)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_moves_balance() {
        let a = Pubkey::system_program_id();
        let from = supersol_crypto::Keypair::generate().pubkey();
        let to = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(from, Account { balance: 1_000, owner: a, data: vec![], executable: false });

        let ix = Instruction {
            program_id: a,
            accounts: vec![from, to],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 400 }).unwrap(),
        };
        SystemProgram.process(&mut accounts, &ix, &from).unwrap();
        assert_eq!(accounts.get(&from).unwrap().balance, 600);
        assert_eq!(accounts.get(&to).unwrap().balance, 400);
    }

    #[test]
    fn transfer_fails_on_insufficient_funds() {
        let a = Pubkey::system_program_id();
        let from = supersol_crypto::Keypair::generate().pubkey();
        let to = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(from, Account::new_wallet(a));

        let ix = Instruction {
            program_id: a,
            accounts: vec![from, to],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        assert!(matches!(
            SystemProgram.process(&mut accounts, &ix, &from),
            Err(TxError::InsufficientFunds)
        ));
    }
}
