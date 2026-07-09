//! Native (trusted, natively-compiled) programs - the phase-1 extension
//! point per `ARCHITECTURE.md` §4/§7: no bytecode sandbox required to add
//! one, at the cost of needing to be trusted code shipped with the
//! validator binary itself, unlike a WASM contract (`wasm.rs`). The System
//! Program (account creation, transfers) lives here because every
//! transaction depends on it.

use crate::error::ExecError;
use qchain_core::{Account, Instruction};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

pub trait NativeProgram: Send + Sync {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey) -> Result<(), ExecError>;
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum SystemInstruction {
    /// accounts[0] = new account (created if absent, funded from the payer).
    CreateAccount { units: u64, owner: Pubkey },
    /// accounts[0] = from, accounts[1] = to.
    Transfer { amount: u64 },
}

pub struct SystemProgram;

impl SystemProgram {
    fn transfer_internal(accounts: &mut HashMap<Pubkey, Account>, from: &Pubkey, to: &Pubkey, amount: u64) -> Result<(), ExecError> {
        let from_balance = accounts.get(from).ok_or(ExecError::AccountNotFound(*from))?.balance;
        if from_balance < amount {
            return Err(ExecError::InsufficientFunds);
        }
        accounts.get_mut(from).unwrap().balance = from_balance - amount;
        accounts
            .entry(*to)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()))
            .balance += amount;
        Ok(())
    }
}

impl NativeProgram for SystemProgram {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey) -> Result<(), ExecError> {
        let instr = SystemInstruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad instruction data: {e}")))?;
        match instr {
            SystemInstruction::CreateAccount { units, owner } => {
                let new_pubkey = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| ExecError::ProgramError("CreateAccount requires accounts[0]".into()))?;
                // Deliberately `entry(..).or_insert_with(..)`, never a
                // pre-seeded placeholder: a prior prototype in this account
                // learned the hard way that pre-populating a default entry
                // for not-yet-existing accounts silently defeats this exact
                // "create if absent" logic (see `project-lessons-learned`).
                accounts.entry(*new_pubkey).or_insert_with(|| Account::new_wallet(owner));
                Self::transfer_internal(accounts, payer, new_pubkey, units)?;
            }
            SystemInstruction::Transfer { amount } => {
                let from = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| ExecError::ProgramError("Transfer requires accounts[0]".into()))?;
                let to = instruction
                    .accounts
                    .get(1)
                    .ok_or_else(|| ExecError::ProgramError("Transfer requires accounts[1]".into()))?;
                Self::transfer_internal(accounts, from, to, amount)?;
            }
        }
        Ok(())
    }
}

use borsh::BorshDeserialize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_moves_balance() {
        let from = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let to = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(from, Account { balance: 1_000, ..Account::new_wallet(Pubkey::system_program_id()) });

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![from, to],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 400 }).unwrap(),
        };
        SystemProgram.process(&mut accounts, &ix, &from).unwrap();
        assert_eq!(accounts[&from].balance, 600);
        assert_eq!(accounts[&to].balance, 400);
    }

    #[test]
    fn create_account_sets_owner_correctly() {
        let payer = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let new_account = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let program_owner = Pubkey::new([9u8; 32]);
        let mut accounts = HashMap::new();
        accounts.insert(payer, Account { balance: 1_000, ..Account::new_wallet(Pubkey::system_program_id()) });

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![new_account],
            data: borsh::to_vec(&SystemInstruction::CreateAccount { units: 300, owner: program_owner }).unwrap(),
        };
        SystemProgram.process(&mut accounts, &ix, &payer).unwrap();
        assert_eq!(accounts[&new_account].owner, program_owner, "owner must be the one CreateAccount specified, not defaulted");
        assert_eq!(accounts[&new_account].balance, 300);
        assert_eq!(accounts[&payer].balance, 700);
    }
}
