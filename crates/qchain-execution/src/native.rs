//! Native (trusted, natively-compiled) programs - the phase-1 extension
//! point per `ARCHITECTURE.md` §4/§7: no bytecode sandbox required to add
//! one, at the cost of needing to be trusted code shipped with the
//! validator binary itself, unlike a WASM contract (`wasm.rs`). The System
//! Program (account creation, transfers) lives here because every
//! transaction depends on it.

use crate::error::ExecError;
use crate::ids::LOADER_PROGRAM_ID;
use qchain_core::{Account, Instruction, Round};
use qchain_crypto::Pubkey;
use sha3::{Digest as _, Sha3_256};
use std::collections::HashMap;

/// Real, adjustable-by-recompiling resource cap on deployed contract
/// bytecode - a placeholder in the same spirit as the other economic
/// constants in `qchain-core::account` (documented, not arbitrary-but-
/// hidden), sized to comfortably fit a real hand-written contract (the
/// test contracts in `wasm.rs` are a few hundred bytes) while bounding
/// how much state/bandwidth one `DeployProgram` can add - unbounded
/// bytecode size is a real state-bloat/gossip-bandwidth DoS vector, not
/// a hypothetical one.
pub const MAX_PROGRAM_BYTECODE_BYTES: usize = 256 * 1024;

/// What a `DeployProgram`-created account's `data` holds - the WASM
/// module bytes plus which export to call, read back by
/// `Ledger::apply_transaction`'s dispatch fallback on every later
/// instruction naming this program as `program_id`.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct WasmProgramData {
    pub entry_point: String,
    pub module_bytes: Vec<u8>,
}

pub trait NativeProgram: Send + Sync {
    /// `current_round` is the DAG round of the certificate whose batch
    /// this instruction came from - the only notion of "now" available
    /// to a native program, since wall-clock time would break
    /// determinism across validators (see `qchain-governance`, which
    /// uses it for voting-period/timelock checks). Programs that don't
    /// need a clock (like `SystemProgram`) simply ignore it.
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
        current_round: Round,
    ) -> Result<(), ExecError>;
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum SystemInstruction {
    /// accounts[0] = new account (created if absent, funded from the payer).
    CreateAccount { units: u64, owner: Pubkey },
    /// accounts[0] = from, accounts[1] = to.
    Transfer { amount: u64 },
    /// accounts[0] = the fresh address this program will live at - must
    /// not already hold an account (deploy-once, same "create if absent"
    /// discipline `CreateAccount` already follows; this never overwrites
    /// an existing wallet or program). No separate deploy fee: the
    /// existing byte-scaled base fee already charges proportionally more
    /// for a larger `module_bytes`, since it's part of this instruction's
    /// data and therefore of `tx.byte_size()`.
    DeployProgram { module_bytes: Vec<u8>, entry_point: String },
}

pub struct SystemProgram;

impl SystemProgram {
    fn transfer_internal(accounts: &mut HashMap<Pubkey, Account>, from: &Pubkey, to: &Pubkey, amount: u64) -> Result<(), ExecError> {
        let from_balance = accounts.get(from).ok_or(ExecError::AccountNotFound(*from))?.balance;
        if from_balance < amount {
            return Err(ExecError::InsufficientFunds);
        }
        accounts.get_mut(from).unwrap().balance = from_balance - amount;
        // saturating_add: overflow-safety discipline (see qchain-governance::record_vote).
        // Unreachable at realistic supply, but a plain `+` overflow would panic-halt
        // every node in release (overflow-checks=true). Byte-identical for real values.
        let to_acct = accounts.entry(*to).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        to_acct.balance = to_acct.balance.saturating_add(amount);
        Ok(())
    }
}

impl NativeProgram for SystemProgram {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, _current_round: Round) -> Result<(), ExecError> {
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
                // Phase 1/2 transactions have exactly one authenticated
                // party (the payer, checked by the transaction's own
                // hybrid signature) - there is no separate per-instruction
                // signer to check yet. So a Transfer's source account must
                // be the payer itself; anything else would let any signed
                // transaction move funds out of an account it never
                // proved control of. Multi-signer transactions (checking
                // an authority distinct from the payer) are a later
                // increment, not present here.
                if from != payer {
                    return Err(ExecError::Unauthorized("Transfer's source account must be the transaction payer".into()));
                }
                Self::transfer_internal(accounts, from, to, amount)?;
            }
            SystemInstruction::DeployProgram { module_bytes, entry_point } => {
                if module_bytes.len() > MAX_PROGRAM_BYTECODE_BYTES {
                    return Err(ExecError::ProgramError(format!(
                        "program bytecode too large: {} bytes (max {MAX_PROGRAM_BYTECODE_BYTES})",
                        module_bytes.len()
                    )));
                }
                let program_pubkey = instruction
                    .accounts
                    .first()
                    .ok_or_else(|| ExecError::ProgramError("DeployProgram requires accounts[0]".into()))?;
                // Working-set membership here means exactly "an account
                // already exists at this address in the persisted store"
                // (see `Ledger::apply_transaction`'s working-set
                // construction) - reject rather than silently overwrite
                // whatever's already there, whether a wallet or another
                // deployed program.
                if accounts.contains_key(program_pubkey) {
                    return Err(ExecError::ProgramError(
                        "an account already exists at the target program address".into(),
                    ));
                }
                let code_hash: [u8; 32] = Sha3_256::digest(&module_bytes).into();
                let data = borsh::to_vec(&WasmProgramData { entry_point, module_bytes })
                    .map_err(|e| ExecError::ProgramError(format!("failed to encode program data: {e}")))?;
                accounts.insert(
                    *program_pubkey,
                    Account { code_hash, data, owner: LOADER_PROGRAM_ID, ..Account::new_wallet(LOADER_PROGRAM_ID) },
                );
            }
        }
        Ok(())
    }
}

use borsh::BorshDeserialize;

#[cfg(test)]
mod tests {
    use super::*;

    /// The browser/WASM wallet (`qchain-wasm`) can't depend on this crate
    /// (wasmtime doesn't target wasm), so it replicates the Borsh encoding of
    /// `SystemInstruction::Transfer { amount }` as `[1u8] ++ amount.to_le_bytes()`.
    /// This guards that assumption: if the enum ever changes shape or order,
    /// this fails and the wasm signer must be updated to match.
    #[test]
    fn transfer_instruction_encoding_is_stable() {
        let amount = 0x0102_0304_0506_0708u64;
        let encoded = borsh::to_vec(&SystemInstruction::Transfer { amount }).unwrap();
        let mut expected = vec![1u8];
        expected.extend_from_slice(&amount.to_le_bytes());
        assert_eq!(encoded, expected, "wasm wallet's hand-rolled Transfer encoding is out of sync");
    }

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
        SystemProgram.process(&mut accounts, &ix, &from, 0).unwrap();
        assert_eq!(accounts[&from].balance, 600);
        assert_eq!(accounts[&to].balance, 400);
    }

    #[test]
    fn transfer_from_an_account_other_than_the_payer_is_rejected() {
        let victim = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let attacker = qchain_crypto::Keypair::generate().unwrap().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(victim, Account { balance: 1_000, ..Account::new_wallet(Pubkey::system_program_id()) });

        // Attacker signs the transaction (so `payer` is the attacker) but
        // names the victim as the Transfer's source account - this must
        // never move the victim's funds.
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![victim, attacker],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1_000 }).unwrap(),
        };
        let result = SystemProgram.process(&mut accounts, &ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
        assert_eq!(accounts[&victim].balance, 1_000, "the victim's balance must be untouched");
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
        SystemProgram.process(&mut accounts, &ix, &payer, 0).unwrap();
        assert_eq!(accounts[&new_account].owner, program_owner, "owner must be the one CreateAccount specified, not defaulted");
        assert_eq!(accounts[&new_account].balance, 300);
        assert_eq!(accounts[&payer].balance, 700);
    }
}
