//! Ties together account storage (`qchain-storage`), native programs, and
//! WASM contracts into `apply_transaction` - the state-transition function
//! this project's execution layer exists to provide. Fee model and dust
//! sweep per `ARCHITECTURE.md` §5.

use crate::error::ExecError;
use crate::native::NativeProgram;
use crate::wasm::WasmExecutor;
use qchain_core::{Account, Instruction, Transaction, BASE_FEE_PER_BYTE_UNITS, DUST_THRESHOLD_UNITS};
use qchain_crypto::Pubkey;
use qchain_storage::StateStore;
use std::collections::HashMap;
use wasmtime::Val;

/// Placeholder gas price - see `ARCHITECTURE.md` §5's tokenomics
/// disclaimer: a starting point, not a modeled figure.
pub const GAS_PRICE_UNITS_PER_FUEL: u64 = 1;
/// Fuel budget for the WASM half of a transaction. A real deployment would
/// derive this from `Message.fee_limit`; fixed here for phase 1 simplicity.
pub const DEFAULT_FUEL_LIMIT: u64 = 5_000_000;

pub enum Program {
    Native(Box<dyn NativeProgram>),
    Wasm { module_bytes: Vec<u8>, entry_point: String },
}

pub struct Ledger {
    store: Box<dyn StateStore>,
    programs: HashMap<Pubkey, Program>,
    wasm: WasmExecutor,
    pub total_burned: u64,
}

impl Ledger {
    pub fn new(store: Box<dyn StateStore>) -> anyhow::Result<Self> {
        Ok(Ledger {
            store,
            programs: HashMap::new(),
            wasm: WasmExecutor::new()?,
            total_burned: 0,
        })
    }

    pub fn register_program(&mut self, id: Pubkey, program: Program) {
        self.programs.insert(id, program);
    }

    pub fn store(&self) -> &dyn StateStore {
        self.store.as_ref()
    }

    pub fn get_balance(&self, pk: &Pubkey) -> u64 {
        self.store.get(pk).map(|a| a.balance).unwrap_or(0)
    }

    pub fn credit(&mut self, pk: Pubkey, amount: u64) {
        let mut account = self.store.get(&pk).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
        account.balance = account.balance.saturating_add(amount);
        self.store.set(pk, account);
    }

    /// Verify the transaction, charge the byte-scaled base fee (split
    /// between burning and `fee_collector`, per `ARCHITECTURE.md` §5),
    /// then dispatch every instruction to its program. Instruction
    /// execution uses a *working set* scoped to the accounts this
    /// transaction actually references - not a clone of the whole store -
    /// see the `blockchain-core-rust` skill for why that distinction is
    /// load-bearing, not just an optimization.
    pub fn apply_transaction(&mut self, tx: &Transaction, fee_collector: &Pubkey) -> Result<u64, ExecError> {
        if !tx.verify_signature() {
            return Err(ExecError::InvalidSignature);
        }

        let byte_fee = BASE_FEE_PER_BYTE_UNITS * tx.byte_size() as u64;
        let mut payer_account = self.store.get(&tx.message.payer).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
        if payer_account.balance < byte_fee {
            return Err(ExecError::InsufficientFunds);
        }
        if payer_account.nonce != tx.message.nonce {
            return Err(ExecError::ProgramError(format!(
                "nonce mismatch: account is at {}, transaction has {}",
                payer_account.nonce, tx.message.nonce
            )));
        }
        payer_account.balance -= byte_fee;
        payer_account.nonce += 1;
        self.store.set(tx.message.payer, payer_account.clone());

        let burn_share = byte_fee / 2;
        let validator_share = byte_fee - burn_share;
        self.total_burned += burn_share;
        self.credit(*fee_collector, validator_share);

        // Working set: the payer is always included (implicit participant,
        // e.g. as CreateAccount's funding source, even when no instruction
        // explicitly lists it - a second lesson learned the hard way in a
        // prior prototype, see `project-lessons-learned`), plus every
        // *pre-existing* account any instruction references. Genuinely new
        // accounts are deliberately left absent so a program's own
        // `entry(..).or_insert_with(..)` is what creates them.
        let mut working: HashMap<Pubkey, Account> = HashMap::new();
        working.insert(tx.message.payer, self.store.get(&tx.message.payer).unwrap_or(payer_account));
        for ix in &tx.message.instructions {
            for pk in &ix.accounts {
                if let Some(account) = self.store.get(pk) {
                    working.entry(*pk).or_insert(account);
                }
            }
        }

        let mut total_gas_fee = 0u64;
        for ix in &tx.message.instructions {
            let program = self.programs.get(&ix.program_id).ok_or(ExecError::UnknownProgram(ix.program_id))?;
            match program {
                Program::Native(native) => native.process(&mut working, ix, &tx.message.payer)?,
                Program::Wasm { module_bytes, entry_point } => {
                    total_gas_fee += self.run_wasm_instruction(module_bytes, entry_point, ix, &mut working)?;
                }
            }
        }

        if total_gas_fee > 0 {
            let payer_after = working.get_mut(&tx.message.payer).ok_or(ExecError::AccountNotFound(tx.message.payer))?;
            if payer_after.balance < total_gas_fee {
                return Err(ExecError::InsufficientFunds);
            }
            payer_after.balance -= total_gas_fee;
            self.total_burned += total_gas_fee / 2;
            let gas_validator_share = total_gas_fee - total_gas_fee / 2;
            working.entry(*fee_collector).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id())).balance += gas_validator_share;
        }

        for (pk, mut account) in working {
            if account.owner == Pubkey::system_program_id() && account.balance > 0 && account.balance < DUST_THRESHOLD_UNITS {
                self.total_burned += account.balance;
                account.balance = 0;
            }
            self.store.set(pk, account);
        }

        Ok(byte_fee + total_gas_fee)
    }

    fn run_wasm_instruction(
        &self,
        module_bytes: &[u8],
        entry_point: &str,
        ix: &Instruction,
        working: &mut HashMap<Pubkey, Account>,
    ) -> Result<u64, ExecError> {
        let accounts: Vec<Account> = ix
            .accounts
            .iter()
            .map(|pk| working.get(pk).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id())))
            .collect();

        // Phase-1 simplification: instruction args are passed as up to two
        // little-endian u64s taken from the tail of `ix.data`, rather than a
        // full ABI/serialization convention - sufficient to prove the
        // pipeline works end to end (see `wasm.rs` tests), not a final
        // contract calling convention.
        let mut args = vec![];
        for chunk in ix.data.chunks(8) {
            if chunk.len() == 8 {
                args.push(Val::I64(i64::from_le_bytes(chunk.try_into().unwrap())));
            }
        }

        let result = self
            .wasm
            .call(module_bytes, entry_point, &args, accounts, DEFAULT_FUEL_LIMIT)
            .map_err(|e| ExecError::Wasm(e.to_string()))?;

        for (pk, account) in ix.accounts.iter().zip(result.accounts.into_iter()) {
            working.insert(*pk, account);
        }

        Ok(result.fuel_consumed * GAS_PRICE_UNITS_PER_FUEL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{SystemInstruction, SystemProgram};
    use qchain_core::Instruction;
    use qchain_crypto::Keypair;
    use qchain_storage::InMemoryStore;

    fn new_test_ledger() -> Ledger {
        let mut ledger = Ledger::new(Box::new(InMemoryStore::new())).unwrap();
        ledger.register_program(Pubkey::system_program_id(), Program::Native(Box::new(SystemProgram)));
        ledger
    }

    #[test]
    fn end_to_end_transfer_charges_fee_and_moves_balance() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();

        ledger.credit(alice.pubkey(), 1_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 100_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();

        let fee = ledger.apply_transaction(&tx, &validator).unwrap();
        assert!(fee > 0, "a multi-kilobyte hybrid-signed transaction must not be free");

        assert_eq!(ledger.get_balance(&bob), 100_000);
        assert_eq!(ledger.get_balance(&alice.pubkey()), 1_000_000 - 100_000 - fee);
        assert_eq!(ledger.get_balance(&validator), fee - fee / 2, "validator gets its half of the burned/split fee");
        assert_eq!(ledger.total_burned, fee / 2);
    }

    #[test]
    fn replayed_transaction_is_rejected_by_nonce() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 1_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();
        ledger.apply_transaction(&tx, &validator).unwrap();

        // Same nonce again - the account has already moved to nonce 1.
        assert!(ledger.apply_transaction(&tx, &validator).is_err());
    }

    #[test]
    fn dust_left_after_a_transfer_is_swept_and_burned() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();

        // Fund alice with just enough to pay the fee and send "almost
        // everything," leaving a sub-threshold residue behind.
        let fee_estimate = {
            let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![alice.pubkey(), bob], data: vec![] };
            let probe = Transaction::new_signed(&alice, 0, [0u8; 32], 0, vec![ix]).unwrap();
            BASE_FEE_PER_BYTE_UNITS * probe.byte_size() as u64
        };
        let starting_balance = fee_estimate + DUST_THRESHOLD_UNITS / 2 + 50_000;
        ledger.credit(alice.pubkey(), starting_balance);

        let send_amount = starting_balance - fee_estimate - (DUST_THRESHOLD_UNITS / 2);
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: send_amount }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], starting_balance, vec![ix]).unwrap();
        ledger.apply_transaction(&tx, &validator).unwrap();

        assert_eq!(ledger.get_balance(&alice.pubkey()), 0, "sub-threshold residue must be swept, not left dangling");
    }
}
