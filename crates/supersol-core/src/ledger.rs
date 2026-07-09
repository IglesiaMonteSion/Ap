use crate::account::Account;
use crate::block::Block;
use crate::transaction::{Instruction, Transaction};
use supersol_crypto::Pubkey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("account not found: {0}")]
    AccountNotFound(Pubkey),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("unknown program: {0}")]
    UnknownProgram(Pubkey),
    #[error("program error: {0}")]
    ProgramError(String),
}

/// Implemented by every native program (System, Token, Memo, ...). This is
/// intentionally the simplest possible extension point: trusted, natively
/// compiled Rust code rather than a sandboxed bytecode VM. That trade-off is
/// what makes writing a new program here as easy as implementing a trait -
/// the "better dev UX" improvement over Solana's BPF/eBPF toolchain - at the
/// cost of not yet supporting untrusted third-party program deployment.
/// Phase 3 of the roadmap replaces this with a sandboxed (likely WASM) VM
/// without changing the ledger/runtime split above it.
pub trait ProgramProcessor: Send + Sync {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), TxError>;
}

pub type ProgramRegistry = HashMap<Pubkey, Box<dyn ProgramProcessor>>;

#[derive(Serialize, Deserialize, Default)]
pub struct Ledger {
    pub accounts: HashMap<Pubkey, Account>,
    pub blocks: Vec<Block>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> u64 {
        self.accounts.get(pubkey).map(|a| a.balance).unwrap_or(0)
    }

    pub fn get_account(&self, pubkey: &Pubkey) -> Option<&Account> {
        self.accounts.get(pubkey)
    }

    /// Verify the transaction's signature, charge the flat per-transaction
    /// fee to `fee_collector` (typically the block leader), and run every
    /// instruction through its target program. The fee is charged upfront
    /// and is *not* refunded if an instruction later fails - it must be paid
    /// to deter spam regardless of whether the transaction's instructions
    /// succeed, the same way real networks charge fees on failed
    /// transactions. Instruction execution itself stays all-or-nothing: we
    /// hand programs a clone of the account map to mutate and only commit it
    /// on success.
    pub fn apply_transaction(
        &mut self,
        tx: &Transaction,
        programs: &ProgramRegistry,
        fee_collector: &Pubkey,
        fee_units: u64,
    ) -> Result<(), TxError> {
        if !tx.verify_signature() {
            return Err(TxError::InvalidSignature);
        }

        let payer_account = self
            .accounts
            .entry(tx.message.payer)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        if payer_account.balance < fee_units {
            return Err(TxError::InsufficientFunds);
        }
        payer_account.balance -= fee_units;
        self.accounts
            .entry(*fee_collector)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()))
            .balance += fee_units;

        let mut scratch = self.accounts.clone();
        for ix in &tx.message.instructions {
            let program = programs
                .get(&ix.program_id)
                .ok_or(TxError::UnknownProgram(ix.program_id))?;
            program.process(&mut scratch, ix, &tx.message.payer)?;
        }
        self.accounts = scratch;
        Ok(())
    }

    /// Directly credit an account, bypassing signature/program checks. Only
    /// meant to be called by a node configured with `--enable-faucet`
    /// (devnet), never on a production validator.
    pub fn airdrop(&mut self, pubkey: Pubkey, amount: u64) {
        let account = self
            .accounts
            .entry(pubkey)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        account.balance = account.balance.saturating_add(amount);
    }

    pub fn push_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poh::{Poh, PohEntry};

    struct NoopProgram;
    impl ProgramProcessor for NoopProgram {
        fn process(&self, _: &mut HashMap<Pubkey, Account>, _: &Instruction, _: &Pubkey) -> Result<(), TxError> {
            Ok(())
        }
    }

    #[test]
    fn rejects_transactions_with_bad_signatures() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![],
            data: vec![],
        };
        let mut tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        tx.message.recent_blockhash = [9u8; 32]; // mutate after signing
        let mut ledger = Ledger::new();
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(Pubkey::system_program_id(), Box::new(NoopProgram));
        let leader = Pubkey::system_program_id();
        assert!(matches!(
            ledger.apply_transaction(&tx, &programs, &leader, 0),
            Err(TxError::InvalidSignature)
        ));
    }

    #[test]
    fn fee_is_charged_to_payer_and_credited_to_leader() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
        let leader = Keypair::generate().pubkey();
        let mut ledger = Ledger::new();
        ledger.airdrop(payer.pubkey(), 10_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![],
            data: vec![],
        };
        let tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(Pubkey::system_program_id(), Box::new(NoopProgram));

        ledger.apply_transaction(&tx, &programs, &leader, 500).unwrap();
        assert_eq!(ledger.get_balance(&payer.pubkey()), 9_500);
        assert_eq!(ledger.get_balance(&leader), 500);
    }

    #[test]
    fn fee_is_charged_even_if_instruction_fails() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
        let leader = Keypair::generate().pubkey();
        let mut ledger = Ledger::new();
        ledger.airdrop(payer.pubkey(), 10_000);

        struct FailingProgram;
        impl ProgramProcessor for FailingProgram {
            fn process(&self, _: &mut HashMap<Pubkey, Account>, _: &Instruction, _: &Pubkey) -> Result<(), TxError> {
                Err(TxError::ProgramError("boom".into()))
            }
        }
        let program_id = Pubkey::new([2u8; 32]);
        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: vec![],
        };
        let tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(program_id, Box::new(FailingProgram));

        assert!(ledger.apply_transaction(&tx, &programs, &leader, 500).is_err());
        assert_eq!(ledger.get_balance(&payer.pubkey()), 9_500);
        assert_eq!(ledger.get_balance(&leader), 500);
    }

    #[test]
    fn airdrop_credits_balance_directly() {
        let mut ledger = Ledger::new();
        let pk = supersol_crypto::Keypair::generate().pubkey();
        ledger.airdrop(pk, 5_000);
        assert_eq!(ledger.get_balance(&pk), 5_000);
    }

    #[test]
    fn block_bookkeeping() {
        let mut ledger = Ledger::new();
        assert!(ledger.latest_block().is_none());
        let mut poh = Poh::new([0u8; 32]);
        let entry: PohEntry = poh.tick();
        ledger.push_block(Block {
            slot: 1,
            leader: supersol_crypto::Keypair::generate().pubkey(),
            previous_blockhash: [0u8; 32],
            blockhash: entry.hash,
            poh_entries: vec![entry.clone()],
            transactions: vec![],
            airdrops: vec![],
        });
        assert_eq!(ledger.latest_block().unwrap().blockhash, entry.hash);
    }
}
