use crate::account::Account;
use crate::block::Block;
use crate::transaction::{Instruction, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use supersol_crypto::Pubkey;
use thiserror::Error;

/// How many recent blocks a validator keeps resident in memory for serving
/// `getBlock` on recent history. Older blocks are still durably recorded
/// (see the node's append-only `blocks.log`) but aren't held in RAM, so a
/// long-running node's memory use stays bounded instead of growing forever
/// with the length of the chain - the same trade-off real Solana validators
/// make by pruning old ledger data and leaving full-history queries to
/// separate archive/RPC nodes.
pub const MAX_RECENT_BLOCKS: usize = 256;

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

#[derive(Serialize, Deserialize)]
pub struct Ledger {
    pub accounts: HashMap<Pubkey, Account>,
    /// Bounded window of the most recently produced blocks, oldest first.
    /// Full history is durably persisted elsewhere (see the node's
    /// append-only block log) - this field intentionally does not grow
    /// without bound.
    pub recent_blocks: VecDeque<Block>,
    pub last_blockhash: [u8; 32],
    pub slot: u64,
    recent_blocks_window: usize,
}

impl Ledger {
    /// A fresh ledger, seeded with the genesis Proof of History hash (used
    /// as the "recent blockhash" before any block has been produced yet).
    pub fn new(genesis_seed: [u8; 32]) -> Self {
        Ledger {
            accounts: HashMap::new(),
            recent_blocks: VecDeque::new(),
            last_blockhash: genesis_seed,
            slot: 0,
            recent_blocks_window: MAX_RECENT_BLOCKS,
        }
    }

    pub fn with_recent_blocks_window(mut self, window: usize) -> Self {
        self.recent_blocks_window = window.max(1);
        self
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

    /// One-time genesis issuance: mints `amount` into `treasury` out of
    /// nothing. This is the *only* place new supply is ever created, and it
    /// must only be invoked once, when a brand new ledger is created (the
    /// node's startup code gates this behind "no prior snapshot exists on
    /// disk"). Everything else that moves treasury funds
    /// (`disburse_from_treasury`) only redistributes what was minted here.
    pub fn genesis_mint(&mut self, treasury: Pubkey, amount: u64) {
        self.accounts
            .entry(treasury)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()))
            .balance += amount;
    }

    /// Move `amount` out of the fixed-supply treasury and into `to`, bounded
    /// by the treasury's actual balance. Used by a devnet faucet
    /// (`requestAirdrop`) to hand out funds for testing without inflating
    /// the total supply - unlike a naive faucet that credits balances out of
    /// thin air, this can never mint a single new unit.
    pub fn disburse_from_treasury(&mut self, treasury: Pubkey, to: Pubkey, amount: u64) -> Result<(), TxError> {
        let treasury_balance = self.accounts.get(&treasury).map(|a| a.balance).unwrap_or(0);
        if treasury_balance < amount {
            return Err(TxError::InsufficientFunds);
        }
        self.accounts.get_mut(&treasury).unwrap().balance -= amount;
        self.accounts
            .entry(to)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()))
            .balance += amount;
        Ok(())
    }

    /// Record a newly produced block as the new chain tip. The block is
    /// still appended to the bounded `recent_blocks` window (for serving
    /// `getBlock` on recent history); callers are responsible for durably
    /// persisting it themselves (e.g. to an append-only log) if long-term
    /// history is needed, since this in-memory window will eventually
    /// evict it.
    pub fn push_block(&mut self, block: Block) {
        self.last_blockhash = block.blockhash;
        self.slot = block.slot;
        self.recent_blocks.push_back(block);
        while self.recent_blocks.len() > self.recent_blocks_window {
            self.recent_blocks.pop_front();
        }
    }

    pub fn latest_blockhash(&self) -> [u8; 32] {
        self.last_blockhash
    }

    pub fn get_recent_block(&self, slot: u64) -> Option<&Block> {
        self.recent_blocks.iter().find(|b| b.slot == slot)
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
        let mut ledger = Ledger::new([0u8; 32]);
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
        let mut ledger = Ledger::new([0u8; 32]);
        ledger.genesis_mint(payer.pubkey(), 10_000);

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
        let mut ledger = Ledger::new([0u8; 32]);
        ledger.genesis_mint(payer.pubkey(), 10_000);

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
    fn genesis_mint_credits_treasury_exactly_once() {
        let mut ledger = Ledger::new([0u8; 32]);
        let treasury = Pubkey::treasury();
        ledger.genesis_mint(treasury, 700_000_000);
        assert_eq!(ledger.get_balance(&treasury), 700_000_000);
    }

    #[test]
    fn disburse_from_treasury_is_bounded_by_its_balance() {
        let mut ledger = Ledger::new([0u8; 32]);
        let treasury = Pubkey::treasury();
        ledger.genesis_mint(treasury, 1_000);
        let alice = supersol_crypto::Keypair::generate().pubkey();

        ledger.disburse_from_treasury(treasury, alice, 600).unwrap();
        assert_eq!(ledger.get_balance(&alice), 600);
        assert_eq!(ledger.get_balance(&treasury), 400);

        // The treasury only has 400 left - asking for 600 more must fail
        // rather than manufacturing new supply.
        assert!(matches!(
            ledger.disburse_from_treasury(treasury, alice, 600),
            Err(TxError::InsufficientFunds)
        ));
        assert_eq!(ledger.get_balance(&alice), 600);
    }

    #[test]
    fn recent_blocks_window_is_bounded() {
        let mut ledger = Ledger::new([0u8; 32]).with_recent_blocks_window(2);
        let mut poh = Poh::new([0u8; 32]);
        for slot in 1..=5u64 {
            let entry: PohEntry = poh.tick();
            ledger.push_block(Block {
                slot,
                leader: Pubkey::system_program_id(),
                previous_blockhash: [0u8; 32],
                blockhash: entry.hash,
                poh_entries: vec![entry],
                transactions: vec![],
                airdrops: vec![],
            });
        }
        assert_eq!(ledger.recent_blocks.len(), 2);
        assert!(ledger.get_recent_block(1).is_none(), "oldest blocks should be evicted");
        assert!(ledger.get_recent_block(5).is_some());
        assert_eq!(ledger.slot, 5);
    }
}
