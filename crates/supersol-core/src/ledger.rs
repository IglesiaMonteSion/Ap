use crate::account::Account;
use crate::block::Block;
use crate::stake::{StakeState, StakeStatus, STAKE_PROGRAM_ID};
use crate::transaction::{Instruction, Transaction};
use borsh::BorshDeserialize;
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

/// Implemented by every native program (System, Stake, Memo, ...). This is
/// intentionally the simplest possible extension point: trusted, natively
/// compiled Rust code rather than a sandboxed bytecode VM. That trade-off is
/// what makes writing a new program here as easy as implementing a trait -
/// the "better dev UX" improvement over Solana's BPF/eBPF toolchain - at the
/// cost of not yet supporting untrusted third-party program deployment.
/// Phase 3 of the roadmap replaces this with a sandboxed (likely WASM) VM
/// without changing the ledger/runtime split above it.
///
/// `accounts` is deliberately *not* the whole ledger: `apply_transaction`
/// only ever hands programs a working set containing the accounts the
/// current transaction's instructions actually reference, so a program can
/// only see and mutate what it was explicitly given - the same
/// least-privilege model Solana programs run under, and the reason
/// per-transaction cost here scales with how many accounts *that*
/// transaction touches rather than with the total number of accounts on
/// the whole chain.
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
    /// Total base units ever destroyed by burned transaction fees. Together
    /// with the treasury and staking-pool balances, this lets `getSupply`
    /// account for every one of the 700,000,000 SSOL minted at genesis.
    pub total_burned: u64,
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
            total_burned: 0,
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

    /// Verify the transaction's signature, burn the flat per-transaction fee,
    /// and run every instruction through its target program. The fee is
    /// burned upfront and is *not* refunded if an instruction later fails -
    /// it must be destroyed regardless of whether the transaction's
    /// instructions succeed, the same way real networks charge fees on
    /// failed transactions, to deter spam.
    ///
    /// Instruction execution builds a small *working set* containing only
    /// the accounts this transaction's instructions reference (not a clone
    /// of every account in the ledger), runs all instructions against it,
    /// and only merges it back into the ledger if every instruction
    /// succeeds - so a failure never partially applies. This keeps
    /// per-transaction cost proportional to how many accounts *it* touches
    /// (almost always a handful) rather than how many accounts exist on the
    /// whole chain, and is also what makes future parallel execution
    /// possible: two transactions whose working sets are disjoint can run
    /// concurrently without stepping on each other.
    pub fn apply_transaction(&mut self, tx: &Transaction, programs: &ProgramRegistry, fee_units: u64) -> Result<(), TxError> {
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
        self.total_burned += fee_units;

        // Only pre-populate entries for accounts that already exist. Genuinely
        // new accounts (e.g. a stake account a CreateAccount instruction is
        // about to create) must stay *absent* from the working set so that a
        // program's own `entry(..).or_insert_with(..)` is the one that
        // creates it - with the owner and initial state the program chooses.
        // Pre-seeding a placeholder here would make that entry already
        // occupied, silently defeating "or_insert_with" and leaving the
        // account owned by nobody in particular.
        let mut working: HashMap<Pubkey, Account> = HashMap::new();
        // The payer is always included, even if no instruction explicitly
        // lists it in `accounts`: programs receive it separately (as their
        // `payer` argument) and may still look it up in the account map
        // (e.g. System's CreateAccount funds a new account from the payer).
        // It's guaranteed to exist by the fee-charging step just above.
        working.insert(tx.message.payer, self.accounts[&tx.message.payer].clone());
        for ix in &tx.message.instructions {
            for pk in &ix.accounts {
                if let Some(account) = self.accounts.get(pk) {
                    working.entry(*pk).or_insert_with(|| account.clone());
                }
            }
        }

        for ix in &tx.message.instructions {
            let program = programs
                .get(&ix.program_id)
                .ok_or(TxError::UnknownProgram(ix.program_id))?;
            program.process(&mut working, ix, &tx.message.payer)?;
        }

        for (pk, account) in working {
            self.accounts.insert(pk, account);
        }
        Ok(())
    }

    /// One-time genesis issuance: mints `amount` into `recipient` out of
    /// nothing. This is the *only* place new supply is ever created, and it
    /// must only be invoked when a brand new ledger is created (the node's
    /// startup code gates this behind "no prior snapshot exists on disk"),
    /// once for the treasury and once for the staking rewards reserve.
    /// Everything else that moves those funds (`disburse_from_treasury`,
    /// `distribute_staking_rewards`) only redistributes what was minted here.
    pub fn genesis_mint(&mut self, recipient: Pubkey, amount: u64) {
        self.accounts
            .entry(recipient)
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

    /// Pay out up to `reward_units_per_epoch` from the staking rewards
    /// reserve, split pro-rata across every currently-active stake account
    /// by its staked balance, and compound the reward straight into that
    /// account's balance. Bounded by the reserve's actual balance - once
    /// it's exhausted, rewards simply stop (no new supply is ever created).
    /// Returns the total amount actually distributed.
    pub fn distribute_staking_rewards(&mut self, staking_pool: Pubkey, reward_units_per_epoch: u64) -> u64 {
        let pool_balance = self.get_balance(&staking_pool);
        if pool_balance == 0 || reward_units_per_epoch == 0 {
            return 0;
        }

        let active_stakes: Vec<(Pubkey, u64)> = self
            .accounts
            .iter()
            .filter(|(_, acc)| acc.owner == STAKE_PROGRAM_ID)
            .filter_map(|(pk, acc)| {
                let state = StakeState::try_from_slice(&acc.data).ok()?;
                (state.status == StakeStatus::Active).then_some((*pk, acc.balance))
            })
            .collect();

        let total_active_stake: u128 = active_stakes.iter().map(|(_, bal)| *bal as u128).sum();
        if total_active_stake == 0 {
            return 0;
        }

        let to_distribute = reward_units_per_epoch.min(pool_balance);
        let mut distributed = 0u64;
        for (pk, stake_balance) in active_stakes {
            let reward = (to_distribute as u128 * stake_balance as u128 / total_active_stake) as u64;
            if reward == 0 {
                continue;
            }
            self.accounts.get_mut(&pk).unwrap().balance += reward;
            distributed += reward;
        }
        self.accounts.get_mut(&staking_pool).unwrap().balance -= distributed;
        distributed
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
        assert!(matches!(
            ledger.apply_transaction(&tx, &programs, 0),
            Err(TxError::InvalidSignature)
        ));
    }

    #[test]
    fn fee_is_burned_not_paid_to_anyone() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
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

        ledger.apply_transaction(&tx, &programs, 500).unwrap();
        assert_eq!(ledger.get_balance(&payer.pubkey()), 9_500);
        assert_eq!(ledger.total_burned, 500);
    }

    #[test]
    fn fee_is_burned_even_if_instruction_fails() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
        let mut ledger = Ledger::new([0u8; 32]);
        ledger.genesis_mint(payer.pubkey(), 10_000);

        struct FailingProgram;
        impl ProgramProcessor for FailingProgram {
            fn process(&self, _: &mut HashMap<Pubkey, Account>, _: &Instruction, _: &Pubkey) -> Result<(), TxError> {
                Err(TxError::ProgramError("boom".into()))
            }
        }
        let program_id = Pubkey::new([9u8; 32]);
        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: vec![],
        };
        let tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(program_id, Box::new(FailingProgram));

        assert!(ledger.apply_transaction(&tx, &programs, 500).is_err());
        assert_eq!(ledger.get_balance(&payer.pubkey()), 9_500);
        assert_eq!(ledger.total_burned, 500);
    }

    #[test]
    fn apply_transaction_only_touches_accounts_the_instructions_reference() {
        use supersol_crypto::Keypair;
        let payer = Keypair::generate();
        let mut ledger = Ledger::new([0u8; 32]);
        ledger.genesis_mint(payer.pubkey(), 10_000);
        // An unrelated account that no instruction in this transaction names.
        let bystander = Keypair::generate().pubkey();
        ledger.genesis_mint(bystander, 42);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![],
            data: vec![],
        };
        let tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(Pubkey::system_program_id(), Box::new(NoopProgram));
        ledger.apply_transaction(&tx, &programs, 100).unwrap();

        assert_eq!(ledger.get_balance(&bystander), 42, "untouched account must be unaffected");
    }

    #[test]
    fn genesis_mint_credits_recipient_exactly_once() {
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

    fn make_stake_account(ledger: &mut Ledger, authority: Pubkey, balance: u64, status: StakeStatus) -> Pubkey {
        let stake_pubkey = supersol_crypto::Keypair::generate().pubkey();
        let state = StakeState {
            authority,
            validator: Pubkey::system_program_id(),
            status,
        };
        ledger.accounts.insert(
            stake_pubkey,
            Account {
                balance,
                owner: STAKE_PROGRAM_ID,
                data: borsh::to_vec(&state).unwrap(),
                executable: false,
            },
        );
        stake_pubkey
    }

    #[test]
    fn staking_rewards_split_pro_rata_and_never_exceed_the_reserve() {
        let mut ledger = Ledger::new([0u8; 32]);
        let pool = Pubkey::staking_rewards_pool();
        ledger.genesis_mint(pool, 1_000);

        let authority = supersol_crypto::Keypair::generate().pubkey();
        let big_stake = make_stake_account(&mut ledger, authority, 900, StakeStatus::Active);
        let small_stake = make_stake_account(&mut ledger, authority, 100, StakeStatus::Active);
        let inactive_stake = make_stake_account(&mut ledger, authority, 500, StakeStatus::Deactivated);

        let distributed = ledger.distribute_staking_rewards(pool, 100);
        assert_eq!(distributed, 100);
        assert_eq!(ledger.get_balance(&big_stake), 900 + 90);
        assert_eq!(ledger.get_balance(&small_stake), 100 + 10);
        assert_eq!(ledger.get_balance(&inactive_stake), 500, "deactivated stake earns nothing");
        assert_eq!(ledger.get_balance(&pool), 900);
    }

    #[test]
    fn staking_rewards_are_capped_by_the_pool_balance() {
        let mut ledger = Ledger::new([0u8; 32]);
        let pool = Pubkey::staking_rewards_pool();
        ledger.genesis_mint(pool, 30);

        let authority = supersol_crypto::Keypair::generate().pubkey();
        make_stake_account(&mut ledger, authority, 1_000, StakeStatus::Active);

        let distributed = ledger.distribute_staking_rewards(pool, 1_000_000);
        assert_eq!(distributed, 30, "can never distribute more than the reserve holds");
        assert_eq!(ledger.get_balance(&pool), 0);
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

    /// Not a correctness test - a single-core throughput measurement of
    /// `apply_transaction`'s overhead (signature verification + fee burn +
    /// working-set construction + program dispatch), run explicitly with
    /// `cargo test --release -p supersol-core -- --ignored --nocapture`.
    /// Uses a no-op program rather than the real System Program's transfer
    /// logic (which lives in `supersol-runtime`, a crate that depends on
    /// this one, not the other way around) - a fair stand-in, since a
    /// transfer's actual arithmetic is negligible next to signature
    /// verification, which dominates real per-transaction cost by roughly
    /// two orders of magnitude (see `supersol-crypto`'s
    /// `bench_hybrid_verify_throughput`).
    #[test]
    #[ignore]
    fn bench_apply_transaction_throughput() {
        use crate::transaction::Instruction as Ix;
        use std::time::Instant;
        use supersol_crypto::Keypair;

        struct NoopProgram;
        impl ProgramProcessor for NoopProgram {
            fn process(&self, _: &mut HashMap<Pubkey, Account>, _: &Instruction, _: &Pubkey) -> Result<(), TxError> {
                Ok(())
            }
        }

        const N: usize = 2_000;

        let mut ledger = Ledger::new([0u8; 32]);
        let mut programs: ProgramRegistry = HashMap::new();
        programs.insert(Pubkey::system_program_id(), Box::new(NoopProgram));

        // Pre-generate distinct signed transactions so the timed loop below
        // measures only `apply_transaction`, not keygen/signing cost.
        let recipient = Keypair::generate().pubkey();
        let mut txs = Vec::with_capacity(N);
        for _ in 0..N {
            let payer = Keypair::generate();
            ledger.genesis_mint(payer.pubkey(), 1_000_000);
            let ix = Ix {
                program_id: Pubkey::system_program_id(),
                accounts: vec![payer.pubkey(), recipient],
                data: vec![],
            };
            txs.push(Transaction::new_signed(&payer, [0u8; 32], vec![ix]));
        }

        let start = Instant::now();
        for tx in &txs {
            ledger.apply_transaction(tx, &programs, 0).unwrap();
        }
        let elapsed = start.elapsed();

        println!(
            "apply_transaction: {:>8.2} tx/sec ({:>6.2} us/tx) over {N} transactions, single core",
            N as f64 / elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1_000_000.0 / N as f64
        );
    }
}
