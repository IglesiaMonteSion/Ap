//! Ties together account storage (`qchain-storage`), native programs, and
//! WASM contracts into `apply_transaction` - the state-transition function
//! this project's execution layer exists to provide. Fee model and dust
//! sweep per `ARCHITECTURE.md` §5.

use crate::error::ExecError;
use crate::ids::{FEE_STATE_ACCOUNT_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID};
use crate::params::{FeeState, FEE_TARGET_BYTES_PER_ROUND};
use crate::native::{NativeProgram, SystemInstruction};
use crate::params::EconomicParams;
use crate::receipt::{CompressedProofSet, StakingEvent, StakingEventKind, TransferReceipt};
use crate::staking::StakeAccountData;
use crate::wasm::WasmExecutor;
use borsh::BorshDeserialize;
use qchain_core::{Account, Instruction, Round, Transaction};
use qchain_crypto::{AlgorithmStatus, Pubkey, RegistryEntry};
use qchain_storage::compressed::{CompressedProof, IncrementalCompressedTree};
use qchain_storage::{IncrementalStateTree, MerkleProof, StateStore};

/// Which state-commitment tree this `Ledger` maintains. `Legacy` is the
/// original 256-deep sparse Merkle tree (`IncrementalStateTree`) - the default,
/// what every existing network runs. `Compressed` is the O(log n) path-compressed
/// tree (`IncrementalCompressedTree`) - a genesis-level opt-in that changes the
/// state root (a hard fork; a network choosing it needs a fresh genesis), giving
/// a measured ~34x faster per-write / ~4x higher apply throughput. The choice is
/// fixed at construction and folded into `chain_id`, so a validator can never
/// silently mix the two.
enum StateTreeImpl {
    Legacy(IncrementalStateTree),
    Compressed(IncrementalCompressedTree),
}

impl StateTreeImpl {
    fn note_set(&mut self, key: &Pubkey, account: &Account) {
        match self {
            StateTreeImpl::Legacy(t) => t.note_set(key, account),
            StateTreeImpl::Compressed(t) => t.note_set(key, account),
        }
    }

    fn root(&self) -> [u8; 32] {
        match self {
            StateTreeImpl::Legacy(t) => t.root(),
            StateTreeImpl::Compressed(t) => t.root(),
        }
    }

    /// Before-state root + inclusion/exclusion proofs for a transfer's two
    /// accounts, for STARK receipt capture - now produced in BOTH modes (the
    /// compressed tree gained `root_with_pending`/`prove_with_pending`, closing
    /// the follow-up that made `Compressed` return `None` here). The proofs come
    /// back as [`CapturedProof`], tagged with whichever tree's format they are,
    /// so the receipt assembler can route them to the right binding shape.
    fn capture_before(&self, from: &Pubkey, to: &Pubkey) -> ([u8; 32], CapturedProof, CapturedProof) {
        match self {
            StateTreeImpl::Legacy(t) => (t.root(), CapturedProof::Legacy(t.prove(from)), CapturedProof::Legacy(t.prove(to))),
            StateTreeImpl::Compressed(t) => (t.root(), CapturedProof::Compressed(t.prove(from)), CapturedProof::Compressed(t.prove(to))),
        }
    }

    /// After-state root + proofs given a transaction's pending working set (the
    /// counterpart to `capture_before`), in whichever tree this ledger runs.
    fn capture_after(&self, from: &Pubkey, to: &Pubkey, changes: &[(Pubkey, Account)]) -> ([u8; 32], CapturedProof, CapturedProof) {
        match self {
            StateTreeImpl::Legacy(t) => (
                t.root_with_pending(changes),
                CapturedProof::Legacy(t.prove_with_pending(from, changes)),
                CapturedProof::Legacy(t.prove_with_pending(to, changes)),
            ),
            StateTreeImpl::Compressed(t) => (
                t.root_with_pending(changes),
                CapturedProof::Compressed(t.prove_with_pending(from, changes)),
                CapturedProof::Compressed(t.prove_with_pending(to, changes)),
            ),
        }
    }
}

/// One captured inclusion/exclusion proof, tagged with the tree format it came
/// from. A `Ledger`'s tree kind is fixed at construction, so all four proofs a
/// single receipt carries are always the same variant.
enum CapturedProof {
    Legacy(MerkleProof),
    Compressed(CompressedProof),
}
use std::collections::HashMap;
use wasmtime::Val;

/// Fuel budget for the WASM half of a transaction. A real deployment would
/// derive this from `Message.fee_limit`; fixed here for phase 1 simplicity.
pub const DEFAULT_FUEL_LIMIT: u64 = 5_000_000;

pub enum Program {
    Native(Box<dyn NativeProgram>),
    Wasm { module_bytes: Vec<u8>, entry_point: String },
}

/// Persistable snapshot of a `Ledger`'s running economic counters. Written to
/// `data_dir/economics` by `qchain-node` and restored on startup so lifetime
/// burn/earnings totals survive a restart. `validator_commissions` is a `Vec`
/// of pairs (not a map) for a stable Borsh encoding.
#[derive(Clone, Default, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EconomicSnapshot {
    pub total_burned: u64,
    pub fee_burned: u64,
    pub dust_burned: u64,
    pub validator_earned: u64,
    pub pool_earned: u64,
    pub validator_commissions: Vec<(Pubkey, u64)>,
    /// v4.0.0 emission total. Appended last; a pre-v4 economics snapshot simply
    /// fails to decode and the report-only counters reset to 0 on that one
    /// upgrade (economics is best-effort/report-only, never consensus state).
    pub total_emitted: u64,
}

pub struct Ledger {
    store: Box<dyn StateStore>,
    programs: HashMap<Pubkey, Program>,
    wasm: WasmExecutor,
    pub total_burned: u64,
    /// Live breakdown of where value flows, so a validator operator can see
    /// the real economics (not just a single "burned" number). All are running
    /// totals since this `Ledger` was constructed (in-memory, reset on restart,
    /// the same deliberate limitation as `total_burned`/`transfer_receipts`),
    /// and all are deterministic across nodes (every node applies the same
    /// transactions with the same `fee_collector`), so they agree network-wide.
    /// `fee_burned + dust_burned == total_burned` by construction.
    pub fee_burned: u64,
    /// Burned specifically by the dust sweep - the "excess left in accounts"
    /// below `dust_threshold` that gets zeroed and destroyed. The user asked
    /// to see this separately from the fee burn.
    pub dust_burned: u64,
    /// Total paid out to validators as direct commission (the `fee_collector`
    /// of each block, i.e. the proposer, keeps this share immediately). This is
    /// literally how a validator earns: half of every fee is not burned, and
    /// `staking_commission_bps` of that half is the validator's cut.
    pub validator_earned: u64,
    /// Total routed into the shared staking rewards pool (the rest of the
    /// non-burned fee half), later claimable by delegators pro-rata.
    pub pool_earned: u64,
    /// Total NEW QCH minted as staking-reward emission (v4.0.0) - the real
    /// inflation counterpart to `total_burned`. Running total since this
    /// `Ledger` was constructed, deterministic across nodes, persisted via
    /// `export_economics`. `pool_earned` above counts only the fee-funded
    /// pool inflow; this counts the freshly-emitted inflow.
    pub total_emitted: u64,
    /// Real, live-maintained incremental sparse Merkle tree - see
    /// `qchain-storage::tree`'s `IncrementalStateTree` doc comment for
    /// the measured performance problem this closes (a single validator
    /// under real transfer load saturating a full CPU core, root-caused
    /// to the plain `StateTree`'s full-recompute-on-every-call design,
    /// not PQC signature verification as initially suspected - see
    /// `project-lessons-learned`). Every real write this `Ledger` makes
    /// to `self.store` is paired with a `self.tree.note_set(...)` call at
    /// the same call site (`write_account`, the one and only place a raw
    /// `self.store.set` is allowed below - enforced by convention and by
    /// this doc comment, not by the type system, so any future new write
    /// site must go through it too) - this pairing is the whole
    /// correctness invariant this type depends on: `self.tree` only ever
    /// answers correctly for keys this exact `Ledger` has itself written.
    tree: StateTreeImpl,
    /// Real captured before/after state for every single-instruction
    /// `Transfer` this ledger has applied - see `receipt.rs` module docs
    /// for exactly what's captured, why it's scoped this narrowly, and
    /// the deliberate "unbounded in-memory `Vec`" limitation.
    transfer_receipts: Vec<TransferReceipt>,
    /// Captured staking actions (Delegate/Undelegate/ClaimReward), so the
    /// dashboard can show staking activity that the transfer list can't
    /// (staking instructions never produce a `TransferReceipt`). Same
    /// in-memory/unbounded/reset-on-restart limitation as `transfer_receipts`.
    staking_events: Vec<StakingEvent>,
    /// Per-`fee_collector` (validator) running total of direct commission
    /// earned, so a node can report *its own* real earnings (not just the
    /// network-wide `validator_earned`). Keyed by the block proposer's
    /// address; bounded by the validator-set size. Persisted by `qchain-node`
    /// via `export_economics`/`import_economics` so it survives restarts.
    validator_commissions: std::collections::BTreeMap<Pubkey, u64>,
}

impl Ledger {
    /// The legacy (256-deep tree) ledger - the default every existing network
    /// uses. Backward-compatible signature.
    pub fn new(store: Box<dyn StateStore>) -> anyhow::Result<Self> {
        Self::new_with_tree(store, false)
    }

    /// Construct a ledger choosing its state-commitment tree: `compressed =
    /// false` is the legacy 256-deep tree (default, byte-identical to `new`);
    /// `compressed = true` is the O(log n) path-compressed tree - a genesis-level
    /// hard-fork opt-in (different state root; needs a fresh genesis). See
    /// `StateTreeImpl`.
    pub fn new_with_tree(store: Box<dyn StateStore>, compressed: bool) -> anyhow::Result<Self> {
        // A store opened from a prior run (`SledStore` pointed at an
        // existing `data_dir`) already holds real accounts the tree has
        // never seen - prime the cache from the store's own contents
        // once at construction so `note_set` alone is sufficient from
        // here on. A fresh/empty store makes this a no-op loop.
        let mut tree = if compressed {
            StateTreeImpl::Compressed(IncrementalCompressedTree::new())
        } else {
            StateTreeImpl::Legacy(IncrementalStateTree::new())
        };
        for (pk, account) in store.iter() {
            tree.note_set(&pk, &account);
        }
        Ok(Ledger {
            store,
            programs: HashMap::new(),
            wasm: WasmExecutor::new()?,
            total_burned: 0,
            fee_burned: 0,
            dust_burned: 0,
            validator_earned: 0,
            pool_earned: 0,
            total_emitted: 0,
            tree,
            transfer_receipts: Vec::new(),
            staking_events: Vec::new(),
            validator_commissions: std::collections::BTreeMap::new(),
        })
    }

    pub fn register_program(&mut self, id: Pubkey, program: Program) {
        self.programs.insert(id, program);
    }

    pub fn store(&self) -> &dyn StateStore {
        self.store.as_ref()
    }

    /// Force the backing store's buffered writes durable to disk (see
    /// `StateStore::flush`). Called on a graceful shutdown so a restart never
    /// resumes from a `round_checkpoint` that is ahead of the persisted account
    /// state. No-op for the in-memory store.
    pub fn flush(&self) {
        self.store.flush();
    }

    /// The only place this `Ledger` is allowed to write to `self.store` -
    /// see `tree`'s doc comment for why every write must go through here
    /// rather than calling `self.store.set` directly.
    fn write_account(&mut self, pubkey: Pubkey, account: Account) {
        self.tree.note_set(&pubkey, &account);
        self.store.set(pubkey, account);
    }

    /// The live root of the real state tree (`qchain-storage`'s
    /// SHA3-256 sparse Merkle tree) - an `O(1)` read of the incrementally
    /// maintained `IncrementalStateTree` above, not a recompute.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Whether this ledger runs the path-compressed state tree (vs the legacy
    /// 256-deep one). The node's `/stark_proof` builder reads this to choose the
    /// binding format (`CompressedRowStateBinding` vs `RowStateBinding`).
    pub fn is_compressed(&self) -> bool {
        matches!(self.tree, StateTreeImpl::Compressed(_))
    }

    /// Every `Transfer` receipt captured so far, oldest first - the raw
    /// material a light-client-facing RPC endpoint proves a
    /// `qchain-stark` batch from. See `receipt.rs` for scope.
    pub fn transfer_receipts(&self) -> &[TransferReceipt] {
        &self.transfer_receipts
    }

    /// Restores previously-captured receipts (loaded from disk by
    /// `qchain-node` on startup) as the initial history, oldest first, so
    /// the transfer log survives a restart instead of being lost the way
    /// an in-memory `Vec` alone would lose it. Called once, before the
    /// node replays any committed transactions - replayed transactions are
    /// rejected by the nonce check in `apply_transaction` and so never
    /// re-append a duplicate receipt, keeping the restored history exact.
    pub fn restore_receipts(&mut self, receipts: Vec<TransferReceipt>) {
        self.transfer_receipts = receipts;
    }

    /// Captured staking activity (Delegate/Undelegate/ClaimReward), oldest
    /// first - what the dashboard and the wallet's activity view render so
    /// staking shows up alongside plain transfers.
    pub fn staking_events(&self) -> &[StakingEvent] {
        &self.staking_events
    }

    /// Restores staking activity loaded from disk on startup, same contract as
    /// `restore_receipts` (nonce check prevents replayed txs re-appending).
    pub fn restore_staking_events(&mut self, events: Vec<StakingEvent>) {
        self.staking_events = events;
    }

    /// Bounds the in-memory transfer-receipt log to at most `max` entries,
    /// dropping the OLDEST when over the cap (keeping the most recent window).
    ///
    /// Each receipt carries four Merkle proofs (~32 KB total: 4 × 256 sibling
    /// hashes × 32 B), so an unbounded log turns chain age directly into RAM -
    /// a 50k-transfer flood is ~1.6 GB, and reloading that many from disk on
    /// boot stalls startup for tens of seconds (both measured live). The
    /// `/stark_proof` endpoint already serves only the last `<= 500` receipts,
    /// and dropping from the FRONT never breaks the contiguity of the retained
    /// suffix (each receipt's `root_before`/`root_after` still chains to its
    /// neighbour), so bounding is safe for the proof chain. The on-disk log
    /// keeps the full history for the explorer; this only caps the live window.
    ///
    /// The caller (the node's commit loop) invokes this ONLY after it has
    /// finished capturing the per-transaction receipt delta by index for that
    /// batch, so draining the front here never invalidates a live index.
    pub fn cap_receipt_log(&mut self, max: usize) {
        let len = self.transfer_receipts.len();
        if len > max {
            self.transfer_receipts.drain(0..len - max);
        }
    }

    /// Bounds the in-memory staking-event log to `max` entries (same rationale
    /// and same drain-oldest policy as `cap_receipt_log`). Staking events are
    /// far smaller (no Merkle proofs), but keeping the window bounded keeps the
    /// dashboard/wallet activity view and boot-time reload cost predictable.
    pub fn cap_staking_events(&mut self, max: usize) {
        let len = self.staking_events.len();
        if len > max {
            self.staking_events.drain(0..len - max);
        }
    }

    /// This validator's own accumulated direct commission (as `fee_collector`).
    /// Distinct from the network-wide `validator_earned` total.
    pub fn commission_of(&self, validator: &Pubkey) -> u64 {
        self.validator_commissions.get(validator).copied().unwrap_or(0)
    }

    /// Serializable snapshot of the running economic counters, so `qchain-node`
    /// can persist them to disk and they survive a restart (an in-memory `Vec`
    /// alone would reset to zero, misreporting lifetime burn/earnings).
    pub fn export_economics(&self) -> EconomicSnapshot {
        EconomicSnapshot {
            total_burned: self.total_burned,
            fee_burned: self.fee_burned,
            dust_burned: self.dust_burned,
            validator_earned: self.validator_earned,
            pool_earned: self.pool_earned,
            validator_commissions: self.validator_commissions.iter().map(|(k, v)| (*k, *v)).collect(),
            total_emitted: self.total_emitted,
        }
    }

    /// Restores previously-persisted economic counters on startup. Called once,
    /// before any transaction replay - replayed transactions are nonce-rejected
    /// and so never double-count into these totals.
    pub fn import_economics(&mut self, snap: EconomicSnapshot) {
        self.total_burned = snap.total_burned;
        self.fee_burned = snap.fee_burned;
        self.dust_burned = snap.dust_burned;
        self.validator_earned = snap.validator_earned;
        self.pool_earned = snap.pool_earned;
        self.total_emitted = snap.total_emitted;
        self.validator_commissions = snap.validator_commissions.into_iter().collect();
    }

    /// Writes an account directly into the store - genesis-time seeding
    /// of program-owned singleton accounts (the staking-stats counter,
    /// the algorithm registry), not a user-facing operation like
    /// `credit`.
    pub fn seed_account(&mut self, pubkey: Pubkey, account: Account) {
        self.write_account(pubkey, account);
    }

    pub fn get_balance(&self, pk: &Pubkey) -> u64 {
        self.store.get(pk).map(|a| a.balance).unwrap_or(0)
    }

    pub fn credit(&mut self, pk: Pubkey, amount: u64) {
        let mut account = self.store.get(&pk).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
        account.balance = account.balance.saturating_add(amount);
        self.write_account(pk, account);
    }

    /// Splits the validator's post-burn share of `base_fee` between direct
    /// commission (`fee_collector`, paid immediately, same as before this
    /// mechanism existed) and the shared delegator reward pool
    /// (`STAKING_REWARDS_POOL_ID`), per the live `staking_commission_bps`.
    /// See `staking.rs`'s module docs for the reward-per-share accumulator
    /// this feeds, and `ARCHITECTURE.md` §5 for the design. Falls back to
    /// crediting `fee_collector` with the whole share, exactly like
    /// pre-staking-reward behavior, whenever nothing is delegated yet
    /// (`staking::accrue_reward_pool` reports this via its `bool` return
    /// rather than this method re-deriving total stake).
    fn credit_validator_share(&mut self, fee_collector: Pubkey, validator_share: u64, params: &EconomicParams) -> Result<(), ExecError> {
        if validator_share == 0 {
            return Ok(());
        }
        let commission = (validator_share as u128 * params.staking_commission_bps as u128 / 10_000) as u64;
        let pool_share = validator_share - commission;

        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        if let Some(stats) = self.store.get(&STAKING_STATS_ID) {
            accounts.insert(STAKING_STATS_ID, stats);
        }
        if let Some(pool) = self.store.get(&STAKING_REWARDS_POOL_ID) {
            accounts.insert(STAKING_REWARDS_POOL_ID, pool);
        }

        let credited = crate::staking::accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, pool_share)?;
        if credited {
            if let Some(pool) = accounts.remove(&STAKING_REWARDS_POOL_ID) {
                self.write_account(STAKING_REWARDS_POOL_ID, pool);
            }
            self.credit(fee_collector, commission);
            self.validator_earned = self.validator_earned.saturating_add(commission);
            self.pool_earned = self.pool_earned.saturating_add(pool_share);
            self.note_validator_commission(fee_collector, commission);
        } else {
            // No delegators yet: the validator keeps the whole non-burned
            // share (its commission is effectively 100% of it).
            self.credit(fee_collector, validator_share);
            self.validator_earned = self.validator_earned.saturating_add(validator_share);
            self.note_validator_commission(fee_collector, validator_share);
        }
        Ok(())
    }

    /// The economic parameters currently in effect - read live from
    /// `PARAMS_ACCOUNT_ID` (governable via a `Low`-tier proposal, see
    /// `governance.rs`), falling back to `EconomicParams::default()` if
    /// that account hasn't been seeded (e.g. a bare `Ledger` built
    /// directly in a test, never wired to `qchain-node`'s genesis
    /// seeding). Read fresh on every `apply_transaction` call rather than
    /// cached, so a passed-and-executed governance proposal takes effect
    /// on the very next transaction, not after a restart.
    pub fn current_params(&self) -> EconomicParams {
        self.store
            .get(&PARAMS_ACCOUNT_ID)
            .and_then(|a| EconomicParams::read_or_legacy(&a.data))
            .unwrap_or_default()
    }

    /// The dynamic-fee accumulator (see `params::FeeState`), or a fresh default
    /// if `FEE_STATE_ACCOUNT_ID` hasn't been created yet.
    pub fn current_fee_state(&self) -> FeeState {
        self.store
            .get(&FEE_STATE_ACCOUNT_ID)
            .and_then(|a| FeeState::try_from_slice(&a.data).ok())
            .unwrap_or_default()
    }

    /// The base fee a transaction committed at `current_round` should actually
    /// pay: the stored `base_fee_per_byte` rolled forward through every elapsed
    /// (mostly empty) round since the fee epoch last closed - see
    /// `params::rolled_base_fee`. This is the value used for CHARGING (in
    /// `apply_transaction`), for ADMISSION (`payer_can_afford_admission`), and
    /// for DISPLAY (`/status`, `/economics`), so an idle chain's fee visibly
    /// decays and low-balance wallets are unlocked WITHOUT any state write - the
    /// stored value only catches up when a transaction commits (STARK-safe, see
    /// `rolled_base_fee`'s doc). Deterministic: a pure function of `current_round`
    /// plus the committed `FeeState`/params, so every validator charges the
    /// identical fee (no fork). If `FEE_STATE_ACCOUNT_ID` doesn't exist yet (no
    /// transaction since genesis / the dynamic-fee upgrade), there's no epoch to
    /// roll - return the stored base unchanged, matching `advance_dynamic_fee`'s
    /// `existing.is_none()` branch.
    pub fn effective_base_fee_at(&self, current_round: Round) -> u64 {
        let base = self.current_params().base_fee_per_byte;
        match self.store.get(&FEE_STATE_ACCOUNT_ID).and_then(|a| FeeState::read_or_legacy(&a.data)) {
            Some(fs) => crate::params::rolled_base_fee(base, fs.epoch_round, fs.epoch_bytes, current_round, FEE_TARGET_BYTES_PER_ROUND),
            None => base,
        }
    }

    /// Advances the EIP-1559-style dynamic base fee. Called once per applied
    /// transaction, INSIDE `apply_transaction` (so every write here lands in the
    /// same committed state transition and the same Merkle root - keeping both
    /// cross-validator determinism and the STARK receipt chain intact). It
    /// accumulates this transaction's bytes into the current fee epoch (one
    /// consensus round); when a transaction from a later round arrives, it
    /// closes the previous epoch, nudging `base_fee_per_byte` up or down toward
    /// `FEE_TARGET_BYTES_PER_ROUND` (see `next_base_fee`), and starts a fresh
    /// epoch. All state (`FeeState`, `base_fee_per_byte`) is on-chain and
    /// persisted, so a restarted validator resumes with the identical fee.
    ///
    /// This tx has already been charged at the pre-roll `base_fee` (a round's
    /// fee is effectively set by the previous round's traffic, EIP-1559-style);
    /// the roll here affects subsequent transactions, never retroactively this
    /// one. Placed after the fee charge and before the receipt's `root_after`
    /// capture on purpose.
    fn advance_dynamic_fee(&mut self, current_round: Round, tx_bytes: u64) {
        let existing = self.store.get(&FEE_STATE_ACCOUNT_ID);
        let mut fs = existing
            .as_ref()
            .and_then(|a| FeeState::read_or_legacy(&a.data))
            .unwrap_or(FeeState { epoch_round: current_round, epoch_bytes: 0, emission_carry: 0 });

        if existing.is_some() && current_round > fs.epoch_round {
            // Close the previous epoch AND roll the fee through every empty
            // round since it. `advance_dynamic_fee` only runs on a committed
            // transaction, so before this an idle gap (or a flood that priced
            // every queued tx out, so none advanced the epoch) never decayed:
            // the fee froze at its peak and the first tx after the gap saw a
            // single ~12.5% step instead of the full catch-up. Real deadlock
            // the stress bot hit and the user saw live - base_fee pinned at
            // 197766 (~1100x the floor) with rounds advancing but nothing
            // executing, unrecoverable without a manual repeg. Fix: apply the
            // closing round's real traffic (`epoch_bytes`), then one
            // below-target decay step per EMPTY round in between (each had
            // zero committed bytes, else a tx from it would have advanced the
            // epoch). EIP-1559's base fee likewise drops on every under-full
            // block, not only when the next tx happens to land. Deterministic:
            // a pure function of the committed round span + committed bytes, so
            // every validator computes the identical base fee (no fork).
            let mut params = self.current_params();
            // The rolled base = the closing round's real traffic + one decay
            // step per empty round since, early-exiting at the floor. Shared
            // with `effective_base_fee_at` (the read-time twin) so a committed
            // transaction always writes exactly the value every reader already
            // saw for `current_round` - the stored state simply catches up.
            let new_base = crate::params::rolled_base_fee(
                params.base_fee_per_byte,
                fs.epoch_round,
                fs.epoch_bytes,
                current_round,
                FEE_TARGET_BYTES_PER_ROUND,
            );
            if new_base != params.base_fee_per_byte {
                params.base_fee_per_byte = new_base;
                let mut pacct = self
                    .store
                    .get(&PARAMS_ACCOUNT_ID)
                    .unwrap_or_else(|| Account::new_wallet(Pubkey::new([3u8; 32])));
                pacct.data = borsh::to_vec(&params).expect("params always serialize");
                self.write_account(PARAMS_ACCOUNT_ID, pacct);
            }
            // Emission (v4.0.0): mint new QCH into the delegator reward pool for
            // every round that elapsed in the just-closed span, funding the
            // target staking APR on top of fees. Deterministic: every validator
            // computes the identical mint from the identical committed
            // `total_staked`/`emission_apr_bps`/elapsed-rounds/carry, so no fork.
            // `accrue_reward_pool` both mints the whole units to the pool balance
            // (real new supply / inflation) and distributes them to stakers via
            // the reward-per-share accumulator. Nothing is emitted when nothing
            // is staked (`total_staked == 0`) or the APR is 0 (emission off) - the
            // block is skipped entirely, so the fractional carry is untouched
            // (it freezes at its last sub-unit value, always < 1 unit, and simply
            // resumes accumulating if emission is switched back on later).
            let total_staked = self.store.get(&STAKING_STATS_ID).and_then(|a| u64::try_from_slice(&a.data).ok()).unwrap_or(0);
            if total_staked > 0 && params.emission_apr_bps > 0 {
                let rounds = (current_round - fs.epoch_round).min(crate::params::ROUNDS_PER_YEAR);
                let (whole, new_carry) = crate::params::emission_for_rounds(total_staked, params.emission_apr_bps, rounds, fs.emission_carry);
                // Advance the carry only for the fraction that WON'T be minted
                // this epoch. The `whole` units are subtracted from the carry
                // (folded into `new_carry`) ONLY once the mint is confirmed
                // below - otherwise a failed mint (a corrupt pool singleton, the
                // only way `accrue_reward_pool` returns anything but `Ok(true)`
                // here since `total_staked > 0` is already gated) would silently
                // drop those units (a deflationary loss). On failure the carry is
                // left carrying the full fixed-point amount, so the next epoch
                // retries it - emission is never lost, only deferred.
                fs.emission_carry = new_carry;
                if whole > 0 {
                    let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
                    if let Some(s) = self.store.get(&STAKING_STATS_ID) {
                        accounts.insert(STAKING_STATS_ID, s);
                    }
                    if let Some(p) = self.store.get(&STAKING_REWARDS_POOL_ID) {
                        accounts.insert(STAKING_REWARDS_POOL_ID, p);
                    }
                    if let Ok(true) = crate::staking::accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, whole) {
                        if let Some(pool) = accounts.remove(&STAKING_REWARDS_POOL_ID) {
                            self.write_account(STAKING_REWARDS_POOL_ID, pool);
                        }
                        self.total_emitted = self.total_emitted.saturating_add(whole);
                    } else {
                        // Mint didn't land: restore the `whole` units to the carry
                        // (new_carry + whole·PRECISION == the original total
                        // fixed-point) so nothing is lost and the next epoch retries.
                        fs.emission_carry = new_carry
                            .saturating_add((whole as u128).saturating_mul(crate::params::EMISSION_PRECISION));
                    }
                }
            }
            fs.epoch_round = current_round;
            fs.epoch_bytes = 0;
        } else if existing.is_none() {
            // First transaction after the dynamic-fee upgrade (or at genesis):
            // just start the epoch, nothing to close yet. Deterministic: every
            // validator hits this at the same committed transaction.
            fs.epoch_round = current_round;
            fs.epoch_bytes = 0;
        }
        fs.epoch_bytes = fs.epoch_bytes.saturating_add(tx_bytes);

        // Persist. Program-owned (not system) so the dust sweep never touches
        // it (and its balance is always 0 regardless).
        let mut acct = existing.unwrap_or_else(|| Account::new_wallet(FEE_STATE_ACCOUNT_ID));
        acct.data = borsh::to_vec(&fs).expect("FeeState always serializes");
        self.write_account(FEE_STATE_ACCOUNT_ID, acct);
    }

    /// The live on-chain algorithm registry - real, governance-mutable
    /// (see `governance.rs`'s `apply_registry_action`), falling back to
    /// `genesis_registry()` if `REGISTRY_ACCOUNT_ID` hasn't been seeded
    /// (e.g. a bare `Ledger` built directly in a test). Read fresh on
    /// every `apply_transaction`, same rationale as `current_params()` -
    /// a passed `ActivateAlgorithm`/`DeprecateAlgorithm`/`RetireAlgorithm`
    /// proposal takes effect on the very next transaction.
    fn current_registry(&self) -> Vec<RegistryEntry> {
        self.store
            .get(&REGISTRY_ACCOUNT_ID)
            .and_then(|a| Vec::<RegistryEntry>::try_from_slice(&a.data).ok())
            .unwrap_or_else(qchain_crypto::registry::genesis_registry)
    }

    /// The real closure of the "the registry is bookkeeping only" gap (see
    /// `project-lessons-learned`): rejects a transaction whose payer combo
    /// includes a scheme that isn't registered at all, is `Retired`
    /// outright, or - for a brand-new account only - is `Deprecated`
    /// (existing accounts keep working through a scheme's deprecation
    /// grace period, matching `AlgorithmStatus::Deprecated`'s own
    /// documented semantics; only new accounts are turned away from it).
    fn check_registry_status(&self, tx: &Transaction, is_new_account: bool) -> Result<(), ExecError> {
        let Some(combo) = tx.resolved_combo() else {
            return Err(ExecError::AlgorithmNotAcceptable("payer key bundle does not resolve to any known combo".to_string()));
        };
        let components = qchain_crypto::combo_components(combo)
            .ok_or_else(|| ExecError::AlgorithmNotAcceptable(format!("unknown combo {combo:?}")))?;
        let registry = self.current_registry();
        for scheme in components {
            match registry.iter().find(|e| e.id == *scheme).map(|e| &e.status) {
                None => return Err(ExecError::AlgorithmNotAcceptable(format!("scheme {scheme:?} is not registered"))),
                Some(AlgorithmStatus::Retired) => {
                    return Err(ExecError::AlgorithmNotAcceptable(format!("scheme {scheme:?} is retired")))
                }
                Some(AlgorithmStatus::Deprecated { .. }) if is_new_account => {
                    return Err(ExecError::AlgorithmNotAcceptable(format!(
                        "scheme {scheme:?} is deprecated; no new accounts may adopt it"
                    )))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Verify the transaction, confirm every scheme in the payer's combo is
    /// still acceptable per the live registry, charge the byte-scaled base
    /// fee (split between burning and `fee_collector`, per
    /// `ARCHITECTURE.md` §5), then dispatch every instruction to its
    /// program. Instruction execution uses a *working set* scoped to the
    /// accounts this transaction actually references - not a clone of the
    /// whole store - see the `blockchain-core-rust` skill for why that
    /// distinction is load-bearing, not just an optimization.
    pub fn apply_transaction(&mut self, tx: &Transaction, fee_collector: &Pubkey, current_round: Round) -> Result<u64, ExecError> {
        self.apply_transaction_inner(tx, fee_collector, current_round, true)
    }

    /// Same as `apply_transaction`, but ASSUMES the caller has already verified
    /// `tx.verify_signature()` (returned `true`) - it skips only the pure,
    /// state-independent PQC signature check, doing everything else identically.
    /// This is the one thing about applying a transaction that can be computed
    /// **in parallel, ahead of time**, off the sequential commit thread: signature
    /// verification is a pure function of the transaction bytes and the embedded
    /// key bundle, with no dependence on ledger state or on any other transaction,
    /// so its accept/reject verdict is identical no matter when or on which thread
    /// it runs. `qchain-node`'s commit loop verifies a whole committed batch's
    /// signatures across a thread pool, then calls THIS for each one in order -
    /// the application (state mutation, fee, registry gating, receipts) stays
    /// strictly sequential and byte-for-byte deterministic. A caller that has NOT
    /// verified the signature must use `apply_transaction` instead; feeding an
    /// unverified transaction here would let a forged signature through.
    pub fn apply_transaction_presigned(&mut self, tx: &Transaction, fee_collector: &Pubkey, current_round: Round) -> Result<u64, ExecError> {
        self.apply_transaction_inner(tx, fee_collector, current_round, false)
    }

    fn apply_transaction_inner(&mut self, tx: &Transaction, fee_collector: &Pubkey, current_round: Round, verify_sig: bool) -> Result<u64, ExecError> {
        if verify_sig && !tx.verify_signature() {
            return Err(ExecError::InvalidSignature);
        }

        let mut payer_account = self.store.get(&tx.message.payer).unwrap_or_else(|| {
            let combo = tx.resolved_combo().unwrap_or(qchain_crypto::COMBO_HYBRID_ED25519_ML_DSA_65);
            Account { algorithm_id: combo, ..Account::new_wallet(Pubkey::system_program_id()) }
        });
        // "New account" for registry-gating purposes means this is the
        // first transaction ever *signed by* this address as a payer
        // (nonce still at its initial 0) - not merely "does an Account
        // row exist," since an address commonly exists already from
        // passively receiving a transfer (native.rs's Transfer creates
        // the destination account with no signature/combo check at all)
        // long before it ever signs anything itself.
        let is_first_transaction_from_this_payer = payer_account.nonce == 0;
        self.check_registry_status(tx, is_first_transaction_from_this_payer)?;

        let params = self.current_params();
        // Charge the EFFECTIVE base fee for this round - the stored
        // `base_fee_per_byte` rolled forward through every empty round since the
        // fee epoch last closed (see `effective_base_fee_at`). This is what makes
        // an idle chain heal on its own: after a flood spikes the fee and traffic
        // pauses, the effective fee decays round by round on READ, so the next
        // transaction (from any wallet) is both admitted and charged at the
        // decayed rate - no funded "unstick" transaction needed. `advance_dynamic_fee`
        // below writes this exact same rolled value, so the stored state catches
        // up in this tx's own (STARK-safe) transition.
        //
        // `saturating_mul`, not `*`: the base fee is governance-set / dynamic
        // (bounded above by `MAX_BASE_FEE_PER_BYTE` but still multi-KB `byte_size`
        // can overflow `u64`), and a plain `*` wraps in release to a small/garbage
        // fee (trivializing or bricking fee collection). Matches the sibling
        // trap-billing path (`bill_trapped_wasm_fuel`) and the admission-time
        // check (`payer_can_afford_admission`). Saturation to `u64::MAX` means the
        // payer simply can't afford it and the tx is rejected.
        let effective_base = self.effective_base_fee_at(current_round);
        let byte_fee = effective_base.saturating_mul(tx.byte_size() as u64);
        // The optional priority-fee tip (see `Message::priority_fee`), charged
        // on top of the base fee and paid 100% to the proposer. Saturating add
        // so a maliciously huge tip can't wrap; the payer simply can't afford it.
        let priority_fee = tx.message.priority_fee;
        let upfront_fee = byte_fee.saturating_add(priority_fee);
        if payer_account.balance < upfront_fee {
            // Fee-decay deadlock fix: still TICK the dynamic fee even though this
            // transaction can't pay it. `advance_dynamic_fee` only closes the fee
            // epoch (and thus DECAYS the base fee toward the floor on a
            // below-target round) when it runs - and it used to run only for
            // transactions that could afford the fee. Under a heavy flood the fee
            // spikes so high that EVERY queued transaction fails this check, so
            // `advance_dynamic_fee` never ran and the fee stayed pinned high
            // forever (a real DoS/robustness gap the stress bot surfaced). Ticking
            // with 0 bytes closes the round's epoch without counting this
            // (uncommitted) transaction's bytes, so a round full of unaffordable
            // transactions reads as below-target and the fee decays back down -
            // like Ethereum's base fee dropping on an under-full block. Runs on
            // the identical committed order at every validator, so it stays
            // deterministic / fork-free.
            self.advance_dynamic_fee(current_round, 0);
            return Err(ExecError::InsufficientFunds);
        }
        // Real enforcement of a field that used to be signed and
        // transmitted but never checked (found live during the security
        // review - see `project-lessons-learned`): reject before any state
        // is touched if even the byte fee alone already exceeds what the
        // payer capped. The real, documented scenario this protects
        // against is `propose-set-base-fee` governance repricing the byte
        // fee while a transaction sits in the mempool - the payer's own
        // declared ceiling from when they signed, not the network's
        // current price, is what should decide whether it still executes.
        if upfront_fee > tx.message.fee_limit {
            // Same fee-decay tick as the insufficient-funds path above: a
            // transaction whose (risen) fee now exceeds its declared fee_limit
            // must still let the round's fee epoch close, or a flood that prices
            // every queued transaction past its limit would pin the fee forever.
            self.advance_dynamic_fee(current_round, 0);
            return Err(ExecError::FeeExceedsLimit { actual: upfront_fee, limit: tx.message.fee_limit });
        }
        if payer_account.nonce != tx.message.nonce {
            return Err(ExecError::ProgramError(format!(
                "nonce mismatch: account is at {}, transaction has {}",
                payer_account.nonce, tx.message.nonce
            )));
        }
        // Snapshot "before" state for a `qchain-stark` receipt *here* -
        // strictly before the byte-scaled fee is deducted below - because
        // the STARK's conservation equation is
        // `from_after == from_before - amount - fee`: it subtracts the fee
        // itself, so `from_before` must be the balance *prior to* the fee
        // deduction too, not just prior to the `Transfer` instruction. A
        // previous version of this code captured `from_before`/`root_before`
        // from the post-fee-deduction store (via the `working` set built
        // below, which is only ever populated from `self.store` after the
        // fee was already committed to it) - real bug caught by
        // `a_single_instruction_transfer_captures_a_real_verifiable_receipt`
        // failing with the fee silently double-counted in the conservation
        // check. Only the exact shape `qchain-stark`'s AIR models applies:
        // a single-instruction transaction whose one instruction is a
        // `Transfer` (see `receipt.rs` module docs for why - `SystemProgram`
        // already enforces `from == payer`, so this covers every real
        // self-paying transfer). `self.store` is still untouched at this
        // point, so no overlay is needed - a direct read is the real
        // pre-transaction state.
        #[allow(clippy::type_complexity)]
        let pre_capture: Option<(Pubkey, Pubkey, u64, Account, Account, [u8; 32], CapturedProof, CapturedProof)> =
            if tx.message.instructions.len() == 1 && tx.message.instructions[0].program_id == Pubkey::system_program_id() {
                let ix = &tx.message.instructions[0];
                match (SystemInstruction::try_from_slice(&ix.data), ix.accounts.first(), ix.accounts.get(1)) {
                    (Ok(SystemInstruction::Transfer { amount }), Some(&from), Some(&to)) => {
                        // Captured in BOTH tree modes now (compressed included):
                        // `capture_before` returns proofs tagged with the tree's
                        // format. `self.store` is still untouched here, so a
                        // direct read is the real pre-transaction state.
                        let (root_before, from_proof_before, to_proof_before) = self.tree.capture_before(&from, &to);
                        let from_before = self.store.get(&from).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
                        let to_before = self.store.get(&to).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
                        Some((from, to, amount, from_before, to_before, root_before, from_proof_before, to_proof_before))
                    }
                    _ => None,
                }
            } else {
                None
            };

        // Capture staking activity (Delegate/Undelegate/ClaimReward) the same
        // way transfers are captured: read the pre-state now (before the
        // instruction runs), and only record it at the end if the whole
        // transaction commits. Scoped to single-instruction staking txs - the
        // exact shape the CLI/wallet build. See `receipt::StakingEvent`.
        let pre_staking: Option<StakingEvent> = if tx.message.instructions.len() == 1
            && tx.message.instructions[0].program_id == STAKING_PROGRAM_ID
        {
            let ix = &tx.message.instructions[0];
            let tx_hash = tx.hash();
            let sys = Pubkey::system_program_id();
            match crate::staking::StakingInstruction::try_from_slice(&ix.data) {
                Ok(crate::staking::StakingInstruction::Delegate { validator, amount }) => Some(StakingEvent {
                    tx_hash,
                    kind: StakingEventKind::Delegate,
                    staker: ix.accounts.first().copied().unwrap_or(sys),
                    validator,
                    stake_account: ix.accounts.get(1).copied().unwrap_or(sys),
                    amount,
                    round: current_round,
                }),
                Ok(crate::staking::StakingInstruction::Undelegate) => {
                    let stake_account = ix.accounts.first().copied().unwrap_or(sys);
                    let sad = self.store.get(&stake_account).and_then(|a| StakeAccountData::try_from_slice(&a.data).ok());
                    sad.map(|s| StakingEvent {
                        tx_hash,
                        kind: StakingEventKind::Undelegate,
                        staker: s.owner,
                        validator: s.validator,
                        stake_account,
                        amount: s.amount,
                        round: current_round,
                    })
                }
                Ok(crate::staking::StakingInstruction::ClaimReward) => {
                    let stake_account = ix.accounts.first().copied().unwrap_or(sys);
                    let sad = self.store.get(&stake_account).and_then(|a| StakeAccountData::try_from_slice(&a.data).ok());
                    let acc_per_share = self
                        .store
                        .get(&STAKING_REWARDS_POOL_ID)
                        .and_then(|p| crate::staking::RewardPoolData::try_from_slice(&p.data).ok())
                        .map(|p| p.acc_reward_per_share)
                        .unwrap_or(0);
                    sad.map(|s| StakingEvent {
                        tx_hash,
                        kind: StakingEventKind::ClaimReward,
                        staker: s.owner,
                        validator: s.validator,
                        stake_account,
                        amount: crate::staking::pending_reward(s.amount, s.reward_debt, acc_per_share),
                        round: current_round,
                    })
                }
                _ => None,
            }
        } else {
            None
        };

        payer_account.balance -= upfront_fee;
        payer_account.nonce += 1;
        self.write_account(tx.message.payer, payer_account.clone());

        // Only the BASE (byte) fee is split 50/50 burn/validators. The priority
        // tip is NOT burned: it goes 100% to the proposer, as the whole point
        // is to reward the validator that included a congested transaction.
        let burn_share = byte_fee / 2;
        let validator_share = byte_fee - burn_share;
        self.total_burned = self.total_burned.saturating_add(burn_share);
        self.fee_burned = self.fee_burned.saturating_add(burn_share);
        self.credit_validator_share(*fee_collector, validator_share, &params)?;
        if priority_fee > 0 {
            // 100% of the tip to the proposer's own account (liquid commission,
            // tracked like the base commission so the dashboard reflects it).
            self.credit(*fee_collector, priority_fee);
            self.validator_earned = self.validator_earned.saturating_add(priority_fee);
            self.note_validator_commission(*fee_collector, priority_fee);
        }

        // Advance the EIP-1559-style dynamic base fee for subsequent rounds.
        // Placed here - after the fee is charged, before the instructions run
        // and before `root_after` is captured - so its on-chain writes are part
        // of THIS transaction's committed state (deterministic across
        // validators, and inside the STARK receipt's root chain).
        self.advance_dynamic_fee(current_round, tx.byte_size() as u64);

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
            match self.programs.get(&ix.program_id) {
                Some(Program::Native(native)) => native.process(&mut working, ix, &tx.message.payer, current_round)?,
                Some(Program::Wasm { module_bytes, entry_point }) => {
                    let module_bytes = module_bytes.clone();
                    let entry_point = entry_point.clone();
                    match self.run_wasm_instruction(&module_bytes, &entry_point, ix, &tx.message.payer, &mut working, params.gas_price_per_fuel) {
                        Ok(fee) => total_gas_fee = total_gas_fee.saturating_add(fee),
                        Err(e) => return Err(self.bill_trapped_wasm_fuel(&tx.message.payer, fee_collector, upfront_fee, tx.message.fee_limit, e)),
                    }
                }
                // Not one of the fixed native programs - check whether a
                // real `SystemInstruction::DeployProgram` deployed a WASM
                // contract at this address (see `native.rs`'s
                // `WasmProgramData`/`LOADER_PROGRAM_ID`). A direct store
                // read, not `working`, since `ix.accounts` (what
                // `working` is populated from) never includes
                // `ix.program_id` itself - a program's own account is
                // read-only from the invoking instruction's perspective,
                // not part of the mutable working set.
                None => {
                    let program_account = self
                        .store
                        .get(&ix.program_id)
                        .filter(|a| a.owner == crate::ids::LOADER_PROGRAM_ID)
                        .ok_or(ExecError::UnknownProgram(ix.program_id))?;
                    let program_data = crate::native::WasmProgramData::try_from_slice(&program_account.data)
                        .map_err(|e| ExecError::ProgramError(format!("corrupt deployed program data: {e}")))?;
                    match self.run_wasm_instruction(
                        &program_data.module_bytes,
                        &program_data.entry_point,
                        ix,
                        &tx.message.payer,
                        &mut working,
                        params.gas_price_per_fuel,
                    ) {
                        Ok(fee) => total_gas_fee = total_gas_fee.saturating_add(fee),
                        Err(e) => return Err(self.bill_trapped_wasm_fuel(&tx.message.payer, fee_collector, upfront_fee, tx.message.fee_limit, e)),
                    }
                }
            }
        }

        // A real, live-confirmed bug this closes (see `project-lessons-
        // learned`): the dust sweep (below) can still zero a resulting
        // balance *after* this point, but `qchain-stark`'s AIR only ever
        // models plain conservation (`to_after == to_before + amount`) -
        // it has no notion of a dust sweep at all, the same kind of
        // single-instruction-shape restriction that already rules out
        // multi-instruction transactions capturing a receipt (see
        // `receipt.rs` module docs). The old code captured the pre-sweep
        // `working` values into the receipt regardless, which either
        // disagreed with what actually got committed (breaking the *next*
        // receipt's chaining, `RootSequenceMismatch`) or, if corrected to
        // report the real post-sweep value instead, disagreed with the
        // circuit's own internal arithmetic for *this* row instead
        // (`BalanceMismatch` - tried and confirmed by this fix's own
        // test). Since the circuit cannot represent a swept balance
        // either way, the honest fix is the same one already used for
        // multi-instruction transactions: don't capture a receipt for a
        // transfer that would be dust-swept, rather than capturing one
        // guaranteed to fail self-verification either at proving or at
        // chaining. `total_gas_fee` is guaranteed `0` for every receipt-
        // eligible transaction (single-instruction, native
        // `SystemInstruction::Transfer` - `Program::Wasm`/gas fees never
        // apply to this branch), so predicting only the dust sweep here
        // exactly matches what the commit loop below will actually write.
        let would_be_dust_swept = |account: &Account| -> bool {
            account.owner == Pubkey::system_program_id() && account.balance > 0 && account.balance < params.dust_threshold
        };
        let pre_capture = pre_capture.filter(|(from, to, ..)| {
            let from_swept = working.get(from).is_some_and(&would_be_dust_swept);
            let to_swept = working.get(to).is_some_and(&would_be_dust_swept);
            !from_swept && !to_swept
        });
        if let Some((from, to, amount, from_before, to_before, root_before, from_proof_before, to_proof_before)) = pre_capture {
            // Same real semantics the old `OverlayStore { base: self.store,
            // overlay: &working }` gave: "the committed store as of right
            // now (already includes this transaction's fee deduction,
            // written above), with `working`'s in-flight instruction
            // results layered on top" - just computed as a small,
            // `working`-sized pending-change set against the incremental
            // tree's cache instead of re-scanning every account through an
            // overlay wrapper.
            let working_changes: Vec<(Pubkey, Account)> = working.iter().map(|(k, v)| (*k, v.clone())).collect();
            let (root_after, from_proof_after, to_proof_after) = self.tree.capture_after(&from, &to, &working_changes);
            let from_after = working.get(&from).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
            let to_after = working.get(&to).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
            // Route the four captured proofs into either the legacy `MerkleProof`
            // receipt fields or the compressed `CompressedProofSet` - a receipt
            // carries exactly one, per the ledger's fixed tree kind. In compressed
            // mode the four `MerkleProof` fields are unused address-only
            // placeholders (there is no 256-deep proof to give); the node's
            // `/stark_proof` builder reads `compressed_proofs` instead.
            let dummy_merkle = |key: &Pubkey| MerkleProof { key: key.to_bytes(), leaf_value_hash: None, siblings: vec![] };
            let (from_proof_before, from_proof_after, to_proof_before, to_proof_after, compressed_proofs) =
                match (from_proof_before, from_proof_after, to_proof_before, to_proof_after) {
                    (CapturedProof::Legacy(fb), CapturedProof::Legacy(fa), CapturedProof::Legacy(tb), CapturedProof::Legacy(ta)) => {
                        (fb, fa, tb, ta, None)
                    }
                    (CapturedProof::Compressed(fb), CapturedProof::Compressed(fa), CapturedProof::Compressed(tb), CapturedProof::Compressed(ta)) => (
                        dummy_merkle(&from),
                        dummy_merkle(&from),
                        dummy_merkle(&to),
                        dummy_merkle(&to),
                        Some(CompressedProofSet { from_proof_before: fb, from_proof_after: fa, to_proof_before: tb, to_proof_after: ta }),
                    ),
                    _ => unreachable!("a ledger's tree kind is fixed; all four captured proofs share one variant"),
                };
            self.transfer_receipts.push(TransferReceipt {
                tx_hash: tx.hash(),
                round: current_round,
                from,
                to,
                amount,
                fee: upfront_fee,
                root_before,
                root_after,
                from_before,
                from_after,
                to_before,
                to_after,
                from_proof_before,
                from_proof_after,
                to_proof_before,
                to_proof_after,
                compressed_proofs,
            });
        }

        // The byte fee alone was already checked against `fee_limit` above,
        // before it was committed to the store - gas fee is only known
        // after the instructions actually ran, so the *combined* total is
        // checked here, before any of `working`'s changes (including the
        // WASM contracts' own state mutations) are committed below. The
        // already-committed byte fee itself is not reverted on this path -
        // consistent with this project's existing "you pay for attempted
        // execution" behavior (a failed WASM call already keeps the byte
        // fee, see the security-review entry in `project-lessons-learned`),
        // so declaring too-low a `fee_limit` for a WASM call still costs
        // the byte fee, same as any other rejected transaction.
        // `saturating_add`, not `+`: `total_gas_fee` is itself a
        // `saturating_mul` of a governance-set `gas_price_per_fuel` with no
        // upper bound, so it can reach `u64::MAX`; with `overflow-checks =
        // true` (release, see root `Cargo.toml`) a plain `+` here would panic
        // on the whole network at once (deterministic tx stream) instead of
        // rejecting this one transaction. Saturating keeps the intended
        // outcome: the fee exceeds any real `fee_limit`, so the tx is rejected.
        let combined_fee = upfront_fee.saturating_add(total_gas_fee);
        if combined_fee > tx.message.fee_limit {
            return Err(ExecError::FeeExceedsLimit { actual: combined_fee, limit: tx.message.fee_limit });
        }

        if total_gas_fee > 0 {
            let payer_after = working.get_mut(&tx.message.payer).ok_or(ExecError::AccountNotFound(tx.message.payer))?;
            if payer_after.balance < total_gas_fee {
                return Err(ExecError::InsufficientFunds);
            }
            payer_after.balance -= total_gas_fee;
            self.total_burned = self.total_burned.saturating_add(total_gas_fee / 2);
            self.fee_burned = self.fee_burned.saturating_add(total_gas_fee / 2);
            let gas_validator_share = total_gas_fee - total_gas_fee / 2;
            // Seed the fee collector's working-set entry from its REAL
            // stored balance, exactly like the payer is seeded at the top of
            // this function - never from a fresh zero-balance account. This
            // is load-bearing, not cosmetic: `fee_collector` (the block
            // proposer) is not the payer and is not listed in any
            // instruction's `accounts` for a normal transaction, so it is
            // absent from `working`. An `or_insert_with(Account::new_wallet)`
            // here would fabricate a fresh zero-balance account holding only
            // this one transaction's gas share, and the commit loop below
            // (`write_account` is a full overwrite) would then clobber the
            // validator's entire accumulated fee balance in the store with
            // it - and, since that fresh account is system-owned and holds
            // less than `dust_threshold`, the dust sweep would then zero even
            // that. Net effect before this fix: every fuel-consuming WASM
            // contract call wiped the proposer's balance to zero and silently
            // broke supply conservation. Seeding from the store (`or_insert`
            // only runs when absent; when `fee_collector` *is* already in
            // `working` - e.g. it was also the payer - the existing entry is
            // reused and this share is simply added on top) preserves the
            // real balance in both cases.
            working
                .entry(*fee_collector)
                .or_insert_with(|| self.store.get(fee_collector).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id())))
                .balance += gas_validator_share;
        }

        for (pk, mut account) in working {
            // Never dust-sweep the fee collector (block proposer): on the WASM
            // gas path it is seeded into `working` from its real store balance
            // and credited its gas share here, so a proposer whose accumulated
            // balance is still below `dust_threshold` (e.g. its first small fee)
            // would otherwise have its legitimately-earned fee zeroed and burned
            // - value destruction the normal (non-gas) path never suffers,
            // because there the proposer is never placed in `working`. (Singleton
            // program accounts are already immune: they are program-owned, not
            // system-owned, so the owner check below excludes them.)
            if pk != *fee_collector
                && account.owner == Pubkey::system_program_id()
                && account.balance > 0
                && account.balance < params.dust_threshold
            {
                self.total_burned = self.total_burned.saturating_add(account.balance);
                self.dust_burned = self.dust_burned.saturating_add(account.balance);
                account.balance = 0;
            }
            self.write_account(pk, account);
        }

        // Everything committed - now record any captured staking activity
        // (a staking tx that failed returned early above, so reaching here
        // means it succeeded).
        if let Some(ev) = pre_staking {
            self.staking_events.push(ev);
        }

        // `combined_fee` (already `saturating_add`) equals `upfront_fee +
        // total_gas_fee` and was proven `<= fee_limit` above; reuse it rather
        // than a fresh `+` that could panic under `overflow-checks`.
        Ok(combined_fee)
    }

    /// Accumulate one block-proposer's direct commission for the per-validator
    /// earnings report. Bounded by validator-set size (keys are proposers).
    fn note_validator_commission(&mut self, validator: Pubkey, amount: u64) {
        let e = self.validator_commissions.entry(validator).or_insert(0);
        *e = e.saturating_add(amount);
    }

    /// Bills the payer for fuel actually consumed by a WASM instruction
    /// that trapped, before the caller propagates the failure - see
    /// `ExecError::Wasm`'s doc comment for the real vulnerability this
    /// closes. Charged directly to the store (same "sticks regardless of
    /// the rest of the transaction" treatment the byte fee already gets in
    /// `apply_transaction`, since `working`'s other changes are about to be
    /// discarded by the early return this feeds into). Capped at the
    /// payer's current balance rather than allowed to underflow - this is
    /// billing for real work already done, not a fresh solvency check, so
    /// there's nothing to reject here, only an amount to collect.
    fn bill_trapped_wasm_fuel(&mut self, payer: &Pubkey, fee_collector: &Pubkey, upfront_fee: u64, fee_limit: u64, err: ExecError) -> ExecError {
        if let ExecError::Wasm { fuel_consumed, .. } = &err {
            if *fuel_consumed > 0 {
                let params = self.current_params();
                let trap_fee = fuel_consumed.saturating_mul(params.gas_price_per_fuel);
                // Enforce `fee_limit` on the trap path too (the success path
                // checks `combined_fee > fee_limit` at `apply_transaction`, but
                // a trap returns before reaching it): the byte/priority
                // `upfront_fee` is already committed and was already `<=
                // fee_limit`, so the trap fee is capped at the remaining
                // allowance. Without this a payer who signed a low `fee_limit`
                // whose contract traps after burning millions of fuel would be
                // charged the full gas, exceeding the ceiling they authorized.
                let trap_fee = trap_fee.min(fee_limit.saturating_sub(upfront_fee));
                // CRITICAL: bill against the payer's committed STORE balance
                // (post-`upfront_fee`, written just before the instruction loop),
                // NEVER `working[payer]`. On a trap the whole transaction fails
                // and every `working` mutation is discarded by the early return
                // this feeds - but `working[payer]` already carries the balance
                // effects of any EARLIER successful instruction in the same tx
                // (e.g. an `Undelegate` that credited principal+reward, or a
                // `Transfer` that debited the payer). Committing that one account
                // while discarding its counterparts (the zeroed stake account,
                // the debited pool, the credited recipient) mints or destroys
                // value - a real, repeatable, network-wide supply break. Reading
                // the store instead commits ONLY `upfront_fee + trap_fee`, with
                // no leaked instruction effects.
                if let Some(mut payer_account) = self.store.get(payer) {
                    let charge = trap_fee.min(payer_account.balance);
                    payer_account.balance -= charge;
                    self.write_account(*payer, payer_account);
                    let burn_share = charge / 2;
                    let validator_share = charge - burn_share;
                    self.total_burned = self.total_burned.saturating_add(burn_share);
                    self.fee_burned = self.fee_burned.saturating_add(burn_share);
                    // Same "attempted-execution byte fee already stuck, so
                    // fold this trap fee's own credit failure into the
                    // returned error rather than swallowing it" posture as
                    // everywhere else `credit_validator_share` is called -
                    // if it errors, that error is arguably more informative
                    // than the original trap, but the trap is what the
                    // caller actually asked about, so it still wins.
                    let _ = self.credit_validator_share(*fee_collector, validator_share, &params);
                }
            }
        }
        err
    }

    fn run_wasm_instruction(
        &self,
        module_bytes: &[u8],
        entry_point: &str,
        ix: &Instruction,
        payer: &Pubkey,
        working: &mut HashMap<Pubkey, Account>,
        gas_price_per_fuel: u64,
    ) -> Result<u64, ExecError> {
        let accounts: Vec<Account> = ix
            .accounts
            .iter()
            .map(|pk| working.get(pk).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id())))
            .collect();
        // A real, live-confirmed vulnerability closed here (see
        // `project-lessons-learned`): without this, a contract had no way
        // to tell whether an account it was about to debit had actually
        // authorized the call, so anyone could name any victim's address
        // as an instruction account and drain it with only their own
        // signature. `is_signer[i]` tells the contract whether
        // `ix.accounts[i]` is this transaction's authenticated payer - the
        // only notion of "signer" this single-signer execution model has.
        let is_signer: Vec<bool> = ix.accounts.iter().map(|pk| pk == payer).collect();

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

        // Snapshot what the post-execution security check needs, BEFORE
        // `accounts`/`is_signer` are moved into `call`.
        let before_balances: Vec<u64> = accounts.iter().map(|a| a.balance).collect();
        let before_owners: Vec<Pubkey> = accounts.iter().map(|a| a.owner).collect();
        let signer_flags = is_signer.clone();

        // Setup-level failures (bad module, missing entry point) never
        // spend fuel - real execution hasn't started yet.
        let result = self
            .wasm
            .call(module_bytes, entry_point, &args, accounts, is_signer, DEFAULT_FUEL_LIMIT)
            .map_err(|e| ExecError::Wasm { message: e.to_string(), fuel_consumed: 0 })?;

        // Real, live-confirmed vulnerability closed here (see
        // `project-lessons-learned`): a contract that burns real fuel (up
        // to `DEFAULT_FUEL_LIMIT`) and then traps - deliberately, via
        // `unreachable`, or by simply running out of fuel - used to report
        // success or failure with no distinction from an instant trap,
        // because `WasmExecutor::call` never surfaced fuel spent before a
        // trap. Confirmed live: a deployed contract with an expensive loop
        // before a deliberate `unreachable` was charged the exact same fee
        // as one that traps immediately, regardless of how much of the
        // fuel budget it burned - free, bounded-but-real CPU for the
        // network, forever, one call at a time. `fuel_consumed` here is
        // propagated to `apply_transaction`, which bills for it directly
        // even though the rest of this transaction's effects still get
        // discarded (same as any other failed instruction).
        if let Some(trap_message) = result.trap {
            return Err(ExecError::Wasm { message: trap_message, fuel_consumed: result.fuel_consumed });
        }

        // SECURITY — enforced by the LEDGER, not the contract. `host_set_balance`
        // lets bytecode write any balance to any declared account, and
        // `host_is_signer` is only *advisory* (a cooperative contract may consult
        // it, but nothing forces malicious bytecode to). So a deployed contract
        // could otherwise mint (`set_balance(self, MAX)`) or steal (drain a
        // victim named in `accounts` without checking the signer). We validate
        // the balance delta here, before committing, so the guarantee holds for
        // ALL bytecode - not just the reference contract that voluntarily checks
        // `host_is_signer`. Two invariants (Solana-style):
        //   (1) an account may only be DEBITED if the caller is authorized over
        //       it - it is the transaction signer, or the contract program owns
        //       it (`owner == program_id`);
        //   (2) the total balance across the declared accounts may not increase
        //       (minting from nothing is impossible).
        // Only `balance` is reachable from the host API (no set for owner/data),
        // so this fully covers what bytecode can change. Fees are billed
        // separately by `apply_transaction`; a rejected instruction still pays
        // its byte/gas fee, so this is not a free retry for an attacker.
        let program_id = ix.program_id;
        let mut total_before: u128 = 0;
        let mut total_after: u128 = 0;
        for (i, account_after) in result.accounts.iter().enumerate() {
            let before = before_balances.get(i).copied().unwrap_or(0);
            let after = account_after.balance;
            total_before += before as u128;
            total_after += after as u128;
            if after < before {
                let authorized = signer_flags.get(i).copied().unwrap_or(false)
                    || before_owners.get(i).map(|o| *o == program_id).unwrap_or(false);
                if !authorized {
                    let who = ix.accounts.get(i).copied().unwrap_or_else(Pubkey::system_program_id);
                    return Err(ExecError::Unauthorized(format!(
                        "contract debited account {who} it is not authorized over (not the signer, not program-owned)"
                    )));
                }
            }
        }
        if total_after > total_before {
            return Err(ExecError::ProgramError(
                "contract increased the total balance across its accounts - minting is not allowed".into(),
            ));
        }

        for (pk, account) in ix.accounts.iter().zip(result.accounts.into_iter()) {
            working.insert(*pk, account);
        }

        // `saturating_mul`, matching `bill_trapped_wasm_fuel`'s trap path
        // and the byte-fee computation: `gas_price_per_fuel` is
        // governance-set with no hard upper bound, so a near-`u64::MAX`
        // price times real fuel would wrap in release. Saturation makes an
        // absurd price simply exceed any balance / `fee_limit` and reject,
        // never wrap to a small charge.
        Ok(result.fuel_consumed.saturating_mul(gas_price_per_fuel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::GOVERNANCE_PROGRAM_ID;
    use crate::native::{SystemInstruction, SystemProgram};
    use qchain_core::{Instruction, BASE_FEE_PER_BYTE_UNITS, DUST_THRESHOLD_UNITS};
    use qchain_crypto::Keypair;
    use qchain_storage::InMemoryStore;

    fn new_test_ledger() -> Ledger {
        let mut ledger = Ledger::new(Box::new(InMemoryStore::new())).unwrap();
        ledger.register_program(Pubkey::system_program_id(), Program::Native(Box::new(SystemProgram)));
        ledger
    }

    fn new_test_ledger_compressed() -> Ledger {
        let mut ledger = Ledger::new_with_tree(Box::new(InMemoryStore::new()), true).unwrap();
        ledger.register_program(Pubkey::system_program_id(), Program::Native(Box::new(SystemProgram)));
        ledger
    }

    /// Phase C correctness anchor: a compressed-tree ledger and a legacy-tree
    /// ledger EXECUTE identically (same balances/nonces - execution is
    /// tree-agnostic); only the state ROOT differs (it's a different, hard-fork
    /// commitment). And the compressed ledger's live root must equal an
    /// INDEPENDENT recompute of its final store - the "no fork" guarantee: any
    /// honest node computing the compressed root over the same accounts gets the
    /// same value.
    #[test]
    fn compressed_ledger_executes_identically_and_its_root_matches_an_independent_recompute() {
        let mut legacy = new_test_ledger();
        let mut compressed = new_test_ledger_compressed();
        let validator = Keypair::generate().unwrap().pubkey();
        let payers: Vec<Keypair> = (0..8).map(|_| Keypair::generate().unwrap()).collect();
        let recips: Vec<Pubkey> = (0..8).map(|_| Keypair::generate().unwrap().pubkey()).collect();
        for p in &payers {
            legacy.credit(p.pubkey(), 50_000_000);
            compressed.credit(p.pubkey(), 50_000_000);
        }
        for (i, p) in payers.iter().enumerate() {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![p.pubkey(), recips[i]],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 3_000_000 }).unwrap(),
            };
            let tx = Transaction::new_signed(p, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
            let rl = legacy.apply_transaction(&tx, &validator, 0);
            let rc = compressed.apply_transaction(&tx, &validator, 0);
            assert_eq!(rl.is_ok(), rc.is_ok(), "both trees must accept/reject the same tx");
        }
        // Execution is identical - balances match across both trees.
        for p in &payers {
            assert_eq!(legacy.get_balance(&p.pubkey()), compressed.get_balance(&p.pubkey()), "payer balance must be tree-agnostic");
        }
        for r in &recips {
            assert_eq!(legacy.get_balance(r), compressed.get_balance(r), "recipient balance must be tree-agnostic");
        }
        // Different commitment - the two roots differ.
        assert_ne!(legacy.merkle_root(), compressed.merkle_root(), "compressed and legacy are distinct commitments");
        // The compressed live root == an independent recompute over the final
        // store (determinism / no-fork).
        let accts: Vec<(Pubkey, Account)> = compressed.store().iter().collect();
        let recomputed = qchain_storage::compressed::CompressedStateTree::root_from_accounts(accts.iter().map(|(k, a)| (k, a)));
        assert_eq!(compressed.merkle_root(), recomputed, "the live compressed root must match an independent recompute (deterministic, fork-free)");
        // Both modes now capture receipts (compressed carries CompressedProofs).
        assert_eq!(compressed.transfer_receipts().len(), legacy.transfer_receipts().len(), "both modes capture the same receipts");
        assert!(!compressed.transfer_receipts().is_empty());
    }

    /// Measure-first for parallel signature verification: how big a slice of a
    /// COMPRESSED-mode `apply_transaction` is the pure PQC signature check? If it
    /// is a large fraction, offloading it to a thread pool (leaving only
    /// `apply_transaction_presigned`'s work on the sequential commit thread) is
    /// worth the change to the safety-critical commit loop; if it is marginal, it
    /// is not (per the project's "only ship a safe optimization if it actually
    /// helps" rule). Ignored by default; run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_verify_fraction_of_compressed_apply() {
        use std::time::Instant;
        const PAYERS: usize = 200;
        const PER_PAYER: u64 = 6;
        let validator = Keypair::generate().unwrap().pubkey();
        let payers: Vec<Keypair> = (0..PAYERS).map(|_| Keypair::generate().unwrap()).collect();
        let recips: Vec<Pubkey> = (0..PAYERS).map(|_| Keypair::generate().unwrap().pubkey()).collect();

        // Build one shared set of signed transfers (nonce runs per payer).
        let build_txs = || -> Vec<Transaction> {
            let mut txs = Vec::new();
            for (pi, p) in payers.iter().enumerate() {
                for n in 0..PER_PAYER {
                    let ix = Instruction {
                        program_id: Pubkey::system_program_id(),
                        accounts: vec![p.pubkey(), recips[pi]],
                        data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
                    };
                    txs.push(Transaction::new_signed(p, n, [0u8; 32], 100_000_000, vec![ix]).unwrap());
                }
            }
            txs
        };
        let txs = build_txs();
        let n = txs.len();

        // Pure signature verification cost.
        let t = Instant::now();
        let mut ok = 0usize;
        for tx in &txs {
            if tx.verify_signature() {
                ok += 1;
            }
        }
        let t_verify = t.elapsed();
        assert_eq!(ok, n);

        let fund = |l: &mut Ledger| {
            for p in &payers {
                l.credit(p.pubkey(), 5_000_000_000);
            }
        };

        // Full apply (verify inline), compressed tree.
        let mut a = new_test_ledger_compressed();
        fund(&mut a);
        let t = Instant::now();
        for tx in &txs {
            let _ = a.apply_transaction(tx, &validator, 0);
        }
        let t_full = t.elapsed();

        // Apply with the signature pre-verified (skipped), compressed tree.
        let mut b = new_test_ledger_compressed();
        fund(&mut b);
        let t = Instant::now();
        for tx in &txs {
            let _ = b.apply_transaction_presigned(tx, &validator, 0);
        }
        let t_presigned = t.elapsed();

        // Same final root (identical execution, verify skip changes nothing but timing).
        assert_eq!(a.merkle_root(), b.merkle_root(), "presigned apply must produce the identical committed state");

        let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / n as f64;
        let tps = |d: std::time::Duration| n as f64 / d.as_secs_f64();
        println!("compressed apply bench over {n} real signed transfers:");
        println!("  pure verify:        {:.1} us/tx", per(t_verify));
        println!("  apply (verify):     {:.1} us/tx  =  {:.0} tx/s", per(t_full), tps(t_full));
        println!("  apply (presigned):  {:.1} us/tx  =  {:.0} tx/s", per(t_presigned), tps(t_presigned));
        println!(
            "  verify is {:.0}% of full apply; commit-thread ceiling if verify is parallelized: {:.1}x",
            100.0 * (t_full.as_secs_f64() - t_presigned.as_secs_f64()) / t_full.as_secs_f64(),
            t_full.as_secs_f64() / t_presigned.as_secs_f64()
        );
    }

    /// v5.1.0: a compressed-mode transfer captures a receipt carrying real
    /// `CompressedProof`s, and those O(log n) proofs verify against the receipt's
    /// own `root_before`/`root_after` - the exact binding the node's compressed
    /// `/stark_proof` light-client relies on. Verified with the cheap
    /// `compressed::verify_proof` (not the heavy full STARK), which is precisely
    /// what `qchain_stark::verify_batch_bound_to_compressed_state` calls per row.
    #[test]
    fn compressed_mode_captures_verifiable_compressed_proof_receipts() {
        use qchain_storage::compressed::{verify_proof, Terminal};
        let mut ledger = new_test_ledger_compressed();
        let validator = Keypair::generate().unwrap().pubkey();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        // Pre-existing account so bob is a first-ever recipient (exclusion proof
        // on `to_before`) AND there's an unrelated leaf making the tree branch.
        ledger.credit(alice.pubkey(), 50_000_000);
        ledger.credit(Keypair::generate().unwrap().pubkey(), 9_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 3_000_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        ledger.apply_transaction(&tx, &validator, 0).unwrap();

        let r = ledger.transfer_receipts().last().expect("a receipt was captured");
        let c = r.compressed_proofs.as_ref().expect("compressed mode carries compressed proofs");
        // The four proofs verify against the receipt's captured roots.
        assert!(verify_proof(r.root_before, &c.from_proof_before), "from_before proof must verify against root_before");
        assert!(verify_proof(r.root_after, &c.from_proof_after), "from_after proof must verify against root_after");
        assert!(verify_proof(r.root_before, &c.to_proof_before), "to_before proof must verify against root_before");
        assert!(verify_proof(r.root_after, &c.to_proof_after), "to_after proof must verify against root_after");
        // bob is a first-ever recipient: to_before is a genuine exclusion proof.
        assert!(matches!(c.to_proof_before.terminal, Terminal::OtherLeaf { .. } | Terminal::Empty), "bob has no prior leaf");
        assert_eq!(r.to_before.balance, 0, "an excluded recipient has zero prior balance");
        // The captured after-proof value matches the committed account hash.
        assert!(matches!(c.from_proof_after.terminal, Terminal::Leaf { .. }));
        // root_after chains from the live tree (what the node commits).
        assert_eq!(r.root_after, ledger.merkle_root(), "captured root_after equals the live committed compressed root");
    }

    #[test]
    fn priority_fee_is_charged_on_top_and_paid_entirely_to_the_validator() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 20_000_000);

        let tip = 3_000_000u64;
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        let tx = Transaction::new_signed_with_priority(&alice, 0, [0u8; 32], 50_000_000, tip, vec![ix]).unwrap();
        let total_fee = ledger.apply_transaction(&tx, &validator, 0).unwrap();

        // The byte (base) portion is total minus the tip.
        let base_fee = total_fee - tip;
        assert!(base_fee > 0);
        // Payer paid amount + base + tip.
        assert_eq!(ledger.get_balance(&alice.pubkey()), 20_000_000 - 2_000_000 - base_fee - tip);
        // Validator got its half of the BASE fee PLUS the whole tip (tips aren't
        // burned).
        assert_eq!(ledger.get_balance(&validator), (base_fee - base_fee / 2) + tip);
        // Only the base fee is burned; the tip is not.
        assert_eq!(ledger.total_burned, base_fee / 2, "the tip must not be burned");
        // The captured receipt's fee reflects base + tip (STARK conservation:
        // from lost amount + base + tip).
        let r = ledger.transfer_receipts().last().unwrap();
        assert_eq!(r.fee, base_fee + tip);
    }

    #[test]
    fn a_priority_tip_pushing_the_total_over_fee_limit_is_rejected() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 20_000_000);
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        // fee_limit just above the base fee but below base+tip -> rejected.
        let tx = Transaction::new_signed_with_priority(&alice, 0, [0u8; 32], 1_100_000, 5_000_000, vec![ix]).unwrap();
        let res = ledger.apply_transaction(&tx, &Pubkey::system_program_id(), 0);
        assert!(matches!(res, Err(ExecError::FeeExceedsLimit { .. })), "base+tip over fee_limit must reject, got {res:?}");
    }

    #[test]
    fn dynamic_fee_epoch_rolls_on_round_change_and_stays_at_floor_under_light_load() {
        // Two transfers in round 0 then one in round 1: the fee epoch must roll
        // to round 1, and with only light load (well under target) the base fee
        // stays pinned at the floor - never below it. (The rise-under-load math
        // is covered by params::tests::next_base_fee_*.)
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 100_000_000);
        let mk = |nonce: u64| {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![alice.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
            };
            Transaction::new_signed(&alice, nonce, [0u8; 32], 50_000_000, vec![ix]).unwrap()
        };
        ledger.apply_transaction(&mk(0), &validator, 0).unwrap();
        ledger.apply_transaction(&mk(1), &validator, 0).unwrap();
        assert_eq!(ledger.current_fee_state().epoch_round, 0, "still in epoch 0 after two round-0 txs");
        // A tx in round 1 closes epoch 0 (light load -> fee stays at floor).
        ledger.apply_transaction(&mk(2), &validator, 1).unwrap();
        assert_eq!(ledger.current_fee_state().epoch_round, 1, "epoch must roll to round 1");
        assert_eq!(
            ledger.current_params().base_fee_per_byte,
            crate::params::FEE_MIN_BASE_FEE_PER_BYTE,
            "light load must keep the base fee at the floor, never below"
        );
    }

    #[test]
    fn the_dynamic_fee_decays_even_when_every_transaction_fails_for_lack_of_funds() {
        // The fee-decay deadlock fix. Pin the base fee absurdly high (as a heavy
        // flood does), then submit a transaction every round from a payer who
        // can't afford it. Before the fix `advance_dynamic_fee` only ran for
        // affordable transactions, so a run of all-failing rounds left the fee
        // pinned forever. Now each failing transaction still ticks the epoch, so
        // the below-target rounds decay the base fee back toward the floor.
        let mut ledger = new_test_ledger();
        let start_fee = 100_000u64;
        let high = EconomicParams { base_fee_per_byte: start_fee, ..EconomicParams::default() };
        ledger.seed_account(PARAMS_ACCOUNT_ID, Account { data: borsh::to_vec(&high).unwrap(), ..Account::new_wallet(Pubkey::new([3u8; 32])) });

        let poor = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(poor.pubkey(), 1_000); // nowhere near the ~500M fee at this rate
        let mk = || {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![poor.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
            };
            // fee_limit u64::MAX so it fails on affordability, not the fee cap.
            Transaction::new_signed(&poor, 0, [0u8; 32], u64::MAX, vec![ix]).unwrap()
        };
        for round in 0..20u64 {
            let r = ledger.apply_transaction(&mk(), &validator, round);
            assert!(matches!(r, Err(ExecError::InsufficientFunds)), "every tx must fail for lack of funds (round {round})");
        }
        let after = ledger.current_params().base_fee_per_byte;
        assert!(after < start_fee, "the base fee must DECAY across all-failing rounds (was {start_fee}, now {after}) - not stay pinned high forever");
        assert!(after >= crate::params::FEE_MIN_BASE_FEE_PER_BYTE, "but never below the floor");
    }

    #[test]
    fn a_single_tx_after_a_long_idle_gap_collapses_a_spiked_fee_back_to_the_floor() {
        // The idle-decay fix. A flood pins the base fee absurdly high, then the
        // chain goes quiet: rounds keep advancing but no transaction commits, so
        // `advance_dynamic_fee` never runs and the fee froze at its peak (the
        // exact live symptom - base_fee 197766, rounds advancing, nothing
        // executing). The multi-step epoch close now rolls one below-target decay
        // step per EMPTY round when the next tx finally lands, so a single
        // committed transaction after a long idle gap heals the fee all the way
        // to the floor in one shot - not one ~12.5% step per tx (~116 txs).
        let mut ledger = new_test_ledger();
        let start_fee = 197_766u64; // the exact pinned value the user saw live
        let high = EconomicParams { base_fee_per_byte: start_fee, ..EconomicParams::default() };
        ledger.seed_account(PARAMS_ACCOUNT_ID, Account { data: borsh::to_vec(&high).unwrap(), ..Account::new_wallet(Pubkey::new([3u8; 32])) });

        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        // Fund alice enough to afford one tx at the spiked fee (the recovery
        // path: one wallet with funds unsticks the whole chain).
        ledger.credit(alice.pubkey(), 5_000_000_000_000);
        let mk = |nonce: u64| {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![alice.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
            };
            Transaction::new_signed(&alice, nonce, [0u8; 32], u64::MAX, vec![ix]).unwrap()
        };
        // A first tx at round 0 opens the epoch at round 0 (no close yet).
        ledger.apply_transaction(&mk(0), &validator, 0).unwrap();
        assert_eq!(ledger.current_params().base_fee_per_byte, start_fee, "no decay yet - epoch just opened");
        // Now a single tx 5000 rounds later: the 4999 empty rounds in between
        // must ALL decay, collapsing the fee to the floor in this one tx.
        ledger.apply_transaction(&mk(1), &validator, 5000).unwrap();
        assert_eq!(
            ledger.current_params().base_fee_per_byte,
            crate::params::FEE_MIN_BASE_FEE_PER_BYTE,
            "a long idle gap must collapse the spiked fee to the floor in ONE committed tx, not one step per tx"
        );
    }

    #[test]
    fn effective_fee_decays_on_read_across_idle_rounds_without_writing_state() {
        // The complete idle-decay fix. A spiked fee must decay as rounds pass
        // even with NO transactions committing - so an idle chain heals on its
        // own and a low-balance wallet is unlocked - WITHOUT writing state on
        // empty rounds (which would break the STARK receipt chain). Model: pin
        // the stored base fee high with a real fee epoch open at round 0, then
        // read the effective fee at ever-later rounds. The STORED value must
        // stay put (no write); the EFFECTIVE value must fall to the floor.
        let mut ledger = new_test_ledger();
        let start_fee = 197_766u64;
        let high = EconomicParams { base_fee_per_byte: start_fee, ..EconomicParams::default() };
        ledger.seed_account(PARAMS_ACCOUNT_ID, Account { data: borsh::to_vec(&high).unwrap(), ..Account::new_wallet(Pubkey::new([3u8; 32])) });
        // Open a fee epoch at round 0 (one committed tx), leaving the stored fee high.
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 5_000_000_000_000);
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        ledger.apply_transaction(&Transaction::new_signed(&alice, 0, [0u8; 32], u64::MAX, vec![ix]).unwrap(), &validator, 0).unwrap();

        let stored = ledger.current_params().base_fee_per_byte;
        assert_eq!(stored, start_fee, "the STORED fee stays high - no idle round wrote state");
        assert_eq!(ledger.effective_base_fee_at(0), start_fee, "same round: no roll");
        // Effective fee at later rounds must decay monotonically to the floor,
        // all WITHOUT any apply_transaction / state write in between.
        let e10 = ledger.effective_base_fee_at(10);
        let e100 = ledger.effective_base_fee_at(100);
        let e5000 = ledger.effective_base_fee_at(5000);
        assert!(e10 < start_fee, "effective fee decays after 10 idle rounds ({e10} < {start_fee})");
        assert!(e100 < e10, "and keeps decaying ({e100} < {e10})");
        assert_eq!(e5000, crate::params::FEE_MIN_BASE_FEE_PER_BYTE, "a long idle gap reaches the floor on read");
        // Crucially, reading the effective fee wrote nothing: the stored value is
        // still the spiked one (only a committed tx moves it).
        assert_eq!(ledger.current_params().base_fee_per_byte, start_fee, "reads never mutate stored state (STARK-chain safe)");
    }

    #[test]
    fn cap_receipt_log_keeps_the_most_recent_window_and_drops_the_oldest() {
        // Bounding the in-memory receipt log must keep the NEWEST `max` receipts
        // (dropping from the front), so the STARK proof endpoint's last-N suffix
        // and the explorer's recent view stay intact while RAM stays bounded.
        use crate::receipt::TransferReceipt;
        use qchain_storage::MerkleProof;
        let dummy_proof = || MerkleProof { key: [0u8; 32], leaf_value_hash: None, siblings: vec![] };
        let mk_receipt = |round: u64| TransferReceipt {
            tx_hash: [0u8; 32],
            round,
            from: Pubkey::new([1u8; 32]),
            to: Pubkey::new([2u8; 32]),
            amount: 1,
            fee: 1,
            root_before: [0u8; 32],
            root_after: [0u8; 32],
            from_before: Account::new_wallet(Pubkey::new([1u8; 32])),
            from_after: Account::new_wallet(Pubkey::new([1u8; 32])),
            to_before: Account::new_wallet(Pubkey::new([2u8; 32])),
            to_after: Account::new_wallet(Pubkey::new([2u8; 32])),
            from_proof_before: dummy_proof(),
            from_proof_after: dummy_proof(),
            to_proof_before: dummy_proof(),
            to_proof_after: dummy_proof(),
            compressed_proofs: None,
        };
        let mut ledger = new_test_ledger();
        ledger.restore_receipts((0..6_000u64).map(mk_receipt).collect());
        ledger.cap_receipt_log(5_000);
        assert_eq!(ledger.transfer_receipts().len(), 5_000, "must bound to the cap");
        assert_eq!(ledger.transfer_receipts().first().unwrap().round, 1_000, "oldest 1000 dropped");
        assert_eq!(ledger.transfer_receipts().last().unwrap().round, 5_999, "newest kept");
        // Under the cap it's a no-op.
        ledger.cap_receipt_log(10_000);
        assert_eq!(ledger.transfer_receipts().len(), 5_000, "no-op when already within bound");
    }

    #[test]
    fn emission_mints_new_qch_into_the_reward_pool_over_elapsed_rounds() {
        // With real stake delegated and the default 12% APR, closing a fee epoch
        // that spanned several rounds mints new QCH straight into the reward
        // pool - real inflation on top of fees, tracked by `total_emitted`.
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 100_000_000);

        // Seed `total_staked`. Chosen so the per-round emission is a clean whole
        // number: 63,072,000,000 staked at 12% APR / 63,072,000 rounds-per-year
        // = 120 units minted per round.
        let total_staked: u64 = 63_072_000_000;
        ledger.store.set(
            STAKING_STATS_ID,
            Account { data: borsh::to_vec(&total_staked).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) },
        );
        // Seed an empty reward pool so we can watch it grow from zero base.
        ledger.store.set(
            STAKING_REWARDS_POOL_ID,
            Account { data: borsh::to_vec(&crate::staking::RewardPoolData::default()).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) },
        );

        let mk = |nonce: u64| {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![alice.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
            };
            Transaction::new_signed(&alice, nonce, [0u8; 32], 50_000_000, vec![ix]).unwrap()
        };
        // First tx opens the fee epoch at round 0 (no elapsed rounds -> no emission).
        ledger.apply_transaction(&mk(0), &validator, 0).unwrap();
        assert_eq!(ledger.total_emitted, 0, "no rounds elapsed yet -> nothing minted");
        // A tx ten rounds later closes epoch 0, spanning 10 rounds -> 10 x 120 = 1200.
        ledger.apply_transaction(&mk(1), &validator, 10).unwrap();
        assert_eq!(ledger.total_emitted, 1_200, "10 rounds x 120/round of emission");
        // The pool balance grew by at least the emitted amount (fee-share may add
        // more, but emission alone accounts for `total_emitted`).
        let pool_balance = ledger.store.get(&STAKING_REWARDS_POOL_ID).unwrap().balance;
        assert!(pool_balance >= 1_200, "emission must be minted into the pool, got {pool_balance}");
    }

    #[test]
    fn emission_is_off_when_no_stake_is_delegated() {
        // With `total_staked == 0` (the pre-staking state), no emission is minted
        // no matter how many rounds elapse - emission funds delegators, and there
        // are none.
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 100_000_000);
        let mk = |nonce: u64| {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![alice.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
            };
            Transaction::new_signed(&alice, nonce, [0u8; 32], 50_000_000, vec![ix]).unwrap()
        };
        ledger.apply_transaction(&mk(0), &validator, 0).unwrap();
        ledger.apply_transaction(&mk(1), &validator, 100).unwrap();
        assert_eq!(ledger.total_emitted, 0, "no stake -> no emission");
    }

    #[test]
    fn economics_snapshot_round_trips_exactly() {
        // A ledger with some real economic state, then export -> import into a
        // fresh ledger must reproduce every counter and the per-validator map
        // exactly - the property that makes restart-persistence correct.
        let mut a = new_test_ledger();
        a.total_burned = 700;
        a.fee_burned = 500;
        a.dust_burned = 200;
        a.validator_earned = 900;
        a.pool_earned = 100;
        a.total_emitted = 4_242;
        let v1 = Keypair::generate().unwrap().pubkey();
        let v2 = Keypair::generate().unwrap().pubkey();
        a.note_validator_commission(v1, 640);
        a.note_validator_commission(v2, 260);
        a.note_validator_commission(v1, 10); // accumulates

        let snap = a.export_economics();
        let mut b = new_test_ledger();
        b.import_economics(snap);

        assert_eq!(b.total_burned, 700);
        assert_eq!(b.fee_burned, 500);
        assert_eq!(b.dust_burned, 200);
        assert_eq!(b.validator_earned, 900);
        assert_eq!(b.pool_earned, 100);
        assert_eq!(b.total_emitted, 4_242);
        assert_eq!(b.commission_of(&v1), 650);
        assert_eq!(b.commission_of(&v2), 260);
        assert_eq!(b.commission_of(&Keypair::generate().unwrap().pubkey()), 0, "an unknown validator has zero commission");

        // And it survives a Borsh disk round-trip (how qchain-node persists it).
        let bytes = borsh::to_vec(&a.export_economics()).unwrap();
        let decoded = EconomicSnapshot::try_from_slice(&bytes).unwrap();
        let mut c = new_test_ledger();
        c.import_economics(decoded);
        assert_eq!(c.commission_of(&v1), 650);
        assert_eq!(c.total_burned, 700);
    }

    #[test]
    fn end_to_end_transfer_charges_fee_and_moves_balance() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();

        ledger.credit(alice.pubkey(), 10_000_000);

        // Must clear DUST_THRESHOLD_UNITS (1_000_000) - anything below it
        // would be swept from bob immediately upon receipt.
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();

        let fee = ledger.apply_transaction(&tx, &validator, 0).unwrap();
        assert!(fee > 0, "a multi-kilobyte hybrid-signed transaction must not be free");

        assert_eq!(ledger.get_balance(&bob), 2_000_000);
        assert_eq!(ledger.get_balance(&alice.pubkey()), 10_000_000 - 2_000_000 - fee);
        assert_eq!(ledger.get_balance(&validator), fee - fee / 2, "validator gets its half of the burned/split fee");
        assert_eq!(ledger.total_burned, fee / 2);
        // The new economics breakdown must reconcile exactly: the burned half
        // is all fee-burn (no dust here), and the non-burned half was all
        // earned by the validator (no delegators, so commission == full share).
        assert_eq!(ledger.fee_burned, fee / 2, "the burned half is fee-burn");
        assert_eq!(ledger.dust_burned, 0, "no dust sweep in this transfer");
        assert_eq!(ledger.fee_burned + ledger.dust_burned, ledger.total_burned, "breakdown must sum to total_burned");
        assert_eq!(ledger.validator_earned, fee - fee / 2, "with no delegators the validator earns the whole non-burned share");
        assert_eq!(ledger.pool_earned, 0, "nothing delegated, so nothing routed to the pool");
    }

    /// A real, live-confirmed gap this closes (see `project-lessons-learned`):
    /// `Message.fee_limit` used to be signed and transmitted but never
    /// checked at all - confirmed live by submitting a real transfer with
    /// `fee_limit=1` that was accepted and charged the real fee anyway.
    #[test]
    fn a_transaction_whose_real_fee_exceeds_its_declared_fee_limit_is_rejected() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        // The real byte fee for a transaction this size is always far
        // above 1 unit - this must be rejected before any state changes,
        // not accepted and silently charged more than the payer capped.
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 1, vec![ix]).unwrap();

        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(matches!(result, Err(ExecError::FeeExceedsLimit { .. })), "a fee above fee_limit must be rejected, got {result:?}");
        assert_eq!(ledger.get_balance(&alice.pubkey()), 10_000_000, "alice must not be charged anything for a rejected transaction");
        assert_eq!(ledger.get_balance(&bob), 0, "bob must never have received the transfer");
    }

    #[test]
    fn replayed_transaction_is_rejected_by_nonce() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        ledger.apply_transaction(&tx, &validator, 0).unwrap();

        // Same nonce again - the account has already moved to nonce 1.
        assert!(ledger.apply_transaction(&tx, &validator, 0).is_err());
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
        ledger.apply_transaction(&tx, &validator, 0).unwrap();

        assert_eq!(ledger.get_balance(&alice.pubkey()), 0, "sub-threshold residue must be swept, not left dangling");
    }

    /// Proves the governance wiring actually closes the loop: seeding
    /// `PARAMS_ACCOUNT_ID` with a different `base_fee_per_byte` (exactly
    /// what `GovernanceProgram::Execute` does for a passed `Low`-tier
    /// proposal, see `governance.rs`) must change what the very next
    /// `apply_transaction` call charges - not just mutate a data blob
    /// nobody reads.
    #[test]
    fn apply_transaction_uses_the_live_on_chain_base_fee_not_the_compiled_in_default() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 50_000_000);

        fn transfer_tx(alice: &Keypair, bob: Pubkey, nonce: u64) -> Transaction {
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![alice.pubkey(), bob],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
            };
            Transaction::new_signed(alice, nonce, [0u8; 32], 50_000_000, vec![ix]).unwrap()
        }

        let tx0 = transfer_tx(&alice, bob, 0);
        let expected_byte_size = tx0.byte_size() as u64;
        let fee_before = ledger.apply_transaction(&tx0, &validator, 0).unwrap();
        assert_eq!(fee_before, BASE_FEE_PER_BYTE_UNITS * expected_byte_size, "starts at the compiled-in default");

        // Simulate what GovernanceProgram::Execute does to a passed
        // Low-tier SetBaseFeePerByte proposal: overwrite the params
        // singleton directly.
        let new_params = EconomicParams { base_fee_per_byte: BASE_FEE_PER_BYTE_UNITS * 10, ..EconomicParams::default() };
        ledger.seed_account(PARAMS_ACCOUNT_ID, Account { data: borsh::to_vec(&new_params).unwrap(), ..Account::new_wallet(Pubkey::new([3u8; 32])) });

        let tx1 = transfer_tx(&alice, bob, 1);
        let fee_after = ledger.apply_transaction(&tx1, &validator, 0).unwrap();
        assert_eq!(fee_after, new_params.base_fee_per_byte * expected_byte_size);
        assert!(fee_after > fee_before * 5, "the new on-chain rate must actually be what gets charged");
    }

    /// Real, reproducible throughput measurement - not a literature
    /// estimate (see `project-lessons-learned`'s "benchmark before making
    /// a throughput claim" entry). Measures two things separately: hybrid
    /// signing (client-side cost, not on the validator's critical path)
    /// and `Ledger::apply_transaction` (signature *verification* + fee +
    /// dust-sweep + System Program dispatch - what a validator actually
    /// does per transaction). This is single-threaded sequential
    /// execution on whatever machine runs it, with no network/consensus
    /// overhead included - a floor on per-core execution throughput, not
    /// a network TPS claim. Run with:
    /// `cargo test --release -p qchain-execution -- --ignored --nocapture apply_transaction_throughput`
    #[test]
    #[ignore]
    fn apply_transaction_throughput() {
        const N: usize = 500;
        let mut ledger = new_test_ledger();
        let validator = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();

        let sign_start = std::time::Instant::now();
        let signed: Vec<Transaction> = (0..N)
            .map(|_| {
                let payer = Keypair::generate().unwrap();
                ledger.credit(payer.pubkey(), 10_000_000);
                let ix = Instruction {
                    program_id: Pubkey::system_program_id(),
                    accounts: vec![payer.pubkey(), bob],
                    data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
                };
                Transaction::new_signed(&payer, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap()
            })
            .collect();
        let sign_elapsed = sign_start.elapsed();

        let fee = signed[0].byte_size() as u64 * BASE_FEE_PER_BYTE_UNITS;

        let exec_start = std::time::Instant::now();
        for tx in &signed {
            ledger.apply_transaction(tx, &validator, 0).unwrap();
        }
        let exec_elapsed = exec_start.elapsed();

        println!(
            "sign+build {N} hybrid txs: {:?} total, {:?}/tx, {:.0} tx/s",
            sign_elapsed,
            sign_elapsed / N as u32,
            N as f64 / sign_elapsed.as_secs_f64()
        );
        println!(
            "apply_transaction (verify+fee+dust+dispatch) x{N}: {:?} total, {:?}/tx, {:.0} tx/s",
            exec_elapsed,
            exec_elapsed / N as u32,
            N as f64 / exec_elapsed.as_secs_f64()
        );
        println!("byte_size per tx: {} bytes, fee at default rate ({BASE_FEE_PER_BYTE_UNITS}/byte): {fee} units", signed[0].byte_size());
    }

    /// The real closure of the "registry is bookkeeping only" gap (see
    /// `project-lessons-learned`): a brand-new account signing with the
    /// SLH-DSA triple combo must be rejected while SLH-DSA hasn't been
    /// registered on this ledger at all - `combo_from_components` resolves
    /// the combo fine, but the registry lookup has nothing to match.
    #[test]
    fn a_new_account_using_an_unregistered_slh_dsa_combo_is_rejected() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate_with_slh_dsa().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        // Credit by address directly - `credit` doesn't go through
        // `apply_transaction`'s registry gate, only real transactions do.
        ledger.credit(alice.pubkey(), 1_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();

        let err = ledger.apply_transaction(&tx, &validator, 0).unwrap_err();
        assert!(matches!(err, ExecError::AlgorithmNotAcceptable(_)), "expected AlgorithmNotAcceptable, got {err:?}");
    }

    /// Same transaction as above, but this time SLH-DSA has genuinely been
    /// activated on this ledger's registry (exactly what a passed
    /// `Registry`-tier `ActivateAlgorithm` proposal's `Execute` does to
    /// `REGISTRY_ACCOUNT_ID`) - now it must succeed. This is the concrete,
    /// end-to-end proof that "activating" a scheme via governance really
    /// does change what a validator accepts, not just a bookkeeping list.
    #[test]
    fn a_new_account_using_slh_dsa_succeeds_once_the_scheme_is_actually_active() {
        let mut ledger = new_test_ledger();
        let mut registry = qchain_crypto::registry::genesis_registry();
        registry.push(qchain_crypto::slh_dsa_registry_entry(0));
        ledger.seed_account(REGISTRY_ACCOUNT_ID, Account { data: borsh::to_vec(&registry).unwrap(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) });

        let alice = Keypair::generate_with_slh_dsa().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        // SLH-DSA signatures are much larger than ML-DSA-65's (~29.8KB vs
        // ~3.4KB, see `project-lessons-learned`), so this combo's byte fee
        // is proportionally larger too - fund generously.
        ledger.credit(alice.pubkey(), 50_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();

        ledger.apply_transaction(&tx, &validator, 0).unwrap();
        assert_eq!(ledger.get_balance(&bob), 2_000_000, "the SLH-DSA-combo transaction must have actually executed");
    }

    /// A scheme that's been `Retired` must be rejected outright, even for
    /// an account that's used it since before retirement - the whole point
    /// of `Retired` (vs. `Deprecated`) is "no longer valid for signing at
    /// all" per `AlgorithmStatus`'s own docs.
    #[test]
    fn an_existing_account_is_rejected_once_its_scheme_is_retired() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        // First transaction succeeds normally (both schemes still Active).
        let ix0 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx0 = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix0]).unwrap();
        ledger.apply_transaction(&tx0, &validator, 0).unwrap();

        // Now retire ML-DSA-65 (as if a passed RetireAlgorithm proposal's
        // grace period fully elapsed) and try a second transaction from
        // the same, already-existing account.
        let mut registry = qchain_crypto::registry::genesis_registry();
        registry[1].status = qchain_crypto::AlgorithmStatus::Retired;
        assert_eq!(registry[1].id, qchain_crypto::ALGORITHM_ML_DSA_65);
        ledger.seed_account(REGISTRY_ACCOUNT_ID, Account { data: borsh::to_vec(&registry).unwrap(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) });

        let ix1 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx1 = Transaction::new_signed(&alice, 1, [0u8; 32], 50_000_000, vec![ix1]).unwrap();
        let err = ledger.apply_transaction(&tx1, &validator, 0).unwrap_err();
        assert!(matches!(err, ExecError::AlgorithmNotAcceptable(_)), "expected AlgorithmNotAcceptable, got {err:?}");
    }

    /// `Deprecated` only blocks *new* accounts from adopting a scheme -
    /// existing accounts keep working through the grace period, per
    /// `AlgorithmStatus::Deprecated`'s own documented semantics.
    #[test]
    fn an_existing_account_keeps_working_while_its_scheme_is_only_deprecated() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        // Each individual amount must clear DUST_THRESHOLD_UNITS on its
        // own - the sweep runs at the end of every single
        // `apply_transaction` call, not just once at the very end of this
        // test, so bob's balance after tx0 alone must already survive it.
        let ix0 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1_500_000 }).unwrap(),
        };
        let tx0 = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix0]).unwrap();
        ledger.apply_transaction(&tx0, &validator, 0).unwrap();

        let mut registry = qchain_crypto::registry::genesis_registry();
        registry[1].status = qchain_crypto::AlgorithmStatus::Deprecated { retirement_epoch: 1_000 };
        ledger.seed_account(REGISTRY_ACCOUNT_ID, Account { data: borsh::to_vec(&registry).unwrap(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) });

        let ix1 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1_500_000 }).unwrap(),
        };
        let tx1 = Transaction::new_signed(&alice, 1, [0u8; 32], 50_000_000, vec![ix1]).unwrap();
        ledger.apply_transaction(&tx1, &validator, 0).unwrap();
        assert_eq!(ledger.get_balance(&bob), 3_000_000, "an existing account must keep working through the deprecation grace period");
    }

    /// The other half of the same rule: a *brand-new* account may not
    /// adopt a `Deprecated` scheme, even though an existing account using
    /// it is still fine (previous test).
    #[test]
    fn a_new_account_cannot_adopt_a_deprecated_scheme() {
        let mut ledger = new_test_ledger();
        let mut registry = qchain_crypto::registry::genesis_registry();
        registry[1].status = qchain_crypto::AlgorithmStatus::Deprecated { retirement_epoch: 1_000 };
        ledger.seed_account(REGISTRY_ACCOUNT_ID, Account { data: borsh::to_vec(&registry).unwrap(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) });

        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 1_000_000);

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        let err = ledger.apply_transaction(&tx, &validator, 0).unwrap_err();
        assert!(matches!(err, ExecError::AlgorithmNotAcceptable(_)), "expected AlgorithmNotAcceptable, got {err:?}");
    }

    #[test]
    fn merkle_root_changes_after_a_real_transfer_and_matches_an_independent_computation() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        let root_before = ledger.merkle_root();
        // `Ledger::merkle_root()` isn't a cached shortcut - it must
        // agree with a fresh `StateTree` computed directly over the
        // same store.
        assert_eq!(root_before, qchain_storage::StateTree::new().root(ledger.store()));

        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 100_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        ledger.apply_transaction(&tx, &validator, 0).unwrap();

        let root_after = ledger.merkle_root();
        assert_ne!(root_before, root_after, "a real balance change must change the root");
        assert_eq!(root_after, qchain_storage::StateTree::new().root(ledger.store()));
    }

    #[test]
    fn a_single_instruction_transfer_captures_a_real_verifiable_receipt() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);
        assert!(ledger.transfer_receipts().is_empty());

        // Must clear DUST_THRESHOLD_UNITS (1_000_000), or bob's `to_after`
        // snapshot below (captured pre-dust-sweep) would disagree with the
        // real post-sweep store the final `ledger.merkle_root()` check
        // reads from.
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        let fee = ledger.apply_transaction(&tx, &validator, 0).unwrap();

        let receipts = ledger.transfer_receipts();
        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        assert_eq!(r.tx_hash, tx.hash());
        assert_eq!(r.from, alice.pubkey());
        assert_eq!(r.to, bob);
        assert_eq!(r.amount, 2_000_000);
        assert_eq!(r.fee, fee);
        assert_eq!(r.from_before.balance, 10_000_000);
        assert_eq!(r.from_after.balance, 10_000_000 - 2_000_000 - fee);
        assert_eq!(r.to_before.balance, 0);
        assert_eq!(r.to_after.balance, 2_000_000);
        assert_ne!(r.root_before, r.root_after);

        // The captured proofs must genuinely verify against their
        // claimed roots and hash exactly the claimed Account snapshots -
        // not just plausible-looking placeholders.
        let empty_leaf_hash = qchain_storage::StateTree::new().empty_leaf_hash();
        assert_eq!(r.from_proof_before.leaf_value_hash, Some(qchain_storage::hash_leaf(&r.from_before)));
        assert!(qchain_storage::verify_proof(r.root_before, &r.from_proof_before, empty_leaf_hash));
        assert_eq!(r.from_proof_after.leaf_value_hash, Some(qchain_storage::hash_leaf(&r.from_after)));
        assert!(qchain_storage::verify_proof(r.root_after, &r.from_proof_after, empty_leaf_hash));
        // Bob didn't exist before this transfer - a real exclusion proof.
        assert_eq!(r.to_proof_before.leaf_value_hash, None);
        assert!(qchain_storage::verify_proof(r.root_before, &r.to_proof_before, empty_leaf_hash));
        assert_eq!(r.to_proof_after.leaf_value_hash, Some(qchain_storage::hash_leaf(&r.to_after)));
        assert!(qchain_storage::verify_proof(r.root_after, &r.to_proof_after, empty_leaf_hash));

        // And the roots themselves must be the real, independently
        // computable roots before/after this exact transaction.
        assert_eq!(r.root_after, ledger.merkle_root());
    }

    /// The real, live-confirmed bug this closes (see `project-lessons-
    /// learned`): a transfer landing a resulting balance below
    /// `DUST_THRESHOLD_UNITS` (routine - a brand-new recipient starts
    /// there) used to capture `root_after`/`to_after` from *before* the
    /// dust sweep, so the receipt disagreed with what actually got
    /// committed - breaking the *next* receipt's `root_before` from
    /// chaining into it (`GET /stark_proof`'s `ChainBroken`). Reporting
    /// the real post-sweep value instead doesn't work either - tried and
    /// confirmed by an earlier version of this exact test - because
    /// `qchain-stark`'s AIR only ever models plain conservation
    /// (`to_after == to_before + amount`), with no notion of a dust
    /// sweep at all, so a "corrected" swept receipt fails the circuit's
    /// own internal arithmetic instead (`BalanceMismatch`). The only
    /// honest fix is not capturing a receipt at all for a transfer that
    /// would be dust-swept - this test confirms that: the sub-threshold
    /// transfer produces no receipt, but a normal, comfortably-above-
    /// threshold transfer right after it still gets a receipt whose
    /// `root_before` is the real current tree root (not chained from a
    /// receipt that was never captured), and that one receipt still
    /// genuinely proves and verifies end to end.
    #[test]
    fn a_transfer_landing_below_the_dust_threshold_captures_no_receipt_instead_of_an_unprovable_one() {
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let carol = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 50_000_000);

        // Sub-threshold: bob's resulting balance would be swept to 0 -
        // must not produce a receipt at all.
        let ix1 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: DUST_THRESHOLD_UNITS / 2 }).unwrap(),
        };
        let tx1 = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix1]).unwrap();
        ledger.apply_transaction(&tx1, &validator, 0).unwrap();
        assert_eq!(ledger.get_balance(&bob), 0, "the transfer itself must still execute and sweep the dust normally");
        assert!(ledger.transfer_receipts().is_empty(), "a transfer the circuit can't represent (dust-swept) must not capture a receipt at all");

        // A second, unrelated, comfortably-above-threshold transfer.
        let ix2 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), carol],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000_000 }).unwrap(),
        };
        let tx2 = Transaction::new_signed(&alice, 1, [0u8; 32], 50_000_000, vec![ix2]).unwrap();
        ledger.apply_transaction(&tx2, &validator, 0).unwrap();

        let receipts = ledger.transfer_receipts();
        assert_eq!(receipts.len(), 1, "only the provable transfer gets a receipt");
        let r = &receipts[0];
        assert_eq!(r.root_after, ledger.merkle_root(), "the captured root_after must match what was actually committed");

        // The real qchain-stark self-verification path itself - the
        // failure mode this closes surfaced exactly here, either as
        // `RootSequenceMismatch` (naive fix) or `BalanceMismatch`
        // (reporting the real swept value instead).
        let steps = vec![qchain_stark::TransferStep::conserving(r.from.to_bytes(), r.to.to_bytes(), r.from_before.balance, r.to_before.balance, r.amount, r.fee)];
        let bindings = vec![qchain_stark::RowStateBinding {
            root_before: r.root_before,
            root_after: r.root_after,
            from_before: r.from_before.clone(),
            from_after: r.from_after.clone(),
            to_before: r.to_before.clone(),
            to_after: r.to_after.clone(),
            from_proof_before: r.from_proof_before.clone(),
            from_proof_after: r.from_proof_after.clone(),
            to_proof_before: r.to_proof_before.clone(),
            to_proof_after: r.to_proof_after.clone(),
        }];
        let (proof, pub_inputs) = qchain_stark::prove_batch(&steps).unwrap();
        qchain_stark::verify_batch_bound_to_state(proof, pub_inputs, &bindings).expect("the one real captured receipt must still genuinely self-verify");
    }

    #[test]
    fn a_multi_instruction_transaction_does_not_capture_a_receipt() {
        // Out of scope by design (see receipt.rs module docs): a
        // multi-instruction transaction doesn't match the single-row
        // shape qchain-stark's AIR models, so no receipt is captured
        // for it, silently or otherwise.
        let mut ledger = new_test_ledger();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        let carol = Keypair::generate().unwrap().pubkey();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 10_000_000);

        let ix1 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1_000 }).unwrap(),
        };
        let ix2 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), carol],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 2_000 }).unwrap(),
        };
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![ix1, ix2]).unwrap();
        ledger.apply_transaction(&tx, &validator, 0).unwrap();

        assert!(ledger.transfer_receipts().is_empty(), "a multi-instruction transaction must not produce a receipt");
    }

    /// Minimal contract exercising the *real* on-chain calling convention
    /// (`run_wasm_instruction`'s doc comment: every argument arrives as an
    /// `i64`, packed back-to-back from `ix.data`) - unlike `wasm.rs`'s own
    /// `TRANSFER_WAT`, which calls `WasmExecutor::call` directly with
    /// hand-picked `Val::I32`/`Val::I64` params and so never exercises
    /// this project's actual instruction-data-to-args decoding at all.
    ///
    /// Checks `host_is_signer` on the source account before debiting - a
    /// real, live-confirmed vulnerability (see `project-lessons-learned`)
    /// was found and closed here: an earlier version of this exact
    /// contract had no such check, which let anyone name any funded
    /// account as `from` and drain it using only their own signature,
    /// mirroring the bug `SystemProgram::Transfer` already had to fix in
    /// `native.rs` (`transfer_from_an_account_other_than_the_payer_is_rejected`
    /// above) for the native System Program specifically.
    const I64_TRANSFER_WAT: &str = r#"
        (module
            (import "env" "host_get_balance" (func $get_balance (param i32) (result i64)))
            (import "env" "host_set_balance" (func $set_balance (param i32 i64)))
            (import "env" "host_is_signer" (func $is_signer (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "transfer") (param $from i64) (param $to i64) (param $amount i64)
                (local $from_balance i64)
                (local $to_balance i64)
                (if (i32.eqz (call $is_signer (i32.wrap_i64 (local.get $from))))
                    (then unreachable))
                (local.set $from_balance (call $get_balance (i32.wrap_i64 (local.get $from))))
                (local.set $to_balance (call $get_balance (i32.wrap_i64 (local.get $to))))
                (call $set_balance (i32.wrap_i64 (local.get $from)) (i64.sub (local.get $from_balance) (local.get $amount)))
                (call $set_balance (i32.wrap_i64 (local.get $to)) (i64.add (local.get $to_balance) (local.get $amount)))
            )
        )
    "#;

    fn deploy_i64_transfer_contract(ledger: &mut Ledger, deployer: &Keypair, validator: &Pubkey) -> Pubkey {
        let program_pk = Keypair::generate().unwrap().pubkey();
        let module_bytes = wat::parse_str(I64_TRANSFER_WAT).unwrap();
        let deploy_ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![program_pk],
            data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: "transfer".into() }).unwrap(),
        };
        let deploy_tx = Transaction::new_signed(deployer, 0, [0u8; 32], 50_000_000, vec![deploy_ix]).unwrap();
        ledger.apply_transaction(&deploy_tx, validator, 0).unwrap();
        program_pk
    }

    #[test]
    fn deploy_program_then_call_it_moves_balances_through_the_real_dispatch_path() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 50_000_000);

        let program_pk = deploy_i64_transfer_contract(&mut ledger, &deployer, &validator);

        // Deployment itself must not have created a wallet balance for
        // the program address, and it must be owned by the loader, not
        // the system program.
        let program_account = ledger.store().get(&program_pk).expect("program account must exist after deploy");
        assert_eq!(program_account.owner, crate::ids::LOADER_PROGRAM_ID);
        assert_eq!(program_account.balance, 0);

        // Fund two ordinary wallets, then call the deployed contract to
        // move value between them - the exact same operation `wasm.rs`'s
        // unit test proves in isolation, now proven through the real
        // dispatch path a live validator actually runs. `alice` must be
        // the transaction's own payer (accounts[0]/"from" must be the
        // signer), matching this project's single-signer authorization
        // model - see `host_is_signer` in the contract above.
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap().pubkey();
        ledger.credit(alice.pubkey(), 5_000_000);

        let mut call_data = Vec::new();
        call_data.extend_from_slice(&0i64.to_le_bytes()); // index 0 = alice
        call_data.extend_from_slice(&1i64.to_le_bytes()); // index 1 = bob
        call_data.extend_from_slice(&2_000_000i64.to_le_bytes());
        let call_ix = Instruction { program_id: program_pk, accounts: vec![alice.pubkey(), bob], data: call_data };
        let call_tx = Transaction::new_signed(&alice, 0, [0u8; 32], 50_000_000, vec![call_ix]).unwrap();
        let fee = ledger.apply_transaction(&call_tx, &validator, 0).unwrap();
        assert!(fee > 0, "a WASM call must still charge the byte fee (gas was 0 for this cheap contract, which is fine)");

        // Alice is both the payer (pays `fee`) and the contract's funds
        // source (pays the 2,000,000 the contract itself moves) - unlike
        // the pre-fix version of this test, where a separate `caller`
        // could debit alice's account without ever being her, which is
        // exactly the vulnerability this fix closed.
        assert_eq!(ledger.get_balance(&alice.pubkey()), 5_000_000 - fee - 2_000_000);
        assert_eq!(ledger.get_balance(&bob), 2_000_000);
    }

    /// The real, live-confirmed attack this session found on an actual
    /// 3-validator testnet: an attacker with no relationship to the
    /// victim's funds names the victim's address as `accounts[0]` ("from")
    /// and their own address as `accounts[1]` ("to"), signs the call
    /// transaction with only their own key, and the pre-fix contract
    /// drained the victim's entire balance - confirmed live against the
    /// deployed contract before this fix existed. Proves the fixed
    /// contract's `host_is_signer` check rejects it.
    #[test]
    fn calling_a_contract_naming_a_non_signer_account_as_the_funds_source_is_rejected() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 50_000_000);

        let program_pk = deploy_i64_transfer_contract(&mut ledger, &deployer, &validator);

        let victim = Keypair::generate().unwrap();
        let attacker = Keypair::generate().unwrap();
        ledger.credit(victim.pubkey(), 2_000_000);
        ledger.credit(attacker.pubkey(), 5_000_000);

        let mut call_data = Vec::new();
        call_data.extend_from_slice(&0i64.to_le_bytes()); // index 0 = victim, never signed
        call_data.extend_from_slice(&1i64.to_le_bytes()); // index 1 = attacker
        call_data.extend_from_slice(&2_000_000i64.to_le_bytes());
        let call_ix = Instruction { program_id: program_pk, accounts: vec![victim.pubkey(), attacker.pubkey()], data: call_data };
        // Signed only by the attacker - the victim never authorized this.
        let call_tx = Transaction::new_signed(&attacker, 0, [0u8; 32], 50_000_000, vec![call_ix]).unwrap();

        let result = ledger.apply_transaction(&call_tx, &validator, 0);
        assert!(result.is_err(), "a contract call naming a non-signer as the funds source must be rejected, not silently drain the victim");
        assert_eq!(ledger.get_balance(&victim.pubkey()), 2_000_000, "the victim's balance must be untouched");
    }

    /// A *malicious* contract that steals exactly like `I64_TRANSFER_WAT`
    /// but deliberately OMITS the `host_is_signer` guard - the whole point
    /// of the ledger-boundary enforcement is that this is rejected anyway.
    /// `host_is_signer` is advisory (a cooperative contract may consult it,
    /// but nothing forces bytecode to), so the previous test only proves
    /// the *reference* contract behaves; this proves the LEDGER refuses the
    /// debit even when the bytecode itself never checks. Value-conserving
    /// (from-=amount, to+=amount), so it slips past the minting invariant
    /// and is caught solely by the debit-authorization invariant.
    const STEAL_NO_SIGNER_CHECK_WAT: &str = r#"
        (module
            (import "env" "host_get_balance" (func $get_balance (param i32) (result i64)))
            (import "env" "host_set_balance" (func $set_balance (param i32 i64)))
            (memory (export "memory") 1)
            (func (export "steal") (param $from i64) (param $to i64) (param $amount i64)
                (local $from_balance i64)
                (local $to_balance i64)
                (local.set $from_balance (call $get_balance (i32.wrap_i64 (local.get $from))))
                (local.set $to_balance (call $get_balance (i32.wrap_i64 (local.get $to))))
                (call $set_balance (i32.wrap_i64 (local.get $from)) (i64.sub (local.get $from_balance) (local.get $amount)))
                (call $set_balance (i32.wrap_i64 (local.get $to)) (i64.add (local.get $to_balance) (local.get $amount)))
            )
        )
    "#;

    /// A *malicious* contract that mints: it sets an account's balance to a
    /// huge value out of nothing, increasing the total across the declared
    /// accounts. Caught by the minting invariant regardless of whether the
    /// target is the signer.
    const MINT_WAT: &str = r#"
        (module
            (import "env" "host_set_balance" (func $set_balance (param i32 i64)))
            (memory (export "memory") 1)
            (func (export "mint") (param $target i64)
                (call $set_balance (i32.wrap_i64 (local.get $target)) (i64.const 1000000000000))
            )
        )
    "#;

    fn deploy_wat(ledger: &mut Ledger, wat: &str, entry_point: &str, deployer: &Keypair, validator: &Pubkey) -> Pubkey {
        let program_pk = Keypair::generate().unwrap().pubkey();
        let module_bytes = wat::parse_str(wat).unwrap();
        let deploy_ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![program_pk],
            data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: entry_point.into() }).unwrap(),
        };
        let deploy_tx = Transaction::new_signed(deployer, 0, [0u8; 32], 50_000_000, vec![deploy_ix]).unwrap();
        ledger.apply_transaction(&deploy_tx, validator, 0).unwrap();
        program_pk
    }

    /// The ledger-boundary security guarantee, proven against bytecode that
    /// makes NO voluntary check: a malicious contract debiting a non-signer
    /// victim is rejected by the ledger itself, and the victim keeps every
    /// unit. This is the real closure of the finding - the reference
    /// contract's own `host_is_signer` check is a courtesy; the ledger is
    /// the enforcement.
    #[test]
    fn a_malicious_contract_that_skips_the_signer_check_still_cannot_drain_a_non_signer() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 50_000_000);

        let program_pk = deploy_wat(&mut ledger, STEAL_NO_SIGNER_CHECK_WAT, "steal", &deployer, &validator);

        let victim = Keypair::generate().unwrap();
        let attacker = Keypair::generate().unwrap();
        ledger.credit(victim.pubkey(), 2_000_000);
        ledger.credit(attacker.pubkey(), 5_000_000);

        let mut call_data = Vec::new();
        call_data.extend_from_slice(&0i64.to_le_bytes()); // index 0 = victim, never signed
        call_data.extend_from_slice(&1i64.to_le_bytes()); // index 1 = attacker
        call_data.extend_from_slice(&2_000_000i64.to_le_bytes());
        let call_ix = Instruction { program_id: program_pk, accounts: vec![victim.pubkey(), attacker.pubkey()], data: call_data };
        let call_tx = Transaction::new_signed(&attacker, 0, [0u8; 32], 50_000_000, vec![call_ix]).unwrap();

        let result = ledger.apply_transaction(&call_tx, &validator, 0);
        assert!(result.is_err(), "the ledger must reject a debit of a non-signer even when the bytecode never checks host_is_signer");
        assert_eq!(ledger.get_balance(&victim.pubkey()), 2_000_000, "victim's balance untouched");
    }

    /// A contract cannot conjure balance from nothing: even setting its own
    /// (signer's) account to a huge value is rejected by the minting
    /// invariant, because the total across declared accounts would grow.
    #[test]
    fn a_malicious_contract_cannot_mint_balance_from_nothing() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 50_000_000);

        let program_pk = deploy_wat(&mut ledger, MINT_WAT, "mint", &deployer, &validator);

        let attacker = Keypair::generate().unwrap();
        ledger.credit(attacker.pubkey(), 5_000_000);

        let mut call_data = Vec::new();
        call_data.extend_from_slice(&0i64.to_le_bytes()); // index 0 = attacker (the signer!) - still can't mint
        let call_ix = Instruction { program_id: program_pk, accounts: vec![attacker.pubkey()], data: call_data };
        let call_tx = Transaction::new_signed(&attacker, 0, [0u8; 32], 50_000_000, vec![call_ix]).unwrap();

        let balance_before = ledger.get_balance(&attacker.pubkey());
        let result = ledger.apply_transaction(&call_tx, &validator, 0);
        assert!(result.is_err(), "minting balance out of nothing must be rejected even for the signer's own account");
        // The instruction is rejected; only the byte fee for the attempt is
        // charged (no mint applied), so the balance never balloons.
        assert!(ledger.get_balance(&attacker.pubkey()) <= balance_before, "no minted balance may survive a rejected mint");
        assert!(ledger.get_balance(&attacker.pubkey()) < 1_000_000_000_000, "the minted value must not have been committed");
    }

    #[test]
    fn deploy_program_refuses_to_overwrite_an_existing_account() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 10_000_000);

        // An address that already holds a real account (a funded
        // wallet) - deploying a program there must be refused, not
        // silently clobber its existing balance/owner/data.
        let victim = Keypair::generate().unwrap().pubkey();
        ledger.credit(victim, 5_000_000);

        let module_bytes = wat::parse_str(I64_TRANSFER_WAT).unwrap();
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![victim],
            data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: "transfer".into() }).unwrap(),
        };
        let tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(result.is_err(), "deploying over an existing account must be rejected");
        assert_eq!(ledger.get_balance(&victim), 5_000_000, "the victim account must be completely untouched");
        assert_eq!(ledger.store().get(&victim).unwrap().owner, Pubkey::system_program_id(), "still an ordinary wallet, not hijacked into a program account");
    }

    #[test]
    fn deploy_program_rejects_bytecode_over_the_size_cap() {
        let mut ledger = new_test_ledger();
        let deployer = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(deployer.pubkey(), 1_000_000_000);

        let program_pk = Keypair::generate().unwrap().pubkey();
        let oversized = vec![0u8; crate::native::MAX_PROGRAM_BYTECODE_BYTES + 1];
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![program_pk],
            data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes: oversized, entry_point: "x".into() }).unwrap(),
        };
        let tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(result.is_err(), "oversized bytecode must be rejected before it's ever stored");
        assert!(ledger.store().get(&program_pk).is_none(), "a rejected deploy must leave no trace of the account");
    }

    #[test]
    fn calling_a_pubkey_with_no_deployed_program_and_no_native_program_is_rejected() {
        let mut ledger = new_test_ledger();
        let caller = Keypair::generate().unwrap();
        let validator = Keypair::generate().unwrap().pubkey();
        ledger.credit(caller.pubkey(), 5_000_000);

        // A fresh, never-deployed-to pubkey - not a native program id,
        // not a loader-owned account either.
        let nonexistent_program = Keypair::generate().unwrap().pubkey();
        let ix = Instruction { program_id: nonexistent_program, accounts: vec![], data: vec![] };
        let tx = Transaction::new_signed(&caller, 0, [0u8; 32], 50_000_000, vec![ix]).unwrap();
        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(matches!(result, Err(ExecError::UnknownProgram(_))));
    }

    /// The real, live-confirmed gas-metering-bypass this session found and
    /// closed (see `project-lessons-learned`): a contract that burns real
    /// fuel and then traps used to be billed identically to one that traps
    /// instantly - confirmed live by deploying both to a real testnet and
    /// seeing the exact same fee charged regardless of how many WASM
    /// iterations ran first. This proves the fix at the `Ledger` level: a
    /// deliberately expensive-then-trapping call must cost strictly more
    /// than a cheap-then-trapping one.
    #[test]
    fn a_wasm_call_that_burns_fuel_before_trapping_is_billed_for_that_fuel_not_just_the_byte_fee() {
        const CHEAP_TRAP_WAT: &str = r#"(module (func (export "go") unreachable))"#;
        const EXPENSIVE_TRAP_WAT: &str = r#"
            (module
                (func (export "go")
                    (local $i i64)
                    (local.set $i (i64.const 0))
                    (block $done
                        (loop $burn
                            (local.set $i (i64.add (local.get $i) (i64.const 1)))
                            (br_if $done (i64.ge_s (local.get $i) (i64.const 500000)))
                            (br $burn)
                        )
                    )
                    unreachable
                )
            )
        "#;

        fn deploy_and_call(wat_src: &str) -> u64 {
            let mut ledger = new_test_ledger();
            let deployer = Keypair::generate().unwrap();
            let validator = Keypair::generate().unwrap().pubkey();
            ledger.credit(deployer.pubkey(), 50_000_000);

            let program_pk = Keypair::generate().unwrap().pubkey();
            let module_bytes = wat::parse_str(wat_src).unwrap();
            let deploy_ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![program_pk],
                data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: "go".into() }).unwrap(),
            };
            let deploy_tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 50_000_000, vec![deploy_ix]).unwrap();
            ledger.apply_transaction(&deploy_tx, &validator, 0).unwrap();

            let caller = Keypair::generate().unwrap();
            ledger.credit(caller.pubkey(), 5_000_000);
            let call_ix = Instruction { program_id: program_pk, accounts: vec![], data: vec![] };
            let call_tx = Transaction::new_signed(&caller, 0, [0u8; 32], 50_000_000, vec![call_ix]).unwrap();
            let before = ledger.get_balance(&caller.pubkey());
            let result = ledger.apply_transaction(&call_tx, &validator, 0);
            assert!(result.is_err(), "a trapping call must still fail overall");
            before - ledger.get_balance(&caller.pubkey())
        }

        let cheap_cost = deploy_and_call(CHEAP_TRAP_WAT);
        let expensive_cost = deploy_and_call(EXPENSIVE_TRAP_WAT);
        assert!(
            expensive_cost > cheap_cost,
            "a call that burns real fuel before trapping ({expensive_cost}) must cost more than one that traps instantly ({cheap_cost}), not the same flat byte fee"
        );
    }

    #[test]
    fn a_trapped_multi_instruction_tx_does_not_commit_earlier_instruction_effects() {
        // CRITICAL regression: when a later instruction in a multi-instruction
        // transaction traps, the whole transaction must fail atomically - NONE
        // of an earlier instruction's balance effects may persist. The trap
        // billing used to commit `working[payer]` (which already carried those
        // effects) while discarding the counterpart accounts, minting/destroying
        // value. Here: [Transfer(payer->victim, N), trapping-call]. The transfer
        // debits the payer and credits the victim IN `working`; the trap then
        // fails the tx. Neither effect may survive: the victim must NOT be
        // credited, and the payer must NOT lose N (only the byte + trap fee).
        const CHEAP_TRAP_WAT: &str = r#"(module (func (export "go") unreachable))"#;
        let mut ledger = new_test_ledger();
        let validator = Keypair::generate().unwrap().pubkey();
        let deployer = Keypair::generate().unwrap();
        ledger.credit(deployer.pubkey(), 50_000_000);
        let program_pk = Keypair::generate().unwrap().pubkey();
        let module_bytes = wat::parse_str(CHEAP_TRAP_WAT).unwrap();
        let deploy_ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![program_pk],
            data: borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: "go".into() }).unwrap(),
        };
        let deploy_tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 50_000_000, vec![deploy_ix]).unwrap();
        ledger.apply_transaction(&deploy_tx, &validator, 0).unwrap();

        let payer = Keypair::generate().unwrap();
        let victim = Keypair::generate().unwrap().pubkey();
        ledger.credit(payer.pubkey(), 50_000_000);
        let n: u64 = 7_000_000;
        let sum = |l: &Ledger| l.get_balance(&payer.pubkey()) + l.get_balance(&victim) + l.get_balance(&validator) + l.get_balance(&deployer.pubkey());
        let payer_before = ledger.get_balance(&payer.pubkey());
        let victim_before = ledger.get_balance(&victim);
        let sum_before = sum(&ledger);
        let burned_before = ledger.total_burned;

        let transfer_ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer.pubkey(), victim],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: n }).unwrap(),
        };
        let trap_ix = Instruction { program_id: program_pk, accounts: vec![], data: vec![] };
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 50_000_000, vec![transfer_ix, trap_ix]).unwrap();
        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(result.is_err(), "the trapping tx must fail overall");

        // The victim's transfer credit must have been discarded with the failed tx.
        assert_eq!(ledger.get_balance(&victim), victim_before, "victim must NOT be credited from a trapped tx");
        // The payer must only have lost fees (byte + trap), NEVER the transferred
        // N - the transfer debit belonged to the failed tx and must be discarded.
        let payer_lost = payer_before - ledger.get_balance(&payer.pubkey());
        assert!(payer_lost < n, "payer must lose only the fee (byte+trap), not the transferred {n} (lost {payer_lost})");
        // Supply is conserved: the tracked balances drop by exactly the newly
        // burned fee, nothing minted or destroyed (the victim credit and the
        // discarded payer debit must net to zero).
        let sum_after = sum(&ledger);
        let burned_delta = ledger.total_burned - burned_before;
        assert_eq!(sum_before - sum_after, burned_delta, "supply must drop by exactly the burned fee");
    }
}
