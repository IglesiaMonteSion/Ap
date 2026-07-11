//! Ties together account storage (`qchain-storage`), native programs, and
//! WASM contracts into `apply_transaction` - the state-transition function
//! this project's execution layer exists to provide. Fee model and dust
//! sweep per `ARCHITECTURE.md` §5.

use crate::error::ExecError;
use crate::ids::{PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID};
use crate::native::{NativeProgram, SystemInstruction};
use crate::params::EconomicParams;
use crate::receipt::TransferReceipt;
use crate::wasm::WasmExecutor;
use borsh::BorshDeserialize;
use qchain_core::{Account, Instruction, Round, Transaction};
use qchain_crypto::{AlgorithmStatus, Pubkey, RegistryEntry};
use qchain_storage::{IncrementalStateTree, MerkleProof, StateStore};
use std::collections::HashMap;
use wasmtime::Val;

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
    tree: IncrementalStateTree,
    /// Real captured before/after state for every single-instruction
    /// `Transfer` this ledger has applied - see `receipt.rs` module docs
    /// for exactly what's captured, why it's scoped this narrowly, and
    /// the deliberate "unbounded in-memory `Vec`" limitation.
    transfer_receipts: Vec<TransferReceipt>,
}

impl Ledger {
    pub fn new(store: Box<dyn StateStore>) -> anyhow::Result<Self> {
        let mut tree = IncrementalStateTree::new();
        // A store opened from a prior run (`SledStore` pointed at an
        // existing `data_dir`) already holds real accounts the tree has
        // never seen - prime the cache from the store's own contents
        // once at construction so `note_set` alone is sufficient from
        // here on. A fresh/empty store makes this a no-op loop.
        for (pk, account) in store.iter() {
            tree.note_set(&pk, &account);
        }
        Ok(Ledger { store, programs: HashMap::new(), wasm: WasmExecutor::new()?, total_burned: 0, tree, transfer_receipts: Vec::new() })
    }

    pub fn register_program(&mut self, id: Pubkey, program: Program) {
        self.programs.insert(id, program);
    }

    pub fn store(&self) -> &dyn StateStore {
        self.store.as_ref()
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

    /// Every `Transfer` receipt captured so far, oldest first - the raw
    /// material a light-client-facing RPC endpoint proves a
    /// `qchain-stark` batch from. See `receipt.rs` for scope.
    pub fn transfer_receipts(&self) -> &[TransferReceipt] {
        &self.transfer_receipts
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
        } else {
            self.credit(fee_collector, validator_share);
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
    fn current_params(&self) -> EconomicParams {
        self.store
            .get(&PARAMS_ACCOUNT_ID)
            .and_then(|a| EconomicParams::try_from_slice(&a.data).ok())
            .unwrap_or_default()
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
        if !tx.verify_signature() {
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
        let byte_fee = params.base_fee_per_byte * tx.byte_size() as u64;
        if payer_account.balance < byte_fee {
            return Err(ExecError::InsufficientFunds);
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
        let pre_capture: Option<(Pubkey, Pubkey, u64, Account, Account, [u8; 32], MerkleProof, MerkleProof)> =
            if tx.message.instructions.len() == 1 && tx.message.instructions[0].program_id == Pubkey::system_program_id() {
                let ix = &tx.message.instructions[0];
                match (SystemInstruction::try_from_slice(&ix.data), ix.accounts.first(), ix.accounts.get(1)) {
                    (Ok(SystemInstruction::Transfer { amount }), Some(&from), Some(&to)) => {
                        let root_before = self.tree.root();
                        let from_proof_before = self.tree.prove(&from);
                        let to_proof_before = self.tree.prove(&to);
                        let from_before = self.store.get(&from).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
                        let to_before = self.store.get(&to).unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
                        Some((from, to, amount, from_before, to_before, root_before, from_proof_before, to_proof_before))
                    }
                    _ => None,
                }
            } else {
                None
            };

        payer_account.balance -= byte_fee;
        payer_account.nonce += 1;
        self.write_account(tx.message.payer, payer_account.clone());

        let burn_share = byte_fee / 2;
        let validator_share = byte_fee - burn_share;
        self.total_burned += burn_share;
        self.credit_validator_share(*fee_collector, validator_share, &params)?;

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
                    total_gas_fee +=
                        self.run_wasm_instruction(module_bytes, entry_point, ix, &tx.message.payer, &mut working, params.gas_price_per_fuel)?;
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
                    total_gas_fee += self.run_wasm_instruction(
                        &program_data.module_bytes,
                        &program_data.entry_point,
                        ix,
                        &tx.message.payer,
                        &mut working,
                        params.gas_price_per_fuel,
                    )?;
                }
            }
        }

        // Capture the "after" half now - deliberately *before* the dust
        // sweep below, since the STARK's conservation equations model
        // the transfer's own raw arithmetic, not the dust-sweep
        // adjustment that may still zero a resulting balance
        // afterward - same class of documented simplification as
        // `qchain-stark`'s own "doesn't re-derive full Ledger fee/nonce
        // semantics" scope note.
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
            let root_after = self.tree.root_with_pending(&working_changes);
            let from_proof_after = self.tree.prove_with_pending(&from, &working_changes);
            let to_proof_after = self.tree.prove_with_pending(&to, &working_changes);
            let from_after = working.get(&from).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
            let to_after = working.get(&to).cloned().unwrap_or_else(|| Account::new_wallet(Pubkey::system_program_id()));
            self.transfer_receipts.push(TransferReceipt {
                tx_hash: tx.hash(),
                from,
                to,
                amount,
                fee: byte_fee,
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
            });
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
            if account.owner == Pubkey::system_program_id() && account.balance > 0 && account.balance < params.dust_threshold {
                self.total_burned += account.balance;
                account.balance = 0;
            }
            self.write_account(pk, account);
        }

        Ok(byte_fee + total_gas_fee)
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

        let result = self
            .wasm
            .call(module_bytes, entry_point, &args, accounts, is_signer, DEFAULT_FUEL_LIMIT)
            .map_err(|e| ExecError::Wasm(e.to_string()))?;

        for (pk, account) in ix.accounts.iter().zip(result.accounts.into_iter()) {
            working.insert(*pk, account);
        }

        Ok(result.fuel_consumed * gas_price_per_fuel)
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();

        let fee = ledger.apply_transaction(&tx, &validator, 0).unwrap();
        assert!(fee > 0, "a multi-kilobyte hybrid-signed transaction must not be free");

        assert_eq!(ledger.get_balance(&bob), 2_000_000);
        assert_eq!(ledger.get_balance(&alice.pubkey()), 10_000_000 - 2_000_000 - fee);
        assert_eq!(ledger.get_balance(&validator), fee - fee / 2, "validator gets its half of the burned/split fee");
        assert_eq!(ledger.total_burned, fee / 2);
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();
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
            Transaction::new_signed(alice, nonce, [0u8; 32], 1_000_000, vec![ix]).unwrap()
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
                Transaction::new_signed(&payer, 0, [0u8; 32], 1_000_000, vec![ix]).unwrap()
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();

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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();

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
        let tx0 = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix0]).unwrap();
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
        let tx1 = Transaction::new_signed(&alice, 1, [0u8; 32], 100_000, vec![ix1]).unwrap();
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
        let tx0 = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix0]).unwrap();
        ledger.apply_transaction(&tx0, &validator, 0).unwrap();

        let mut registry = qchain_crypto::registry::genesis_registry();
        registry[1].status = qchain_crypto::AlgorithmStatus::Deprecated { retirement_epoch: 1_000 };
        ledger.seed_account(REGISTRY_ACCOUNT_ID, Account { data: borsh::to_vec(&registry).unwrap(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) });

        let ix1 = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![alice.pubkey(), bob],
            data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1_500_000 }).unwrap(),
        };
        let tx1 = Transaction::new_signed(&alice, 1, [0u8; 32], 100_000, vec![ix1]).unwrap();
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix]).unwrap();
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
        let tx = Transaction::new_signed(&alice, 0, [0u8; 32], 100_000, vec![ix1, ix2]).unwrap();
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
        let deploy_tx = Transaction::new_signed(deployer, 0, [0u8; 32], 1_000_000, vec![deploy_ix]).unwrap();
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
        let call_tx = Transaction::new_signed(&alice, 0, [0u8; 32], 1_000_000, vec![call_ix]).unwrap();
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
        let call_tx = Transaction::new_signed(&attacker, 0, [0u8; 32], 1_000_000, vec![call_ix]).unwrap();

        let result = ledger.apply_transaction(&call_tx, &validator, 0);
        assert!(result.is_err(), "a contract call naming a non-signer as the funds source must be rejected, not silently drain the victim");
        assert_eq!(ledger.get_balance(&victim.pubkey()), 2_000_000, "the victim's balance must be untouched");
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
        let tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 1_000_000, vec![ix]).unwrap();
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
        let tx = Transaction::new_signed(&deployer, 0, [0u8; 32], 1_000_000, vec![ix]).unwrap();
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
        let tx = Transaction::new_signed(&caller, 0, [0u8; 32], 1_000_000, vec![ix]).unwrap();
        let result = ledger.apply_transaction(&tx, &validator, 0);
        assert!(matches!(result, Err(ExecError::UnknownProgram(_))));
    }
}
