//! Contract execution via Wasmtime - decision and rationale in
//! `ARCHITECTURE.md` §4 and the `wasm-vm-integration` skill: built-in fuel
//! metering mapping directly to the gas model, and a security/sandboxing
//! design lineage appropriate for running untrusted third-party bytecode
//! (unlike the natively-compiled, trusted programs in `native.rs`).
//!
//! Account access model: a contract call receives the *declared* accounts
//! for its instruction as an ordered list (`host_get_balance(index)` /
//! `host_set_balance(index, ..)`), the same "instruction declares which
//! accounts it touches" convention as `native.rs` and the rest of this
//! project's execution model (see `ARCHITECTURE.md` §4 and the
//! `blockchain-core-rust` skill) - it's what makes conflict detection
//! between transactions possible, and it means a contract can never reach
//! into an account it wasn't explicitly handed.

use borsh::BorshDeserialize;
use qchain_core::Account;
use qchain_crypto::{AlgorithmStatus, RegistryEntry, ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

/// A real, live-confirmed memory-bomb DoS this closes: fuel meters
/// instructions, not the data volume they touch (confirmed in
/// wasmtime-cranelift's `fuel_before_op` - every instruction costs exactly 1
/// fuel regardless of operand size), so `memory.grow`/`memory.fill` can
/// commit gigabytes of real RAM for a handful of fuel. Measured live: a
/// 72-byte contract calling `memory.grow` then a single `memory.fill` drove
/// a validator's RSS from ~9MB to ~1.96GB and blocked it for several real
/// seconds, for a fuel cost of 7 out of a 5,000,000 budget. 16MiB is
/// generous for this project's actual reference contracts (a few KB at
/// most) while making a bomb attempt fail cheaply instead of committing
/// real memory.
const MAX_CONTRACT_MEMORY_BYTES: usize = 16 * 1024 * 1024;

pub struct WasmCallResult {
    pub accounts: Vec<Account>,
    pub log: Vec<String>,
    pub fuel_consumed: u64,
    /// `Some(message)` when the call itself trapped (an explicit
    /// `unreachable`, an out-of-fuel abort, or any other WASM execution
    /// error) - `fuel_consumed` is still populated in this case, real fuel
    /// spent computing up to the point of the trap. See `Ledger::
    /// run_wasm_instruction`'s doc comment for the real, live-confirmed gas-
    /// metering-bypass this distinction closes: a contract that burns fuel
    /// and then traps must still be billed for it, not treated as if no
    /// computation happened at all.
    pub trap: Option<String>,
}

struct HostState {
    accounts: Vec<Account>,
    /// `is_signer[i]` is true when `accounts[i]` is the transaction's
    /// authenticated payer - the only notion of "signer" this single-signer
    /// execution model has (same limitation `native.rs`'s `SystemProgram`
    /// already documents). Exposed to contracts via `host_is_signer` so a
    /// contract *can* refuse to move funds out of an account nothing
    /// authorized - see that syscall's own doc comment for the real
    /// vulnerability this closed.
    is_signer: Vec<bool>,
    log: Vec<String>,
    /// Enforces `MAX_CONTRACT_MEMORY_BYTES` - see that constant's doc
    /// comment for the real memory-bomb DoS this closes.
    limits: StoreLimits,
}

fn read_memory(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let memory = caller.get_export("memory")?.into_memory()?;
    let data = memory.data(&caller);
    let (ptr, len) = (ptr as usize, len as usize);
    data.get(ptr..ptr.checked_add(len)?).map(|s| s.to_vec())
}

/// See `host_verify_signature`'s doc comment for the `registry_account_idx`
/// contract. Fails closed: a declared registry account that doesn't decode,
/// or doesn't list `scheme_id`, rejects rather than falling back silently.
fn scheme_acceptable(accounts: &[Account], registry_account_idx: i32, scheme_id: u16) -> bool {
    if registry_account_idx < 0 {
        return scheme_id == ALGORITHM_ED25519.0 || scheme_id == ALGORITHM_ML_DSA_65.0;
    }
    let Some(account) = accounts.get(registry_account_idx as usize) else {
        return false;
    };
    let Ok(registry) = Vec::<RegistryEntry>::try_from_slice(&account.data) else {
        return false;
    };
    registry.iter().any(|e| e.id.0 == scheme_id && !matches!(e.status, AlgorithmStatus::Retired))
}

pub struct WasmExecutor {
    engine: Engine,
}

impl Default for WasmExecutor {
    fn default() -> Self {
        Self::new().expect("wasmtime engine construction should not fail with a valid config")
    }
}

impl WasmExecutor {
    pub fn new() -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        Ok(WasmExecutor { engine })
    }

    fn build_linker(&self) -> anyhow::Result<Linker<HostState>> {
        let mut linker = Linker::new(&self.engine);

        linker.func_wrap("env", "host_get_balance", |caller: Caller<'_, HostState>, idx: i32| -> i64 {
            caller
                .data()
                .accounts
                .get(idx as usize)
                .map(|a| a.balance as i64)
                .unwrap_or(-1)
        })?;

        linker.func_wrap("env", "host_set_balance", |mut caller: Caller<'_, HostState>, idx: i32, new_balance: i64| {
            if new_balance >= 0 {
                if let Some(acc) = caller.data_mut().accounts.get_mut(idx as usize) {
                    acc.balance = new_balance as u64;
                }
            }
        })?;

        // Real fix for a real, live-confirmed vulnerability (see
        // `project-lessons-learned`): `host_get_balance`/`host_set_balance`
        // give a contract access to any account *declared* in the
        // instruction, by index, with no way to tell whether the entity at
        // that index actually authorized this call. A contract that trusts
        // caller-supplied indices for authorization (the only pattern the
        // host API allowed before this syscall existed) let anyone name any
        // victim's address as an instruction account and drain it, with
        // only the attacker's own signature - the exact same class of bug
        // `SystemProgram::Transfer` already had to fix for the native
        // System Program (`from != payer` check in `native.rs`), just
        // unfixed here because WASM contracts are a separate code path with
        // no equivalent primitive. A contract that wants "the caller must
        // own this account" semantics now can check `host_is_signer(idx)`
        // before debiting - it did not exist previously, so no prior
        // contract's logic could have relied on it.
        linker.func_wrap("env", "host_is_signer", |caller: Caller<'_, HostState>, idx: i32| -> i32 {
            i32::from(caller.data().is_signer.get(idx as usize).copied().unwrap_or(false))
        })?;

        linker.func_wrap("env", "host_log", |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
            if let Some(bytes) = read_memory(&mut caller, ptr, len) {
                let msg = String::from_utf8_lossy(&bytes).to_string();
                caller.data_mut().log.push(msg);
            }
        })?;

        // Exposes the crypto-agility layer to contracts (ARCHITECTURE.md
        // §4): a contract can verify a signature against any registered
        // scheme individually, e.g. for custom multisig authorization
        // logic, without reimplementing PQC math in WASM - it always calls
        // straight into the same native, liboqs-backed verification the
        // base protocol uses. `registry_account_idx` is opportunistic: pass
        // the index (into this instruction's declared accounts, same
        // convention as `host_get_balance`) of the on-chain algorithm
        // registry account to have this syscall actually consult its live
        // Active/Deprecated/Retired status - or pass -1 to skip that and
        // fall back to the two schemes valid unconditionally since genesis
        // (Ed25519, ML-DSA-65). Without a declared registry account,
        // SLH-DSA (or any future scheme) is never accepted here - a
        // contract that wants it must declare the registry account.
        linker.func_wrap(
            "env",
            "host_verify_signature",
            |mut caller: Caller<'_, HostState>,
             scheme_id: i32,
             pubkey_ptr: i32,
             pubkey_len: i32,
             msg_ptr: i32,
             msg_len: i32,
             sig_ptr: i32,
             sig_len: i32,
             registry_account_idx: i32|
             -> i32 {
                let Some(pubkey) = read_memory(&mut caller, pubkey_ptr, pubkey_len) else {
                    return 0;
                };
                let Some(msg) = read_memory(&mut caller, msg_ptr, msg_len) else {
                    return 0;
                };
                let Some(sig) = read_memory(&mut caller, sig_ptr, sig_len) else {
                    return 0;
                };
                if !scheme_acceptable(&caller.data().accounts, registry_account_idx, scheme_id as u16) {
                    return 0;
                }
                let ok = if scheme_id as u16 == ALGORITHM_ED25519.0 {
                    match (<[u8; 32]>::try_from(pubkey.as_slice()), <[u8; 64]>::try_from(sig.as_slice())) {
                        (Ok(pk), Ok(sg)) => qchain_crypto::verify_ed25519_component(&pk, &msg, &sg),
                        _ => false,
                    }
                } else if scheme_id as u16 == ALGORITHM_ML_DSA_65.0 {
                    qchain_crypto::verify_ml_dsa_65_component(&pubkey, &msg, &sig)
                } else if scheme_id as u16 == ALGORITHM_SLH_DSA.0 {
                    qchain_crypto::verify_slh_dsa_component(&pubkey, &msg, &sig)
                } else {
                    false
                };
                i32::from(ok)
            },
        )?;

        Ok(linker)
    }

    /// Instantiate `wasm_bytes` and call its exported `entry_point` with
    /// `params`, metered to `fuel_limit` units of fuel. `accounts` are the
    /// instruction's declared accounts, in order, exposed to the contract
    /// only via `host_get_balance`/`host_set_balance` by index - never
    /// directly. `is_signer` (same length/order as `accounts`) is what
    /// `host_is_signer` reports back to the contract.
    pub fn call(
        &self,
        wasm_bytes: &[u8],
        entry_point: &str,
        params: &[Val],
        accounts: Vec<Account>,
        is_signer: Vec<bool>,
        fuel_limit: u64,
    ) -> anyhow::Result<WasmCallResult> {
        let module = Module::new(&self.engine, wasm_bytes)?;
        let linker = self.build_linker()?;

        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let host_state = HostState { accounts, is_signer, log: Vec::new(), limits };
        let mut store = Store::new(&self.engine, host_state);
        store.set_fuel(fuel_limit)?;
        store.limiter(|state| &mut state.limits);

        let instance = linker.instantiate(&mut store, &module)?;
        let func = instance
            .get_func(&mut store, entry_point)
            .ok_or_else(|| anyhow::anyhow!("no exported function named '{entry_point}'"))?;

        let result_count = func.ty(&store).results().len();
        let mut results = vec![Val::I64(0); result_count];
        // Deliberately not `?` here (see `WasmCallResult::trap`'s doc
        // comment): a trap - an explicit `unreachable`, running out of the
        // fuel budget, or any other execution error - still leaves the
        // store's remaining-fuel counter meaningful, since Wasmtime doesn't
        // poison the `Store` on a trap. Capturing that instead of
        // early-returning is what lets the caller bill for fuel actually
        // spent computing up to the point of failure, rather than treating
        // a trapped call as if it cost nothing.
        let call_result = func.call(&mut store, params, &mut results);

        let remaining = store.get_fuel()?;
        let fuel_consumed = fuel_limit.saturating_sub(remaining);
        let trap = call_result.err().map(|e| e.to_string());
        let host_state = store.into_data();

        Ok(WasmCallResult { accounts: host_state.accounts, log: host_state.log, fuel_consumed, trap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Pubkey;

    fn wallet(balance: u64) -> Account {
        Account {
            balance,
            nonce: 0,
            algorithm_id: qchain_crypto::COMBO_HYBRID_ED25519_ML_DSA_65,
            owner: Pubkey::system_program_id(),
            code_hash: [0u8; 32],
            data: vec![],
        }
    }

    /// A minimal WASM "transfer" contract, hand-written in WAT: reads two
    /// account balances via host calls, moves `amount` from account 0 to
    /// account 1, writes both back. Proves the whole pipeline - module
    /// loading, fuel metering, host function calls mutating account state -
    /// works end to end, not just in isolation.
    const TRANSFER_WAT: &str = r#"
        (module
            (import "env" "host_get_balance" (func $get_balance (param i32) (result i64)))
            (import "env" "host_set_balance" (func $set_balance (param i32 i64)))
            (memory (export "memory") 1)
            (func (export "transfer") (param $from i32) (param $to i32) (param $amount i64)
                (local $from_balance i64)
                (local $to_balance i64)
                (local.set $from_balance (call $get_balance (local.get $from)))
                (local.set $to_balance (call $get_balance (local.get $to)))
                (call $set_balance (local.get $from) (i64.sub (local.get $from_balance) (local.get $amount)))
                (call $set_balance (local.get $to) (i64.add (local.get $to_balance) (local.get $amount)))
            )
        )
    "#;

    #[test]
    fn wasm_contract_transfers_between_accounts() {
        let wasm_bytes = wat::parse_str(TRANSFER_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();
        let accounts = vec![wallet(1_000), wallet(0)];

        let result = executor
            .call(
                &wasm_bytes,
                "transfer",
                &[Val::I32(0), Val::I32(1), Val::I64(300)],
                accounts,
                vec![true, false],
                1_000_000,
            )
            .unwrap();

        assert_eq!(result.accounts[0].balance, 700);
        assert_eq!(result.accounts[1].balance, 300);
        assert!(result.fuel_consumed > 0, "a real contract call must consume some fuel");
    }

    #[test]
    fn insufficient_fuel_aborts_execution() {
        let wasm_bytes = wat::parse_str(TRANSFER_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();
        let accounts = vec![wallet(1_000), wallet(0)];

        // The call itself traps (`Ok(..)` with `trap: Some(..)`, not `Err`)
        // - see `WasmCallResult::trap`'s doc comment for why this is no
        // longer a hard `Err`: the caller needs `fuel_consumed` even when
        // the call fails, to bill for fuel actually spent, not just detect
        // failure.
        let result = executor
            .call(&wasm_bytes, "transfer", &[Val::I32(0), Val::I32(1), Val::I64(300)], accounts, vec![true, false], 1)
            .unwrap();
        assert!(result.trap.is_some(), "1 unit of fuel must not be enough to complete a real call");
    }

    /// The exact live-confirmed gas-metering-bypass this closes (see
    /// `project-lessons-learned`): a contract that burns real fuel and then
    /// deliberately traps must report that fuel as consumed, not zero -
    /// otherwise the caller (`Ledger::run_wasm_instruction`) has no way to
    /// bill for the computation that actually happened.
    #[test]
    fn fuel_consumed_before_a_deliberate_trap_is_still_reported() {
        const BURN_THEN_TRAP_WAT: &str = r#"
            (module
                (func (export "burn_then_trap")
                    (local $i i64)
                    (local.set $i (i64.const 0))
                    (block $done
                        (loop $burn
                            (local.set $i (i64.add (local.get $i) (i64.const 1)))
                            (br_if $done (i64.ge_s (local.get $i) (i64.const 1000)))
                            (br $burn)
                        )
                    )
                    unreachable
                )
            )
        "#;
        let wasm_bytes = wat::parse_str(BURN_THEN_TRAP_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();

        let result = executor.call(&wasm_bytes, "burn_then_trap", &[], vec![], vec![], 1_000_000).unwrap();
        assert!(result.trap.is_some(), "the deliberate `unreachable` must be reported as a trap");
        assert!(result.fuel_consumed > 0, "fuel spent looping before the trap must not be reported as zero");
    }

    /// The exact real, live-confirmed memory-bomb DoS `MAX_CONTRACT_MEMORY_
    /// BYTES`/`StoreLimits` closes - see that constant's doc comment for the
    /// measured real numbers (a 72-byte contract driving RSS from ~9MB to
    /// ~1.96GB for 7 fuel, live against a real single-validator testnet).
    /// This reproduces the identical shape (grow then fill far past the
    /// limit) and confirms it now traps cheaply instead of committing real
    /// memory.
    #[test]
    fn a_contract_growing_memory_past_the_configured_limit_traps_instead_of_committing_real_memory() {
        const MEMORY_BOMB_WAT: &str = r#"
            (module
                (memory (export "memory") 1 65536)
                (func (export "bomb")
                    (drop (memory.grow (i32.const 30520)))
                    (memory.fill (i32.const 0) (i32.const 65) (i32.const 2000000000))
                )
            )
        "#;
        let wasm_bytes = wat::parse_str(MEMORY_BOMB_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();

        let result = executor.call(&wasm_bytes, "bomb", &[], vec![], vec![], 5_000_000).unwrap();
        assert!(result.trap.is_some(), "growing memory past MAX_CONTRACT_MEMORY_BYTES must trap, not succeed");
        assert!(result.fuel_consumed < 100, "the trap must fire on the grow itself, not after real work - got {} fuel", result.fuel_consumed);
    }

    const IS_SIGNER_WAT: &str = r#"
        (module
            (import "env" "host_is_signer" (func $is_signer (param i32) (result i32)))
            (func (export "check") (param $idx i32) (result i32)
                (call $is_signer (local.get $idx))
            )
        )
    "#;

    #[test]
    fn host_is_signer_reports_the_real_signer_index_and_rejects_out_of_range() {
        let wasm_bytes = wat::parse_str(IS_SIGNER_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();
        let module = wasmtime::Module::new(&executor.engine, &wasm_bytes).unwrap();
        let linker = executor.build_linker().unwrap();
        let accounts = vec![wallet(0), wallet(0)];
        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let mut store = wasmtime::Store::new(&executor.engine, HostState { accounts, is_signer: vec![true, false], log: vec![], limits });
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let func = instance.get_func(&mut store, "check").unwrap();

        let call = |store: &mut wasmtime::Store<HostState>, idx: i32| -> i32 {
            let mut results = vec![Val::I32(0)];
            func.call(&mut *store, &[Val::I32(idx)], &mut results).unwrap();
            results[0].i32().unwrap()
        };

        assert_eq!(call(&mut store, 0), 1, "index 0 is the real signer");
        assert_eq!(call(&mut store, 1), 0, "index 1 was only declared, never signed");
        assert_eq!(call(&mut store, 99), 0, "an out-of-range index must fail closed, not panic or trap");
    }

    const VERIFY_WAT: &str = r#"
        (module
            (import "env" "host_verify_signature"
                (func $verify (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "check")
                (param $scheme i32) (param $pk_ptr i32) (param $pk_len i32)
                (param $msg_ptr i32) (param $msg_len i32) (param $sig_ptr i32) (param $sig_len i32)
                (param $registry_idx i32)
                (result i32)
                (call $verify
                    (local.get $scheme)
                    (local.get $pk_ptr) (local.get $pk_len)
                    (local.get $msg_ptr) (local.get $msg_len)
                    (local.get $sig_ptr) (local.get $sig_len)
                    (local.get $registry_idx))
            )
        )
    "#;

    /// Lays out `pubkey`/`msg`/`sig` back-to-back in `store`'s linear memory
    /// and calls the WAT module's `check` export - shared by every
    /// `host_verify_signature` test below.
    fn call_verify_syscall(
        executor: &WasmExecutor,
        accounts: Vec<Account>,
        scheme_id: u16,
        pubkey: &[u8],
        msg: &[u8],
        sig: &[u8],
        registry_account_idx: i32,
    ) -> i32 {
        let wasm_bytes = wat::parse_str(VERIFY_WAT).unwrap();
        let module = wasmtime::Module::new(&executor.engine, &wasm_bytes).unwrap();
        let linker = executor.build_linker().unwrap();
        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let mut store = wasmtime::Store::new(&executor.engine, HostState { accounts, is_signer: vec![], log: vec![], limits });
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let memory = instance.get_memory(&mut store, "memory").unwrap();

        let pk_off = 0usize;
        memory.write(&mut store, pk_off, pubkey).unwrap();
        let msg_off = pk_off + pubkey.len();
        memory.write(&mut store, msg_off, msg).unwrap();
        let sig_off = msg_off + msg.len();
        memory.write(&mut store, sig_off, sig).unwrap();

        let func = instance.get_func(&mut store, "check").unwrap();
        let mut results = vec![Val::I32(0)];
        func.call(
            &mut store,
            &[
                Val::I32(scheme_id as i32),
                Val::I32(pk_off as i32),
                Val::I32(pubkey.len() as i32),
                Val::I32(msg_off as i32),
                Val::I32(msg.len() as i32),
                Val::I32(sig_off as i32),
                Val::I32(sig.len() as i32),
                Val::I32(registry_account_idx),
            ],
            &mut results,
        )
        .unwrap();
        results[0].i32().unwrap()
    }

    #[test]
    fn contract_can_verify_a_signature_via_the_crypto_agility_syscall() {
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::Keypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();

        let result = call_verify_syscall(&executor, vec![], ALGORITHM_ED25519.0, &bundle.components[0].bytes, msg, &sig.components[0].bytes, -1);
        assert_eq!(result, 1, "contract-side verification of a real signature must succeed");
    }

    #[test]
    fn syscall_rejects_slh_dsa_without_a_declared_registry_account() {
        // No registry account declared (-1) falls back to the two schemes
        // valid unconditionally since genesis - SLH-DSA isn't one of them.
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::slh_dsa::SlhDsaKeypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();

        let result = call_verify_syscall(&executor, vec![], qchain_crypto::ALGORITHM_SLH_DSA.0, kp.public_key_bytes(), msg, &sig, -1);
        assert_eq!(result, 0, "SLH-DSA must not verify without an opted-in registry lookup");
    }

    #[test]
    fn syscall_accepts_slh_dsa_when_the_declared_registry_account_has_it_active() {
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::slh_dsa::SlhDsaKeypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();

        let registry = vec![qchain_crypto::slh_dsa_registry_entry(0)];
        let registry_account = Account { data: borsh::to_vec(&registry).unwrap(), ..wallet(0) };

        let result =
            call_verify_syscall(&executor, vec![registry_account], qchain_crypto::ALGORITHM_SLH_DSA.0, kp.public_key_bytes(), msg, &sig, 0);
        assert_eq!(result, 1, "a live, Active registry entry for SLH-DSA must make the syscall accept it");
    }

    #[test]
    fn syscall_rejects_a_retired_scheme_even_though_it_would_otherwise_verify() {
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::Keypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();

        let mut entry = qchain_crypto::registry::genesis_registry()[0].clone();
        entry.status = qchain_crypto::AlgorithmStatus::Retired;
        let registry_account = Account { data: borsh::to_vec(&vec![entry]).unwrap(), ..wallet(0) };

        let result =
            call_verify_syscall(&executor, vec![registry_account], ALGORITHM_ED25519.0, &bundle.components[0].bytes, msg, &sig.components[0].bytes, 0);
        assert_eq!(result, 0, "a Retired scheme must be rejected by the syscall even though the raw signature is genuinely valid");
    }
}
