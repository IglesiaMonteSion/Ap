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

use qchain_core::Account;
use qchain_crypto::{ALGORITHM_ED25519, ALGORITHM_ML_DSA_65};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, Val};

pub struct WasmCallResult {
    pub accounts: Vec<Account>,
    pub log: Vec<String>,
    pub fuel_consumed: u64,
}

struct HostState {
    accounts: Vec<Account>,
    log: Vec<String>,
}

fn read_memory(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let memory = caller.get_export("memory")?.into_memory()?;
    let data = memory.data(&caller);
    let (ptr, len) = (ptr as usize, len as usize);
    data.get(ptr..ptr.checked_add(len)?).map(|s| s.to_vec())
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

        linker.func_wrap("env", "host_log", |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
            if let Some(bytes) = read_memory(&mut caller, ptr, len) {
                let msg = String::from_utf8_lossy(&bytes).to_string();
                caller.data_mut().log.push(msg);
            }
        })?;

        // Exposes the crypto-agility layer to contracts (ARCHITECTURE.md
        // §4): a contract can verify a signature against either registered
        // scheme individually, e.g. for custom multisig authorization
        // logic, without reimplementing PQC math in WASM - it always calls
        // straight into the same native, liboqs-backed verification the
        // base protocol uses.
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
             sig_len: i32|
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
                let ok = if scheme_id as u16 == ALGORITHM_ED25519.0 {
                    match (<[u8; 32]>::try_from(pubkey.as_slice()), <[u8; 64]>::try_from(sig.as_slice())) {
                        (Ok(pk), Ok(sg)) => qchain_crypto::verify_ed25519_component(&pk, &msg, &sg),
                        _ => false,
                    }
                } else if scheme_id as u16 == ALGORITHM_ML_DSA_65.0 {
                    qchain_crypto::verify_ml_dsa_65_component(&pubkey, &msg, &sig)
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
    /// directly.
    pub fn call(
        &self,
        wasm_bytes: &[u8],
        entry_point: &str,
        params: &[Val],
        accounts: Vec<Account>,
        fuel_limit: u64,
    ) -> anyhow::Result<WasmCallResult> {
        let module = Module::new(&self.engine, wasm_bytes)?;
        let linker = self.build_linker()?;

        let host_state = HostState { accounts, log: Vec::new() };
        let mut store = Store::new(&self.engine, host_state);
        store.set_fuel(fuel_limit)?;

        let instance = linker.instantiate(&mut store, &module)?;
        let func = instance
            .get_func(&mut store, entry_point)
            .ok_or_else(|| anyhow::anyhow!("no exported function named '{entry_point}'"))?;

        let result_count = func.ty(&store).results().len();
        let mut results = vec![Val::I64(0); result_count];
        func.call(&mut store, params, &mut results)?;

        let remaining = store.get_fuel()?;
        let fuel_consumed = fuel_limit.saturating_sub(remaining);
        let host_state = store.into_data();

        Ok(WasmCallResult {
            accounts: host_state.accounts,
            log: host_state.log,
            fuel_consumed,
        })
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

        let result = executor.call(&wasm_bytes, "transfer", &[Val::I32(0), Val::I32(1), Val::I64(300)], accounts, 1);
        assert!(result.is_err(), "1 unit of fuel must not be enough to complete a real call");
    }

    const VERIFY_WAT: &str = r#"
        (module
            (import "env" "host_verify_signature"
                (func $verify (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "check")
                (param $scheme i32) (param $pk_ptr i32) (param $pk_len i32)
                (param $msg_ptr i32) (param $msg_len i32) (param $sig_ptr i32) (param $sig_len i32)
                (result i32)
                (call $verify
                    (local.get $scheme)
                    (local.get $pk_ptr) (local.get $pk_len)
                    (local.get $msg_ptr) (local.get $msg_len)
                    (local.get $sig_ptr) (local.get $sig_len))
            )
        )
    "#;

    #[test]
    fn contract_can_verify_a_signature_via_the_crypto_agility_syscall() {
        let wasm_bytes = wat::parse_str(VERIFY_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();

        let kp = qchain_crypto::Keypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();

        // Lay out pubkey, message, and signature back-to-back in linear
        // memory by writing them via a second contract instance's memory
        // export directly (test-only convenience - a real contract would
        // receive this data as instruction args).
        let module = wasmtime::Module::new(&executor.engine, &wasm_bytes).unwrap();
        let linker = executor.build_linker().unwrap();
        let mut store = wasmtime::Store::new(&executor.engine, HostState { accounts: vec![], log: vec![] });
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let memory = instance.get_memory(&mut store, "memory").unwrap();

        let pk_off = 0usize;
        memory.write(&mut store, pk_off, &bundle.ed25519).unwrap();
        let msg_off = pk_off + bundle.ed25519.len();
        memory.write(&mut store, msg_off, msg).unwrap();
        let sig_off = msg_off + msg.len();
        memory.write(&mut store, sig_off, &sig.ed25519.0).unwrap();

        let func = instance.get_func(&mut store, "check").unwrap();
        let mut results = vec![Val::I32(0)];
        func.call(
            &mut store,
            &[
                Val::I32(ALGORITHM_ED25519.0 as i32),
                Val::I32(pk_off as i32),
                Val::I32(bundle.ed25519.len() as i32),
                Val::I32(msg_off as i32),
                Val::I32(msg.len() as i32),
                Val::I32(sig_off as i32),
                Val::I32(64),
            ],
            &mut results,
        )
        .unwrap();

        assert_eq!(results[0].i32(), Some(1), "contract-side verification of a real signature must succeed");
    }
}
