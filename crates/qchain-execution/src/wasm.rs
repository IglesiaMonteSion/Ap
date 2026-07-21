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
use qchain_crypto::{AlgorithmStatus, Pubkey, RegistryEntry, ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasmtime::{Caller, Config, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Val};

/// Separador de dominio para derivar una dirección de cuenta PROPIA DEL PROGRAMA
/// (PDA, SDK v0.3): `pda = SHA3-256(PDA_DOMAIN ‖ program_id(32) ‖ seed)`. La
/// MISMA fórmula la usa el cliente off-chain (`qchain_wasm::program_pda`) para
/// derivar la dirección que incluye en `ix.accounts`. Como el `program_id`
/// entra en el hash, un programa NUNCA puede derivar (ni reclamar) la PDA de
/// otro programa → sin front-running entre programas.
pub(crate) const PDA_DOMAIN: &[u8] = b"qchain-program-pda-v1";

/// Deriva la dirección PDA de `program_id` para `seed` (misma fórmula on/off-chain).
pub fn derive_pda(program_id: &Pubkey, seed: &[u8]) -> Pubkey {
    let mut h = Sha3_256::new();
    h.update(PDA_DOMAIN);
    h.update(program_id.0);
    h.update(seed);
    Pubkey::new(h.finalize().into())
}

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

// ---------------------------------------------------------------------------
// HOST-CALL FUEL METERING (QCH-WASM-001).
//
// Wasmtime's fuel meter charges exactly 1 fuel per *wasm* instruction and
// nothing for the native work a host call does (confirmed in wasmtime-27's
// `fuel_before_op`). So an unmetered host call is FREE native CPU: a contract
// could loop `host_verify_signature` (a ~150µs PQC verify) or `host_log`/
// `host_set_data` with megabyte payloads for near-zero fuel — unbounded work
// per transaction, one call at a time. We fix that by charging fuel from
// inside each host call, proportional to the work it does. Fuel is a committed
// part of the gas model, identical on every node → deterministic / fork-free.
//
// Charged BEFORE the work: if the contract can't afford it, we drain fuel to 0
// (so its very next wasm instruction traps out-of-fuel) and skip the work,
// returning the call's failure sentinel. Against `DEFAULT_FUEL_LIMIT`
// (5,000,000) these caps bound e.g. a signature-verify loop to ~100 verifies
// and a cheap-host-call loop to ~50k calls per transaction.
const FUEL_PER_HOST_CALL: u64 = 100;
/// Per byte moved across the wasm↔host boundary (read or written): bounds a
/// huge memcpy in `host_log`/`host_get_data`/`host_set_data`/verify inputs.
const FUEL_PER_BYTE: u64 = 1;
/// Per byte hashed by `host_use_pda` (SHA3-256 over the seed).
const FUEL_PER_SHA3_BYTE: u64 = 2;
/// A single PQC signature verification is the most expensive host operation by
/// far (~150µs measured); charge for it directly so a verify loop is bounded.
const FUEL_PER_SIGNATURE_VERIFY: u64 = 50_000;

// PER-INPUT CAPS (QCH-WASM-001 part 2): bound the size of any single seed,
// message, key, signature, or log line a contract can hand a host call, so a
// single call can't force an outsized native allocation/copy before the fuel
// charge even applies.
/// A PDA seed is a small tag + a 32-byte key at most in every real pattern.
const MAX_PDA_SEED_LEN: usize = 128;
/// Max message length `host_verify_signature` will hash+verify.
const MAX_VERIFY_MSG_LEN: usize = 64 * 1024;
/// Max public-key length (ML-DSA-65 pk ≈1952B; generous headroom).
const MAX_VERIFY_PUBKEY_LEN: usize = 4096;
/// Max signature length (SLH-DSA-256s sig ≈29.8KB is the largest real one).
const MAX_VERIFY_SIG_LEN: usize = 64 * 1024;
/// Max bytes of a single `host_log` line.
const MAX_LOG_MSG_LEN: usize = 4096;
/// Per-execution budget on total logged bytes — bounds `HostState.log` RAM
/// regardless of how many times the contract calls `host_log` (the unbounded-
/// Vec growth this closes). Once exceeded, further log lines are dropped.
const MAX_LOG_TOTAL_BYTES: usize = 64 * 1024;

/// Charge `amount` fuel for native host-side work. Returns `true` if the
/// contract could afford it (fuel already deducted); `false` if not — in which
/// case fuel is drained to 0 so the contract's next wasm instruction traps
/// out-of-fuel, and the caller must skip the work and return its failure
/// sentinel. Deterministic: reads/writes the committed fuel counter only.
fn charge(caller: &mut Caller<'_, HostState>, amount: u64) -> bool {
    let remaining = caller.get_fuel().unwrap_or(0);
    if amount > remaining {
        let _ = caller.set_fuel(0);
        return false;
    }
    let _ = caller.set_fuel(remaining - amount);
    true
}

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
    /// El `program_id` de la instrucción en ejecución (SDK v0.3): la identidad
    /// bajo la que se derivan/reclaman las PDAs (`host_use_pda`).
    program_id: Pubkey,
    /// Las DIRECCIONES de `accounts` (mismo orden). `accounts` son los `Account`
    /// pero no llevan su propia clave; para comparar contra una PDA derivada se
    /// necesitan las direcciones declaradas en la instrucción.
    keys: Vec<Pubkey>,
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
    /// Running total of logged bytes this execution — enforces
    /// `MAX_LOG_TOTAL_BYTES` so `log` can't grow without bound (QCH-WASM-001).
    log_bytes: usize,
    /// The committed round of the transaction being executed. Threaded in so
    /// `host_verify_signature` can enforce the crypto-agility lifecycle
    /// (activation height / retirement) against real committed height, exactly
    /// like `Ledger::check_registry_status` (QCH-WASM-003).
    current_round: u64,
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

fn write_memory(caller: &mut Caller<'_, HostState>, ptr: i32, bytes: &[u8]) -> bool {
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return false;
    };
    memory.write(caller, ptr as usize, bytes).is_ok()
}

/// Tope del tamaño de `data` que un contrato puede ESCRIBIR en una cuenta con
/// `host_set_data` (el estado estructurado del SDK v0.2). Acota bloat/DoS; los
/// singletons de protocolo (registro/params) no los escribe un contrato — su
/// tamaño lo maneja el ledger, no este límite. 16 KB es holgado para el estado
/// por-cuenta de un contrato (un token/perfil/contador entra en decenas de bytes).
pub(crate) const MAX_CONTRACT_ACCOUNT_DATA: usize = 16 * 1024;

/// Decides whether `scheme_id` may be used by `host_verify_signature` right
/// now. MANDATORY REGISTRY (QCH-WASM-003): a contract MUST declare the on-chain
/// algorithm registry account (`registry_account_idx >= 0`, an index into the
/// instruction's declared accounts). There is NO unconditional genesis
/// fallback — the old `idx < 0 → accept Ed25519/ML-DSA` path bypassed the
/// crypto-agility lifecycle entirely (a not-yet-active scheme verified early, a
/// Retired scheme kept verifying). Fails closed: a bad index, a registry that
/// doesn't decode, or a scheme that isn't listed all reject.
///
/// The status/height rules mirror `Ledger::check_registry_status` exactly, so a
/// contract-side verify never accepts a scheme the base protocol would reject:
///   - `activation_epoch > current_round` → reject (governance scheduled it for
///     a future round; it does not take effect early);
///   - `Retired` → reject (no longer valid for signing at all);
///   - `Active` / `Deprecated` → accept (deprecation only turns away NEW key
///     adoption; existing signatures keep verifying through the grace period).
///
/// Deterministic: a pure function of the committed `current_round` + committed
/// registry account → every validator agrees, no fork.
fn scheme_acceptable(accounts: &[Account], registry_account_idx: i32, scheme_id: u16, current_round: u64) -> bool {
    if registry_account_idx < 0 {
        return false;
    }
    let Some(account) = accounts.get(registry_account_idx as usize) else {
        return false;
    };
    let Ok(registry) = Vec::<RegistryEntry>::try_from_slice(&account.data) else {
        return false;
    };
    let Some(entry) = registry.iter().find(|e| e.id.0 == scheme_id) else {
        return false;
    };
    if current_round < entry.activation_epoch {
        return false;
    }
    !matches!(entry.status, AlgorithmStatus::Retired)
}

/// Bound on the compiled-module cache (QCH-WASM-002). Each entry is a compiled
/// `Arc<Module>`; when full we clear wholesale (a crude bound, not an LRU — the
/// cache is a pure perf optimization with zero consensus effect, so correctness
/// is independent of eviction policy). 256 distinct deployed contracts warm at
/// once is generous for this project's scale.
const MAX_CACHED_MODULES: usize = 256;

pub struct WasmExecutor {
    engine: Engine,
    /// Compiled-module cache keyed by `code_hash` (SHA3-256 of the bytecode)
    /// so a module compiles ONCE instead of on every call (QCH-WASM-002).
    /// Cranelift compilation is expensive; recompiling per call was wasted work
    /// and a DoS vector (a repeatedly-called contract paid full compilation
    /// every time). Only successful compilations are cached, keyed by the exact
    /// bytes, and compilation is deterministic for a fixed wasmtime version, so
    /// the cache never changes execution results — two nodes with different
    /// cache states produce identical output. `Mutex` gives interior
    /// mutability under `&self` (`call` takes `&self`); a single `Ledger`'s
    /// executor is never touched concurrently (`apply_transaction` is `&mut`).
    module_cache: Mutex<HashMap<[u8; 32], Arc<Module>>>,
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
        // DETERMINISMO entre arquitecturas (ARM/x86) — QCH S8, tarea #195. Sin
        // esto, un contrato que use floats podría producir patrones de bits NaN
        // DISTINTOS entre x86 y ARM (los dos que ofrecen Oracle/Contabo) → estado
        // divergente → FORK entre validadores de arquitecturas distintas.
        //   - `cranelift_nan_canonicalization(true)`: unifica todo NaN al NaN
        //     canónico de WebAssembly (0x7ff8… para f64), determinista en todas
        //     las arquitecturas. Los contratos de referencia son de enteros → no
        //     los afecta; solo hace determinista a uno que use floats.
        //   - `wasm_relaxed_simd(false)`: la propuesta "relaxed SIMD" es
        //     NO-determinista por diseño (deja al backend elegir el resultado) →
        //     se desactiva del todo.
        //   - `max_wasm_stack`: límite de pila EXPLÍCITO (no el default del motor)
        //     — una recursión profunda hace trap acotado en vez de depender del
        //     default. 512 KB es holgado para los contratos reales.
        config.cranelift_nan_canonicalization(true);
        config.wasm_relaxed_simd(false);
        config.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config)?;
        Ok(WasmExecutor { engine, module_cache: Mutex::new(HashMap::new()) })
    }

    /// Get the compiled `Module` for `wasm_bytes`, compiling+caching on a miss
    /// (keyed by `code_hash`). See `module_cache`'s doc for the determinism
    /// argument — the cache never changes execution results.
    fn get_or_compile(&self, code_hash: [u8; 32], wasm_bytes: &[u8]) -> anyhow::Result<Arc<Module>> {
        if let Ok(cache) = self.module_cache.lock() {
            if let Some(m) = cache.get(&code_hash) {
                return Ok(m.clone());
            }
        }
        let module = Arc::new(Module::new(&self.engine, wasm_bytes)?);
        if let Ok(mut cache) = self.module_cache.lock() {
            if cache.len() >= MAX_CACHED_MODULES {
                cache.clear();
            }
            cache.insert(code_hash, module.clone());
        }
        Ok(module)
    }

    /// DEPLOY-TIME VALIDATION (QCH-WASM-002). Reject at `DeployProgram` time a
    /// module that doesn't compile or doesn't export its declared
    /// `entry_point`, so a bad contract never persists (and every later call
    /// isn't forced to re-fail compilation). Deterministic: the same wasmtime
    /// on every node accepts/rejects the same bytes, adding no fork surface
    /// beyond what execution already requires. Warms the module cache as a side
    /// effect, so the first real call is already compiled.
    pub fn validate_deploy(&self, wasm_bytes: &[u8], entry_point: &str) -> anyhow::Result<()> {
        let code_hash: [u8; 32] = Sha3_256::digest(wasm_bytes).into();
        let module = self
            .get_or_compile(code_hash, wasm_bytes)
            .map_err(|e| anyhow::anyhow!("contract bytecode does not compile: {e}"))?;
        match module.get_export(entry_point) {
            Some(ExternType::Func(_)) => Ok(()),
            Some(_) => Err(anyhow::anyhow!("export '{entry_point}' exists but is not a function")),
            None => Err(anyhow::anyhow!("contract has no exported function named '{entry_point}'")),
        }
    }

    fn build_linker(&self) -> anyhow::Result<Linker<HostState>> {
        let mut linker = Linker::new(&self.engine);

        linker.func_wrap("env", "host_get_balance", |mut caller: Caller<'_, HostState>, idx: i32| -> i64 {
            if !charge(&mut caller, FUEL_PER_HOST_CALL) {
                return -1;
            }
            caller
                .data()
                .accounts
                .get(idx as usize)
                .map(|a| a.balance as i64)
                .unwrap_or(-1)
        })?;

        linker.func_wrap("env", "host_set_balance", |mut caller: Caller<'_, HostState>, idx: i32, new_balance: i64| {
            if !charge(&mut caller, FUEL_PER_HOST_CALL) {
                return;
            }
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
        linker.func_wrap("env", "host_is_signer", |mut caller: Caller<'_, HostState>, idx: i32| -> i32 {
            if !charge(&mut caller, FUEL_PER_HOST_CALL) {
                return 0;
            }
            i32::from(caller.data().is_signer.get(idx as usize).copied().unwrap_or(false))
        })?;

        linker.func_wrap("env", "host_log", |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
            // Cap a single line, and charge for the bytes copied (QCH-WASM-001).
            let len = len.max(0).min(MAX_LOG_MSG_LEN as i32);
            if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(FUEL_PER_BYTE.saturating_mul(len as u64))) {
                return;
            }
            if let Some(bytes) = read_memory(&mut caller, ptr, len) {
                // Per-execution log-byte budget bounds `HostState.log` RAM no
                // matter how many times the contract logs (QCH-WASM-001).
                let used = caller.data().log_bytes;
                if used.saturating_add(bytes.len()) > MAX_LOG_TOTAL_BYTES {
                    return;
                }
                let msg = String::from_utf8_lossy(&bytes).to_string();
                let state = caller.data_mut();
                state.log_bytes = used.saturating_add(bytes.len());
                state.log.push(msg);
            }
        })?;

        // SDK v0.2 — estado estructurado on-chain. Un contrato lee/escribe los
        // BYTES de `data` de una cuenta declarada, por índice (misma convención
        // que balance). La AUTORIZACIÓN de escritura la refuerza el LEDGER (ver
        // `run_wasm_instruction`): la `data` de una cuenta solo cambia si el
        // llamador está autorizado sobre ella (es el firmante, o el programa la
        // posee) — igual que el débito de saldo. Aquí solo se mueven bytes; el
        // borde de seguridad valida el cambio antes de comprometerlo.
        linker.func_wrap("env", "host_data_len", |mut caller: Caller<'_, HostState>, idx: i32| -> i32 {
            if !charge(&mut caller, FUEL_PER_HOST_CALL) {
                return -1;
            }
            caller.data().accounts.get(idx as usize).map(|a| a.data.len() as i32).unwrap_or(-1)
        })?;
        linker.func_wrap(
            "env",
            "host_get_data",
            |mut caller: Caller<'_, HostState>, idx: i32, ptr: i32, max_len: i32| -> i32 {
                // Clonar evita el conflicto de préstamo con `write_memory(&mut caller)`.
                let Some(data) = caller.data().accounts.get(idx as usize).map(|a| a.data.clone()) else {
                    return -1;
                };
                let n = core::cmp::min(data.len(), max_len.max(0) as usize);
                // Charge for the bytes copied out (QCH-WASM-001).
                if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(FUEL_PER_BYTE.saturating_mul(n as u64))) {
                    return -1;
                }
                if write_memory(&mut caller, ptr, &data[..n]) {
                    n as i32
                } else {
                    -1
                }
            },
        )?;
        linker.func_wrap(
            "env",
            "host_set_data",
            |mut caller: Caller<'_, HostState>, idx: i32, ptr: i32, len: i32| -> i32 {
                if len < 0 || len as usize > MAX_CONTRACT_ACCOUNT_DATA {
                    return -1;
                }
                // Charge for the bytes copied in (QCH-WASM-001).
                if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(FUEL_PER_BYTE.saturating_mul(len as u64))) {
                    return -1;
                }
                let Some(bytes) = read_memory(&mut caller, ptr, len) else {
                    return -1;
                };
                match caller.data_mut().accounts.get_mut(idx as usize) {
                    Some(acc) => {
                        acc.data = bytes;
                        0
                    }
                    None => -1,
                }
            },
        )?;

        // SDK v0.3 — cuentas de estado PROPIAS DEL PROGRAMA (PDAs). Verifica que
        // `accounts[idx]` sea genuinamente la PDA de ESTE programa para `seed`
        // (`address == derive_pda(program_id, seed)`), y si es una cuenta FRESCA
        // (system-owned, saldo 0, data vacía) la RECLAMA poniendo su owner =
        // program_id. Devuelve 0 si la cuenta ya es utilizable por el programa
        // (recién reclamada o ya suya), -1 si no es la PDA o está ocupada por
        // otro. Como `program_id` entra en la derivación, un programa jamás
        // puede reclamar la PDA de otro (sin front-running). El borde del ledger
        // vuelve a autorizar el cambio de owner (solo fresh system→program_id).
        linker.func_wrap(
            "env",
            "host_use_pda",
            |mut caller: Caller<'_, HostState>, idx: i32, seed_ptr: i32, seed_len: i32| -> i32 {
                // Cap the seed and charge for hashing it (SHA3 over the seed).
                if seed_len < 0 || seed_len as usize > MAX_PDA_SEED_LEN {
                    return -1;
                }
                if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(FUEL_PER_SHA3_BYTE.saturating_mul(seed_len as u64))) {
                    return -1;
                }
                let Some(seed) = read_memory(&mut caller, seed_ptr, seed_len) else {
                    return -1;
                };
                let program_id = caller.data().program_id;
                let expected = derive_pda(&program_id, &seed);
                let idx = idx as usize;
                let Some(key) = caller.data().keys.get(idx).copied() else {
                    return -1;
                };
                if key != expected {
                    return -1; // la cuenta declarada NO es la PDA de este programa
                }
                let Some(acc) = caller.data_mut().accounts.get_mut(idx) else {
                    return -1;
                };
                if acc.owner == program_id {
                    return 0; // ya es nuestra, lista para usar
                }
                if acc.owner == Pubkey::system_program_id() && acc.balance == 0 && acc.data.is_empty() {
                    acc.owner = program_id; // reclamar la cuenta fresca como PDA del programa
                    return 0;
                }
                -1 // existe y no es nuestra (ocupada) — no reclamable
            },
        )?;

        // SDK v0.4 — LECTURA de la DIRECCIÓN (pubkey) de una cuenta declarada,
        // por índice. Read-only: copia los 32 bytes de la dirección de
        // `accounts[idx]` en la memoria del contrato y devuelve cuántos copió
        // (-1 si `idx` está fuera de rango). Las direcciones son PÚBLICAS, así
        // que exponerlas no autoriza nada ni cambia estado — solo habilita el
        // control de acceso por DUEÑO (un contrato de tesorería guarda la
        // dirección de su admin y, al retirar, exige que el firmante coincida
        // con ella) y patrones tipo whitelist / PDA-por-usuario. Puramente
        // aditivo: una tx que no lo llama es byte-idéntica.
        linker.func_wrap(
            "env",
            "host_get_pubkey",
            |mut caller: Caller<'_, HostState>, idx: i32, ptr: i32, max_len: i32| -> i32 {
                let Some(key) = caller.data().keys.get(idx as usize).map(|k| k.0) else {
                    return -1;
                };
                let n = core::cmp::min(key.len(), max_len.max(0) as usize);
                // Charge for the bytes copied out (QCH-WASM-001).
                if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(FUEL_PER_BYTE.saturating_mul(n as u64))) {
                    return -1;
                }
                if write_memory(&mut caller, ptr, &key[..n]) {
                    n as i32
                } else {
                    -1
                }
            },
        )?;

        // Exposes the crypto-agility layer to contracts (ARCHITECTURE.md
        // §4): a contract can verify a signature against any registered
        // scheme individually, e.g. for custom multisig authorization
        // logic, without reimplementing PQC math in WASM - it always calls
        // straight into the same native, liboqs-backed verification the
        // base protocol uses. `registry_account_idx` is opportunistic: pass
        // the index (into this instruction's declared accounts, same
        // convention as `host_get_balance`) of the on-chain algorithm
        // registry account. The registry is now MANDATORY (QCH-WASM-003): a
        // contract MUST declare it (`registry_account_idx >= 0`); there is no
        // unconditional genesis fallback. The scheme must be registered, past
        // its `activation_epoch` for the current committed round, and not
        // Retired — the same crypto-agility lifecycle the base protocol
        // enforces (see `scheme_acceptable`). Passing -1 rejects everything.
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
                // Per-input caps (QCH-WASM-001): bound a single verify's key/
                // message/signature so it can't force an outsized copy.
                if pubkey_len < 0 || pubkey_len as usize > MAX_VERIFY_PUBKEY_LEN {
                    return 0;
                }
                if msg_len < 0 || msg_len as usize > MAX_VERIFY_MSG_LEN {
                    return 0;
                }
                if sig_len < 0 || sig_len as usize > MAX_VERIFY_SIG_LEN {
                    return 0;
                }
                // Charge for the bytes copied AND for the PQC verify itself (the
                // most expensive host op, ~150µs) BEFORE doing any of it, so a
                // verify loop is fuel-bounded to ~100 verifies (QCH-WASM-001).
                let copy_fuel = FUEL_PER_BYTE.saturating_mul((pubkey_len + msg_len + sig_len) as u64);
                if !charge(&mut caller, FUEL_PER_HOST_CALL.saturating_add(copy_fuel).saturating_add(FUEL_PER_SIGNATURE_VERIFY)) {
                    return 0;
                }
                let Some(pubkey) = read_memory(&mut caller, pubkey_ptr, pubkey_len) else {
                    return 0;
                };
                let Some(msg) = read_memory(&mut caller, msg_ptr, msg_len) else {
                    return 0;
                };
                let Some(sig) = read_memory(&mut caller, sig_ptr, sig_len) else {
                    return 0;
                };
                let current_round = caller.data().current_round;
                if !scheme_acceptable(&caller.data().accounts, registry_account_idx, scheme_id as u16, current_round) {
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
    /// `host_is_signer` reports back to the contract. `current_round` is the
    /// committed round, used by `host_verify_signature` to enforce the
    /// crypto-agility lifecycle. The compiled module is cached by code_hash so
    /// a repeatedly-called contract compiles once (QCH-WASM-002).
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        wasm_bytes: &[u8],
        entry_point: &str,
        params: &[Val],
        program_id: Pubkey,
        keys: Vec<Pubkey>,
        accounts: Vec<Account>,
        is_signer: Vec<bool>,
        current_round: u64,
        fuel_limit: u64,
    ) -> anyhow::Result<WasmCallResult> {
        let code_hash: [u8; 32] = Sha3_256::digest(wasm_bytes).into();
        let module = self.get_or_compile(code_hash, wasm_bytes)?;
        let linker = self.build_linker()?;

        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let host_state = HostState { program_id, keys, accounts, is_signer, log: Vec::new(), log_bytes: 0, current_round, limits };
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
                Pubkey::new([9u8; 32]),
                vec![Pubkey::new([1u8; 32]), Pubkey::new([2u8; 32])],
                accounts,
                vec![true, false],
                0,
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
            .call(&wasm_bytes, "transfer", &[Val::I32(0), Val::I32(1), Val::I64(300)], Pubkey::new([9u8; 32]), vec![Pubkey::new([1u8; 32]), Pubkey::new([2u8; 32])], accounts, vec![true, false], 0, 1)
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

        let result = executor.call(&wasm_bytes, "burn_then_trap", &[], Pubkey::system_program_id(), vec![], vec![], vec![], 0, 1_000_000).unwrap();
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

        let result = executor.call(&wasm_bytes, "bomb", &[], Pubkey::system_program_id(), vec![], vec![], vec![], 0, 5_000_000).unwrap();
        assert!(result.trap.is_some(), "growing memory past MAX_CONTRACT_MEMORY_BYTES must trap, not succeed");
        assert!(result.fuel_consumed < 100, "the trap must fire on the grow itself, not after real work - got {} fuel", result.fuel_consumed);
    }

    /// QCH S8 / tarea #195: la canonicalización de NaN está ACTIVA — un NaN de
    /// float se unifica al patrón canónico de WebAssembly, igual en toda
    /// arquitectura (ARM/x86), evitando un fork por bits de NaN divergentes.
    #[test]
    fn nan_is_canonicalized_for_cross_arch_determinism() {
        // `$x / $x` con `$x = 0.0` produce NaN en TIEMPO DE EJECUCIÓN (param, no
        // constante plegable), así se ejercita la canonicalización del backend.
        let wat = r#"(module (func (export "nan") (param $x f64) (result i64)
            (i64.reinterpret_f64 (f64.div (local.get $x) (local.get $x)))))"#;
        let wasm_bytes = wat::parse_str(wat).unwrap();
        let executor = WasmExecutor::new().unwrap();
        let module = wasmtime::Module::new(&executor.engine, &wasm_bytes).unwrap();
        let linker = executor.build_linker().unwrap();
        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let mut store = wasmtime::Store::new(
            &executor.engine,
            HostState { program_id: Pubkey::system_program_id(), keys: vec![], accounts: vec![], is_signer: vec![], log: vec![], log_bytes: 0, current_round: 0, limits },
        );
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let func = instance.get_func(&mut store, "nan").unwrap();
        let mut results = [wasmtime::Val::I64(0)];
        func.call(&mut store, &[wasmtime::Val::F64(0)], &mut results).unwrap();
        let bits = results[0].unwrap_i64() as u64;
        assert_eq!(
            bits, 0x7ff8_0000_0000_0000,
            "el NaN debe ser el canónico de WebAssembly (determinismo ARM/x86) - fue {bits:#018x}"
        );
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
        let mut store = wasmtime::Store::new(&executor.engine, HostState { program_id: Pubkey::system_program_id(), keys: vec![], accounts, is_signer: vec![true, false], log: vec![], log_bytes: 0, current_round: 0, limits });
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

    // SDK v0.4 — reads the 32-byte address of a declared account into memory,
    // returning bytes written (-1 out of range). Enables owner-based access
    // control in contracts (compare the signer's pubkey to a stored admin).
    const GET_PUBKEY_WAT: &str = r#"
        (module
            (import "env" "host_get_pubkey" (func $get_pubkey (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "read") (param $idx i32) (param $ptr i32) (param $max i32) (result i32)
                (call $get_pubkey (local.get $idx) (local.get $ptr) (local.get $max))
            )
        )
    "#;

    #[test]
    fn host_get_pubkey_reads_the_account_address_and_rejects_out_of_range() {
        let wasm_bytes = wat::parse_str(GET_PUBKEY_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();
        let module = wasmtime::Module::new(&executor.engine, &wasm_bytes).unwrap();
        let linker = executor.build_linker().unwrap();
        let a0 = Pubkey::new([7u8; 32]);
        let a1 = Pubkey::new([42u8; 32]);
        let accounts = vec![wallet(0), wallet(0)];
        let limits = StoreLimitsBuilder::new().memory_size(MAX_CONTRACT_MEMORY_BYTES).trap_on_grow_failure(true).build();
        let mut store = wasmtime::Store::new(
            &executor.engine,
            HostState { program_id: Pubkey::system_program_id(), keys: vec![a0, a1], accounts, is_signer: vec![true, false], log: vec![], log_bytes: 0, current_round: 0, limits },
        );
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        let func = instance.get_func(&mut store, "read").unwrap();

        let read = |store: &mut wasmtime::Store<HostState>, idx: i32| -> i32 {
            let mut results = vec![Val::I32(0)];
            func.call(&mut *store, &[Val::I32(idx), Val::I32(0), Val::I32(32)], &mut results).unwrap();
            results[0].i32().unwrap()
        };

        assert_eq!(read(&mut store, 0), 32, "the address is exactly 32 bytes");
        let mut buf = [0u8; 32];
        memory.read(&store, 0, &mut buf).unwrap();
        assert_eq!(buf, [7u8; 32], "reads the real address of accounts[0]");
        assert_eq!(read(&mut store, 1), 32);
        memory.read(&store, 0, &mut buf).unwrap();
        assert_eq!(buf, [42u8; 32], "reads the real address of accounts[1]");
        assert_eq!(read(&mut store, 99), -1, "an out-of-range index fails closed, not panic/trap");
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
        let mut store = wasmtime::Store::new(&executor.engine, HostState { program_id: Pubkey::system_program_id(), keys: vec![], accounts, is_signer: vec![], log: vec![], log_bytes: 0, current_round: 0, limits });
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

    /// Build a declared account holding the genesis registry (Ed25519 +
    /// ML-DSA-65, both Active from round 0) — the account a contract must now
    /// declare to verify anything (mandatory registry, QCH-WASM-003).
    fn genesis_registry_account() -> Account {
        Account { data: borsh::to_vec(&qchain_crypto::registry::genesis_registry()).unwrap(), ..wallet(0) }
    }

    #[test]
    fn contract_can_verify_a_signature_via_the_crypto_agility_syscall() {
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::Keypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();

        // Declares the genesis registry at idx 0 (mandatory now). Ed25519 is
        // Active from genesis there, so a real signature verifies.
        let result =
            call_verify_syscall(&executor, vec![genesis_registry_account()], ALGORITHM_ED25519.0, &bundle.components[0].bytes, msg, &sig.components[0].bytes, 0);
        assert_eq!(result, 1, "contract-side verification of a real signature must succeed");
    }

    #[test]
    fn syscall_rejects_any_scheme_without_a_declared_registry_account() {
        // MANDATORY REGISTRY (QCH-WASM-003): with no registry account (-1),
        // EVERY scheme is rejected now — even a genesis-Active one like Ed25519.
        // There is no unconditional fallback that bypasses the lifecycle.
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::Keypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();

        let result = call_verify_syscall(&executor, vec![], ALGORITHM_ED25519.0, &bundle.components[0].bytes, msg, &sig.components[0].bytes, -1);
        assert_eq!(result, 0, "a genuinely valid Ed25519 signature must still be rejected with no declared registry");
    }

    #[test]
    fn syscall_rejects_slh_dsa_without_a_declared_registry_account() {
        // No registry account declared (-1) rejects everything now.
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::slh_dsa::SlhDsaKeypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();

        let result = call_verify_syscall(&executor, vec![], qchain_crypto::ALGORITHM_SLH_DSA.0, kp.public_key_bytes(), msg, &sig, -1);
        assert_eq!(result, 0, "SLH-DSA must not verify without an opted-in registry lookup");
    }

    #[test]
    fn syscall_rejects_a_scheme_not_yet_active_at_the_current_round() {
        // Crypto-agility activation height (QCH-WASM-003): a scheme scheduled to
        // activate at a FUTURE round must not verify before then, even with a
        // real signature and a declared registry.
        let executor = WasmExecutor::new().unwrap();
        let kp = qchain_crypto::slh_dsa::SlhDsaKeypair::generate().unwrap();
        let msg = b"contract-checked message";
        let sig = kp.sign(msg).unwrap();

        // SLH-DSA registered to activate only at round 100.
        let registry = vec![qchain_crypto::slh_dsa_registry_entry(100)];
        let registry_account = Account { data: borsh::to_vec(&registry).unwrap(), ..wallet(0) };

        // current_round defaults to 0 in call_verify_syscall's HostState → below
        // the activation height → reject.
        let result = call_verify_syscall(&executor, vec![registry_account], qchain_crypto::ALGORITHM_SLH_DSA.0, kp.public_key_bytes(), msg, &sig, 0);
        assert_eq!(result, 0, "a scheme not yet active at the current round must be rejected");
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

    /// QCH-WASM-001: host calls are fuel-metered. A contract that loops a host
    /// call far more times than the budget allows (FUEL_PER_HOST_CALL each) must
    /// trap out-of-fuel — before this fix, host calls cost 0 fuel and the loop
    /// would complete, i.e. unbounded free native CPU per transaction.
    #[test]
    fn a_host_call_loop_is_fuel_metered_and_traps_when_it_overspends() {
        const HOST_CALL_LOOP_WAT: &str = r#"
            (module
                (import "env" "host_get_balance" (func $bal (param i32) (result i64)))
                (func (export "spin") (param $n i64)
                    (local $i i64)
                    (block $done
                        (loop $l
                            (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                            (drop (call $bal (i32.const 0)))
                            (local.set $i (i64.add (local.get $i) (i64.const 1)))
                            (br $l)
                        )
                    )
                )
            )
        "#;
        let wasm_bytes = wat::parse_str(HOST_CALL_LOOP_WAT).unwrap();
        let executor = WasmExecutor::new().unwrap();
        // 200k host calls * 100 fuel = 20M fuel, far over the 5M budget → trap.
        let result = executor
            .call(&wasm_bytes, "spin", &[Val::I64(200_000)], Pubkey::system_program_id(), vec![], vec![], vec![], 0, 5_000_000)
            .unwrap();
        assert!(result.trap.is_some(), "an unbounded host-call loop must trap out-of-fuel, not run free");
        // A modest loop that fits the budget still completes (metering doesn't
        // break a legitimate contract that uses a few host calls).
        let ok = executor
            .call(&wasm_bytes, "spin", &[Val::I64(10)], Pubkey::system_program_id(), vec![], vec![], vec![], 0, 5_000_000)
            .unwrap();
        assert!(ok.trap.is_none(), "a small host-call loop must still complete within budget");
    }

    /// QCH-WASM-002: a contract is validated at deploy — it must compile and
    /// export its declared entry point, or it's rejected before it can persist.
    #[test]
    fn validate_deploy_accepts_a_real_module_and_rejects_bad_ones() {
        let executor = WasmExecutor::new().unwrap();
        let good = wat::parse_str(TRANSFER_WAT).unwrap();
        assert!(executor.validate_deploy(&good, "transfer").is_ok(), "a real module exporting the entry point validates");
        assert!(executor.validate_deploy(&good, "does_not_exist").is_err(), "a missing entry point is rejected at deploy");
        assert!(executor.validate_deploy(b"\x00 not wasm", "transfer").is_err(), "non-wasm bytes are rejected at deploy");
    }
}
