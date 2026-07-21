//! # qchain-sdk
//!
//! SDK de alto nivel para escribir **contratos inteligentes de Qchain en Rust**,
//! en vez de WebAssembly a mano (WAT). Compila a `wasm32-unknown-unknown` y
//! produce un `.wasm` listo para `qchain deploy-program` / el panel "Contratos"
//! de QScan.
//!
//! ## Modelo de ejecución (lo que hay que saber)
//!
//! Un contrato es una función WebAssembly exportada. El ledger la invoca con:
//! - **cuentas por índice**: la instrucción declara una lista de cuentas
//!   (`accounts[0]`, `accounts[1]`, …). El contrato lee/escribe su saldo por
//!   índice con [`balance`] / [`set_balance`]; **`accounts[0]` es, por
//!   convención, el ORIGEN y tiene que ser el firmante** de la transacción.
//! - **argumentos `i64`**: los args de la instrucción llegan como enteros `i64`.
//!   El punto de entrada tiene **aridad fija**: con [`entrypoint!`] son **4**
//!   (`sel, a, b, c`), así que quien llama pasa SIEMPRE 4 args (rellenando con 0).
//!
//! ## Seguridad reforzada por el ledger (no por el contrato)
//!
//! Aunque un contrato malicioso no chequee nada, el **ledger** garantiza en el
//! borde, para TODO bytecode: (1) una cuenta solo se DEBITA si el llamador está
//! autorizado (es el firmante, o el programa la posee); (2) el total de saldo
//! nunca crece (acuñar es imposible). El SDK agrega los chequeos "buenos
//! vecinos" ([`require_signer`], montos no negativos, saldo suficiente) para que
//! el contrato falle temprano y claro, pero la garantía dura vive en el ledger.
//!
//! ## Ejemplo mínimo
//!
//! ```ignore
//! #![no_std]
//! use qchain_sdk::{entrypoint, transfer, balance, abort, log};
//!
//! // accounts[0]=origen(firma), accounts[1]=destino
//! fn run([sel, amount, _b, _c]: [i64; 4]) {
//!     match sel {
//!         1 => { log("transfer"); transfer(0, 1, amount); }  // amount: acct0 -> acct1
//!         4 => { log("sweep");    transfer(0, 1, balance(0)); } // todo -> acct1
//!         _ => abort(),
//!     }
//! }
//! entrypoint!(run);
//! ```
//!
//! Compilá con `deploy/build-contract.sh <carpeta-del-contrato>` y desplegá el
//! `.wasm` resultante. Ver `docs/SMART-CONTRACTS.md`.
#![no_std]

// ============================================================================
// Syscalls crudos del host. Solo existen dentro del entorno wasm del nodo; en
// una build de host (para `cargo check`/tests) usamos stubs inertes.
// ============================================================================
mod sys {
    #[cfg(target_arch = "wasm32")]
    #[link(wasm_import_module = "env")]
    extern "C" {
        pub fn host_get_balance(idx: i32) -> i64;
        pub fn host_set_balance(idx: i32, val: i64);
        pub fn host_is_signer(idx: i32) -> i32;
        pub fn host_log(ptr: i32, len: i32);
    }

    // Stubs para compilar en el host (nunca se ejecutan en un contrato real).
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_get_balance(_idx: i32) -> i64 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_set_balance(_idx: i32, _val: i64) {}
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_is_signer(_idx: i32) -> i32 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_log(_ptr: i32, _len: i32) {}
}

/// Aborta la ejecución del contrato (trap). Todo lo que hizo la transacción se
/// descarta; el pagador igual paga el fee de bytes/gas de su intento (no es un
/// reintento gratis para un atacante).
#[inline(never)]
pub fn abort() -> ! {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        panic!("contract abort")
    }
}

/// Saldo (en unidades; 1 QCH = 1_000_000_000) de la cuenta en `idx`. Devuelve
/// `-1` si `idx` está fuera del rango de cuentas declaradas por la instrucción.
#[inline]
pub fn balance(idx: u32) -> i64 {
    unsafe { sys::host_get_balance(idx as i32) }
}

/// Escribe el saldo de la cuenta en `idx`. Preferí [`credit`]/[`debit`]/
/// [`transfer`], que validan; esto es el primitivo crudo.
#[inline]
pub fn set_balance(idx: u32, value: i64) {
    unsafe { sys::host_set_balance(idx as i32, value) }
}

/// `true` si la cuenta en `idx` es el firmante (pagador autenticado) de esta
/// transacción — el único concepto de "firmante" del modelo de un solo firmante.
#[inline]
pub fn is_signer(idx: u32) -> bool {
    unsafe { sys::host_is_signer(idx as i32) != 0 }
}

/// Emite un evento de log (texto). Útil para depurar / trazar; no afecta el
/// estado. El host lo captura por transacción.
#[inline]
pub fn log(msg: &str) {
    unsafe { sys::host_log(msg.as_ptr() as i32, msg.len() as i32) }
}

/// Aborta si la condición es falsa. Con `require!(cond, "motivo")` además loguea
/// el motivo antes de abortar.
#[macro_export]
macro_rules! require {
    ($cond:expr $(,)?) => {
        if !($cond) {
            $crate::abort()
        }
    };
    ($cond:expr, $msg:expr $(,)?) => {
        if !($cond) {
            $crate::log($msg);
            $crate::abort()
        }
    };
}

/// Aborta si la cuenta en `idx` no firmó esta transacción. Usalo antes de mover
/// fondos de una cuenta "propia del usuario".
#[inline]
pub fn require_signer(idx: u32) {
    if !is_signer(idx) {
        log("qchain-sdk: se requiere firma");
        abort();
    }
}

/// Acredita `amount` (>= 0) a la cuenta `idx`, con chequeo de overflow.
#[inline]
pub fn credit(idx: u32, amount: i64) {
    if amount < 0 {
        abort();
    }
    let b = balance(idx).max(0); // una cuenta inexistente se trata como 0
    match b.checked_add(amount) {
        Some(v) => set_balance(idx, v),
        None => abort(),
    }
}

/// Debita `amount` (>= 0) de la cuenta `idx`; aborta si no alcanza el saldo.
#[inline]
pub fn debit(idx: u32, amount: i64) {
    if amount < 0 {
        abort();
    }
    let b = balance(idx);
    if b < amount {
        abort();
    }
    set_balance(idx, b - amount);
}

/// Transferencia segura: mueve `amount` de `from` a `to`. Exige que `from` haya
/// FIRMADO (además del refuerzo del ledger), que `amount >= 0` y que haya saldo.
/// Conserva el valor total.
#[inline]
pub fn transfer(from: u32, to: u32, amount: i64) {
    require_signer(from);
    debit(from, amount);
    credit(to, amount);
}

/// Define el punto de entrada del contrato: exporta la función `run` con aridad
/// fija de **4** enteros `i64` (`sel, a, b, c`) y la delega a `$handler`, que
/// recibe `[i64; 4]`. Quien llama pasa SIEMPRE 4 args (rellená con 0 los que no
/// uses) — un `.wasm` con aridad `N` rechaza una llamada con `!= N` args.
///
/// ```ignore
/// fn run([sel, x, _y, _z]: [i64; 4]) { /* ... */ }
/// qchain_sdk::entrypoint!(run);
/// ```
#[macro_export]
macro_rules! entrypoint {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn run(a0: i64, a1: i64, a2: i64, a3: i64) {
            $handler([a0, a1, a2, a3]);
        }
    };
}

// Manejador de panics para el contrato final (no_std). Solo en wasm; en el host
// lo provee `std`. Un panic (overflow, unwrap, require) se convierte en un trap,
// que el ledger trata como instrucción fallida (se descartan los cambios).
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
