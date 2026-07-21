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
        // SDK v0.2 — estado estructurado en account.data
        pub fn host_data_len(idx: i32) -> i32;
        pub fn host_get_data(idx: i32, ptr: i32, max_len: i32) -> i32;
        pub fn host_set_data(idx: i32, ptr: i32, len: i32) -> i32;
        // SDK v0.3 — cuentas de estado propias del programa (PDAs)
        pub fn host_use_pda(idx: i32, seed_ptr: i32, seed_len: i32) -> i32;
        // SDK v0.4 — lectura de la dirección (pubkey) de una cuenta declarada
        pub fn host_get_pubkey(idx: i32, ptr: i32, max_len: i32) -> i32;
        // SDK v0.6 — dirección que DESPLEGÓ este contrato (anti init-takeover)
        pub fn host_get_deployer(ptr: i32, max_len: i32) -> i32;
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
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_data_len(_idx: i32) -> i32 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_get_data(_idx: i32, _ptr: i32, _max_len: i32) -> i32 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_set_data(_idx: i32, _ptr: i32, _len: i32) -> i32 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_use_pda(_idx: i32, _seed_ptr: i32, _seed_len: i32) -> i32 {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_get_pubkey(_idx: i32, _ptr: i32, _max_len: i32) -> i32 {
        -1
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub unsafe fn host_get_deployer(_ptr: i32, _max_len: i32) -> i32 {
        -1
    }
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

// ============================================================================
// SDK v0.2 — ESTADO ESTRUCTURADO on-chain (bytes de `account.data`).
//
// Un contrato puede leer/escribir los bytes de `data` de una cuenta declarada.
// La ESCRITURA la autoriza el LEDGER igual que un débito: solo se puede escribir
// la `data` de una cuenta si el llamador está autorizado sobre ella — es el
// FIRMANTE (`accounts[0]`), o el programa la posee. El patrón típico v0.2 es
// guardar el estado del usuario en su PROPIA cuenta (`accounts[0]`, el firmante).
// ============================================================================

/// Largo actual (en bytes) de `accounts[idx].data`.
#[inline]
pub fn data_len(idx: u32) -> usize {
    let n = unsafe { sys::host_data_len(idx as i32) };
    if n < 0 {
        0
    } else {
        n as usize
    }
}

/// Copia hasta `out.len()` bytes de `accounts[idx].data` en `out`. Devuelve
/// cuántos bytes se copiaron (0 si la cuenta no existe o no tiene data).
#[inline]
pub fn get_data(idx: u32, out: &mut [u8]) -> usize {
    let n = unsafe { sys::host_get_data(idx as i32, out.as_mut_ptr() as i32, out.len() as i32) };
    if n < 0 {
        0
    } else {
        n as usize
    }
}

/// Escribe `bytes` como la nueva `data` de `accounts[idx]`. Aborta si el ledger
/// rechaza (no autorizado / supera el tope de 16 KB). Persiste on-chain.
#[inline]
pub fn set_data(idx: u32, bytes: &[u8]) {
    let r = unsafe { sys::host_set_data(idx as i32, bytes.as_ptr() as i32, bytes.len() as i32) };
    if r != 0 {
        log("qchain-sdk: set_data rechazado");
        abort();
    }
}

// --- helpers de (des)serialización manual de enteros LE en un buffer ---
// Sin `serde`/alloc: un contrato arma su layout con offsets fijos. Ej:
//   [count: i64 @0][updates: u64 @8]  → 16 bytes.

/// Lee un `u64` little-endian en `buf[off..off+8]`; `0` si no entra.
#[inline]
pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    match buf.get(off..off + 8) {
        Some(s) => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        None => 0,
    }
}

/// Lee un `i64` little-endian en `buf[off..off+8]`; `0` si no entra.
#[inline]
pub fn read_i64(buf: &[u8], off: usize) -> i64 {
    read_u64(buf, off) as i64
}

/// Lee un `u32` little-endian en `buf[off..off+4]`; `0` si no entra.
#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    match buf.get(off..off + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

/// Escribe un `u64` little-endian en `buf[off..off+8]`; aborta si no entra.
#[inline]
pub fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    match buf.get_mut(off..off + 8) {
        Some(s) => s.copy_from_slice(&v.to_le_bytes()),
        None => abort(),
    }
}

/// Escribe un `i64` little-endian en `buf[off..off+8]`; aborta si no entra.
#[inline]
pub fn write_i64(buf: &mut [u8], off: usize, v: i64) {
    write_u64(buf, off, v as u64)
}

/// Escribe un `u32` little-endian en `buf[off..off+4]`; aborta si no entra.
#[inline]
pub fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    match buf.get_mut(off..off + 4) {
        Some(s) => s.copy_from_slice(&v.to_le_bytes()),
        None => abort(),
    }
}

// ============================================================================
// SDK v0.3 — CUENTAS DE ESTADO PROPIAS DEL PROGRAMA (PDAs).
//
// Para estado COMPARTIDO que ningún usuario firma (un contador global, un
// supply, un libro de órdenes), el contrato usa una cuenta cuya dirección es
// una **PDA** derivada de `program_id + seed`. El cliente incluye esa dirección
// en `accounts`; el contrato la "usa" con [`use_pda`], que la reclama (la pone
// `owner = program_id`) la primera vez y confirma que es suya. A partir de ahí
// el contrato lee/escribe su `data` con [`get_data`]/[`set_data`] (autorizado
// porque el programa la posee — nadie firma como la PDA).
//
// La dirección off-chain se deriva con la MISMA fórmula
// `SHA3-256("qchain-program-pda-v1" ‖ program_id ‖ seed)` (en el nodo:
// `qchain_execution::wasm::derive_pda`; para el cliente, `qchain_wasm::program_pda`).
// Como `program_id` entra en el hash, un programa NUNCA puede reclamar la PDA de
// otro → sin front-running.
// ============================================================================

/// Reclama/usa la cuenta `accounts[idx]` como PDA de ESTE programa para `seed`.
/// Devuelve `true` si la cuenta es genuinamente la PDA del programa (recién
/// reclamada o ya suya) y quedó lista para leer/escribir su `data`; `false` si
/// la cuenta declarada no es esa PDA o está ocupada por otro. Patrón típico:
///
/// ```ignore
/// require!(use_pda(1, b"global"));   // accounts[1] es nuestra PDA "global"
/// let mut buf = [0u8; 8];
/// get_data(1, &mut buf);
/// // ... mutar ...
/// set_data(1, &buf);
/// ```
#[inline]
pub fn use_pda(idx: u32, seed: &[u8]) -> bool {
    unsafe { sys::host_use_pda(idx as i32, seed.as_ptr() as i32, seed.len() as i32) == 0 }
}

// ============================================================================
// SDK v0.4 — TESORERÍAS DE PROGRAMA (fondos en una PDA) + control de acceso por
// DUEÑO. Cierra el límite honesto de v0.3: mover fondos DE una cuenta propia del
// programa (una PDA de tesorería) HACIA un usuario.
//
// Por qué hace falta un helper nuevo: [`transfer`] exige que el ORIGEN haya
// FIRMADO — y NADIE firma como una PDA (no tiene clave privada). Así que
// `transfer` sirve para DEPOSITAR en la tesorería (un usuario firma y manda),
// pero NO para PAGAR desde ella. El ledger SÍ autoriza debitar una cuenta que el
// programa posee (`owner == program_id`, el mismo borde de v2.0.4), así que un
// contrato puede pagar desde su PDA — [`pda_transfer`] es ese primitivo, sin el
// chequeo de firma sobre el origen. La garantía dura (no acuñar, no debitar lo
// ajeno) sigue viviendo en el ledger para TODO bytecode.
//
// El control de acceso por dueño usa [`pubkey`]: un contrato guarda la dirección
// de su admin en la `data` de la PDA al inicializar y, al retirar, exige que el
// FIRMANTE (`accounts[0]`) coincida con esa dirección guardada.
// ============================================================================

/// Lee la **dirección** (pubkey de 32 bytes) de `accounts[idx]`. Las direcciones
/// son públicas; esto habilita el control de acceso por dueño (comparar el
/// firmante contra un admin guardado). Devuelve `[0u8; 32]` si `idx` está fuera
/// de rango (una dirección que nunca es la de una cuenta real → un chequeo de
/// igualdad contra ella siempre falla, fail-closed).
#[inline]
pub fn pubkey(idx: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = unsafe { sys::host_get_pubkey(idx as i32, out.as_mut_ptr() as i32, 32) };
    if n != 32 {
        return [0u8; 32];
    }
    out
}

/// `true` si la dirección de `accounts[idx]` es exactamente `expected`. Útil para
/// "el firmante debe ser el admin guardado": `require!(pubkey_eq(0, &admin))`.
#[inline]
pub fn pubkey_eq(idx: u32, expected: &[u8; 32]) -> bool {
    &pubkey(idx) == expected
}

/// La **dirección que DESPLEGÓ este contrato** (registrada on-chain por
/// `DeployProgram` y ligada a la dirección del programa POR CONSTRUCCIÓN —
/// re-auditoría #2). Devuelve `[0u8; 32]` para un programa registrado en génesis
/// (sin deploy on-chain) o ante un fallo de memoria — una dirección que nunca es
/// la de una cuenta real, así un chequeo de igualdad contra ella siempre falla
/// (fail-closed).
#[inline]
pub fn deployer() -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = unsafe { sys::host_get_deployer(out.as_mut_ptr() as i32, 32) };
    if n != 32 {
        return [0u8; 32];
    }
    out
}

/// **ANTI INIT-TAKEOVER**: exige que el FIRMANTE (`accounts[0]`) sea la dirección
/// que desplegó este contrato. Se usa en la instrucción de `init` de un contrato
/// para cerrar el front-run donde un tercero llama la `init` primero y se registra
/// a sí mismo como admin. Aborta si el firmante no es el deployer.
///
/// Exige AMBAS cosas: (1) `accounts[0]` es el firmante autenticado
/// ([`require_signer(0)`]) — sin esto, nadie prueba controlar la dirección —, y
/// (2) esa dirección coincide con el deployer. El check de firma es esencial: el
/// sentinela `[0u8;32]` de un programa de génesis (sin deployer) igual exige que
/// el firmante sea la dirección cero, que nadie puede firmar → fail-closed.
#[inline]
pub fn require_deployer() {
    require_signer(0);
    require!(pubkey(0) == deployer());
}

/// **PAGO desde una tesorería del programa**: mueve `amount` (>= 0) de una cuenta
/// que ESTE programa posee (una PDA ya reclamada con [`use_pda`]) hacia `to`.
/// A diferencia de [`transfer`], NO exige firma sobre el origen — nadie firma
/// como una PDA; el ledger autoriza el débito porque el programa la posee. Aborta
/// si `amount < 0` o si la PDA no tiene saldo suficiente. Conserva el valor total.
///
/// **Importante:** llamá [`use_pda`] sobre `from` ANTES (para que el programa la
/// posea); si `from` NO es una PDA del programa ni el firmante, el ledger
/// RECHAZA el débito y la transacción entera se descarta (defensa del borde).
#[inline]
pub fn pda_transfer(from: u32, to: u32, amount: i64) {
    debit(from, amount); // el borde del ledger exige que el programa posea `from`
    credit(to, amount);
}

/// **DEPÓSITO en una tesorería**: un usuario firmante mueve `amount` de su propia
/// cuenta (`from`, que debe haber firmado) hacia la PDA de tesorería `to`. Es
/// exactamente [`transfer`] con nombre de intención; el usuario autoriza debitar
/// lo suyo, y acreditar la PDA es un simple crédito.
#[inline]
pub fn deposit(from: u32, to: u32, amount: i64) {
    transfer(from, to, amount);
}

// ============================================================================
// SDK v0.5 — CAPA DE SEGURIDAD. Helpers que codifican los HALLAZGOS y LECCIONES
// de la auditoría del proyecto para que un contrato de tercero los tenga "por
// defecto" y sea difícil de escribir mal. Las tres lecciones que más rompen
// contratos en el mundo real, hechas ergonómicas:
//
//   1) OVERFLOW-SAFETY: un `+`/`-` que desborda es la fuente #1 de acuñación/robo
//      en tokens. `add_u64`/`sub_u64` abortan (nunca envuelven) con mensaje.
//   2) AUTORIZACIÓN POR DUEÑO: `require_owner` compara el firmante contra un admin
//      guardado (el patrón de v0.4, reusable) — para mint/config/roles.
//   3) "DEBITAR SÓLO LO TUYO" POR CONSTRUCCIÓN: `holder_seed` deriva la PDA de
//      saldo de un titular de SU dirección, así un contrato que usa `pubkey(0)`
//      (el firmante) para el origen NO PUEDE tocar el saldo de otro — la
//      autorización queda en la ESTRUCTURA, no en un chequeo que se pueda olvidar
//      (la clase exacta del fix del borde WASM de v2.0.4, llevada al contrato).
//
// La garantía DURA sigue en el LEDGER (no acuñar, débito autorizado sólo si
// firmante o program-owned, conservación) para TODO bytecode; estos helpers hacen
// que el contrato ADEMÁS falle temprano, claro y por diseño.
// ============================================================================

/// Suma checkeada de `u64`: aborta (no envuelve) en overflow. En un ledger, un
/// overflow que envuelve acuña valor de la nada — la lección de `overflow-checks`.
#[inline]
pub fn add_u64(a: u64, b: u64) -> u64 {
    match a.checked_add(b) {
        Some(v) => v,
        None => {
            log("qchain-sdk: overflow u64");
            abort()
        }
    }
}

/// Resta checkeada de `u64`: aborta si `a < b` (underflow = saldo insuficiente /
/// acuñación por wraparound). Usalo para debitar un saldo/supply de un token.
#[inline]
pub fn sub_u64(a: u64, b: u64) -> u64 {
    match a.checked_sub(b) {
        Some(v) => v,
        None => {
            log("qchain-sdk: underflow / saldo insuficiente");
            abort()
        }
    }
}

/// Lee una dirección (32 bytes) de `buf[off..off+32]`; aborta si no entra.
#[inline]
pub fn read_pubkey(buf: &[u8], off: usize) -> [u8; 32] {
    let mut a = [0u8; 32];
    match buf.get(off..off + 32) {
        Some(s) => a.copy_from_slice(s),
        None => abort(),
    }
    a
}

/// Escribe una dirección (32 bytes) en `buf[off..off+32]`; aborta si no entra.
#[inline]
pub fn write_pubkey(buf: &mut [u8], off: usize, pk: &[u8; 32]) {
    match buf.get_mut(off..off + 32) {
        Some(s) => s.copy_from_slice(pk),
        None => abort(),
    }
}

/// Exige que el FIRMANTE (`accounts[0]`) sea el admin/dueño guardado en `buf` en
/// `admin_off` (32 bytes). El chequeo de dueño de v0.4, reusable para mint
/// authority / config / roles. Aborta si no coincide.
#[inline]
pub fn require_owner(buf: &[u8], admin_off: usize) {
    if pubkey(0) != read_pubkey(buf, admin_off) {
        log("qchain-sdk: solo el dueno");
        abort();
    }
}

/// Construye el seed de una PDA **por-titular**: `tag ‖ holder(32)` (33 bytes). La
/// clave de seguridad de un token: la dirección de la PDA de saldo de un titular
/// se deriva de SU dirección, así un contrato que usa `pubkey(0)` (el firmante)
/// como titular del origen SÓLO puede debitar el saldo del firmante — un atacante
/// que nombre la PDA de saldo de una víctima falla el `use_pda` (esa PDA no deriva
/// de la dirección del atacante) y la tx se descarta. La autorización queda POR
/// CONSTRUCCIÓN. El `tag` separa espacios de PDA (ej. `0x01` = saldos).
#[inline]
pub fn holder_seed(tag: u8, holder: &[u8; 32]) -> [u8; 33] {
    let mut s = [0u8; 33];
    s[0] = tag;
    s[1..].copy_from_slice(holder);
    s
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
