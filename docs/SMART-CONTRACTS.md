# Contratos inteligentes en Qchain — `qchain-sdk`

Escribí contratos de Qchain **en Rust** (no en WebAssembly a mano). El crate
`qchain-sdk` da wrappers seguros de los syscalls del host, un macro para el punto
de entrada, y helpers de saldos. Un contrato compila a un `.wasm` chico que se
despliega con `qchain deploy-program` o el panel **Contratos → Desplegar** de
QScan (firmando en la wallet).

> **¿Antes esto era a mano?** Sí — se escribía el `.wasm`/WAT cuidando la
> convención `i64` y los syscalls. El SDK reemplaza eso por Rust legible. Ambos
> caminos siguen produciendo el mismo tipo de `.wasm`.

## 1. Instalar el target de wasm (una vez)

```bash
rustup target add wasm32-unknown-unknown
# opcional pero recomendado (achica el .wasm):
#   apt-get install binaryen     # trae wasm-opt
```

## 2. Escribir un contrato

Un contrato es una carpeta con su `Cargo.toml` y `src/lib.rs`. Ejemplo completo
en `crates/qchain-sdk/templates/payments/` (una "tesorería/pagos" con 6
funciones). El corazón:

```rust
#![no_std]
use qchain_sdk::{abort, balance, entrypoint, log, require, transfer};

// accounts[0] = ORIGEN (tiene que firmar) ; accounts[1..] = destinos
fn dispatch([sel, x, y, z]: [i64; 4]) {
    match sel {
        1 => { log("transfer"); transfer(0, 1, x); }                 // x: acct0 -> acct1
        2 => { log("split2");  transfer(0, 1, x); transfer(0, 2, y); }
        4 => { log("sweep");   transfer(0, 1, balance(0)); }         // todo -> acct1
        5 => { require!(x >= 0 && x <= 10_000);                       // x = puntos básicos
               transfer(0, 1, (balance(0) / 10_000) * x); }          // x/10000 del saldo
        _ => abort(),
    }
}
entrypoint!(dispatch);   // exporta `run` con 4 args i64 y llama a `dispatch`
```

`Cargo.toml` del contrato:

```toml
[package]
name = "payments"
version = "0.1.0"
edition = "2021"
[workspace]                       # su propio workspace (se compila aparte)
[lib]
crate-type = ["cdylib"]           # produce el .wasm
[dependencies]
qchain-sdk = { path = "RUTA/A/crates/qchain-sdk" }
[profile.release]
opt-level = "z"                   # optimizar para TAMAÑO (tope 256 KB)
lto = true
panic = "abort"
strip = true
codegen-units = 1
```

## 3. Compilar

```bash
deploy/build-contract.sh crates/qchain-sdk/templates/payments
# => crates/qchain-sdk/templates/payments/payments.wasm  (~557 bytes)
```

## 4. Desplegar e interactuar

**Desde la CLI:**

```bash
qchain deploy-program --rpc <url> --keypair <tu>.json \
  --module payments.wasm --entry-point run
# imprime la dirección del contrato

qchain call-program --rpc <url> --keypair <tu>.json \
  --program <dir-contrato> \
  --accounts <TU_DIR>,<DESTINO> \
  --args 1,5000000000,0,0            # sel=1 transfer 5 QCH (5e9 unidades)
```

**Desde QScan** (con el puente wallet-connect): **Contratos → Desplegar /
interactuar → Conectar wallet**, subí el `.wasm`, entry point `run`; después
llamá con las cuentas (CSV, la 1ª tu wallet) y los args i64 (CSV).

## Reglas del modelo de ejecución (importante)

- **Cuentas por índice.** La instrucción declara `accounts[]`. El contrato
  lee/escribe saldos por índice. **`accounts[0]` es el ORIGEN y debe firmar.**
- **Args `i64`, aridad FIJA.** Con `entrypoint!` el punto de entrada `run` toma
  **4** `i64` (`sel, a, b, c`). Quien llama pasa **siempre 4 args** (rellená con
  `0` los que no uses) — un `.wasm` de aridad N rechaza una llamada con ≠ N args.
- **Unidades.** 1 QCH = 1 000 000 000 unidades. Los montos van en unidades.

## Seguridad (la da el ledger, no el contrato)

Aunque un contrato sea malicioso, el **ledger** garantiza en el borde, para TODO
bytecode: (1) una cuenta solo se DEBITA si el llamador está autorizado (es el
firmante, o el programa la posee); (2) el total de saldo nunca crece (acuñar es
imposible). El SDK agrega chequeos tempranos y claros (`require_signer`, montos
≥ 0, saldo suficiente), pero la garantía dura vive en el ledger. Un `panic`,
`require!` fallido o `abort()` = **trap**: se descartan los cambios y el pagador
igual paga el fee de su intento.

## API del SDK

| Función | Qué hace |
|---|---|
| `balance(idx) -> i64` | saldo de `accounts[idx]` (-1 si el índice no existe) |
| `set_balance(idx, v)` | escribe el saldo (crudo; preferí `transfer`) |
| `is_signer(idx) -> bool` | ¿`accounts[idx]` firmó esta tx? |
| `require_signer(idx)` | aborta si `idx` no firmó |
| `credit(idx, amount)` | acredita (checked, `amount ≥ 0`) |
| `debit(idx, amount)` | debita (aborta si no alcanza) |
| `transfer(from, to, amount)` | `from` firma → debita `from`, acredita `to` |
| `log(msg)` | emite un evento de texto |
| `abort()` / `require!(cond[, msg])` | trap si falla |
| `entrypoint!(handler)` | exporta `run(4×i64)` → `handler([i64;4])` |
| **`data_len(idx)`** | largo de `accounts[idx].data` (SDK v0.2) |
| **`get_data(idx, &mut buf) -> usize`** | copia la `data` de `accounts[idx]` a `buf` |
| **`set_data(idx, &bytes)`** | escribe la `data` de `accounts[idx]` (autorizada por el ledger) |
| **`read_u64/read_i64/read_u32(buf, off)`** | lee un entero LE del buffer |
| **`write_u64/write_i64/write_u32(buf, off, v)`** | escribe un entero LE en el buffer |

## Estado estructurado on-chain (SDK v0.2)

Además de saldos, un contrato puede guardar **estado estructurado** en los bytes
de `data` de una cuenta. El patrón v0.2: **cada usuario guarda su propio estado
en su cuenta** (`accounts[0]`, el firmante). El contrato arma un layout de
offsets fijos (sin `serde`, `no_std`):

```rust
// Estado en accounts[0].data (16 bytes): [count: i64 @0][updates: u64 @8]
fn dispatch([sel, x, _y, _z]: [i64; 4]) {
    require!(is_signer(0));                 // solo el dueño toca su estado
    let mut buf = [0u8; 16];
    let n = get_data(0, &mut buf);
    let mut count = if n >= 8 { read_i64(&buf, 0) } else { 0 };
    match sel {
        1 => count = x,                     // init
        2 => count = count.saturating_add(x), // add
        _ => abort(),
    }
    write_i64(&mut buf, 0, count);
    set_data(0, &buf);                      // persiste on-chain
}
```

Ejemplo completo: `crates/qchain-sdk/templates/counter/`. **Se lee de vuelta por
RPC**: `GET /account/<dir>` devuelve el campo `data` (los bytes del estado), que
el cliente decodifica con el mismo layout.

**Autorización (la refuerza el LEDGER):** la `data` de una cuenta solo puede
cambiar si el llamador está autorizado sobre ella — es el **firmante**, o el
**programa la posee** — el MISMO modelo que el débito de saldo. Un contrato NO
puede sobrescribir la `data` de una víctima que no firmó. Tope de escritura:
**16 KB** por cuenta. Un `owner` de cuenta **nunca** cambia por un contrato.

> **Límite v0.2:** el estado se guarda en la cuenta del **firmante**. Cuentas de
> estado **propias del programa** (estilo PDA de Solana, `owner == program_id`,
> para estado compartido que ningún usuario firma) necesitan asignación de owner
> — es el próximo incremento del SDK. El borde de autorización ya lo contempla
> (la rama "programa la posee"), así que landeará sin cambio de seguridad.

Los syscalls crudos del host (`host_get_balance`, `host_set_balance`,
`host_is_signer`, `host_log`, `host_verify_signature`) siguen disponibles para
casos avanzados; el SDK cubre el 99% de los contratos de pagos/tokens.

## Límites honestos

- **Un solo firmante** por transacción (el pagador). No hay multisig on-chain
  todavía; `host_verify_signature` permite verificar firmas arbitrarias dentro
  del contrato si necesitás lógica de autorización custom.
- **Sin estado arbitrario más allá de saldos** en el SDK v0.1: la API expuesta
  es de saldos por cuenta (el modelo de pagos). Guardar datos estructurados en
  la `data` de una cuenta es posible a bajo nivel pero todavía no tiene wrappers
  de alto nivel — es el siguiente incremento del SDK.
- Bytecode máximo **256 KB**; `opt-level="z"` + `wasm-opt` mantienen los
  contratos de pagos en cientos de bytes.
