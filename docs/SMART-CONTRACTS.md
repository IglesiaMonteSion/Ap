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
| **`use_pda(idx, seed) -> bool`** | reclama/usa `accounts[idx]` como PDA del programa (SDK v0.3) |
| **`pubkey(idx) -> [u8;32]`** | dirección de `accounts[idx]` (para control de acceso por dueño, SDK v0.4) |
| **`pubkey_eq(idx, &expected) -> bool`** | ¿la dirección de `accounts[idx]` es `expected`? |
| **`pda_transfer(from, to, amount)`** | PAGA desde una PDA del programa (sin firma sobre el origen; SDK v0.4) |
| **`deposit(from, to, amount)`** | DEPÓSITO en una tesorería (= `transfer`, con nombre de intención) |
| **`add_u64(a,b)` / `sub_u64(a,b)`** | aritmética checkeada (abortan en over/underflow; SDK v0.5) |
| **`read_pubkey/write_pubkey(buf, off[, pk])`** | lee/escribe una dirección (32B) en un buffer |
| **`require_owner(&buf, off)`** | exige que el firmante sea el dueño guardado en `buf[off..off+32]` |
| **`holder_seed(tag, &holder) -> [u8;33]`** | seed de PDA por-titular (`tag ‖ holder`) — "debitar sólo lo tuyo" por construcción |

> **Escribiendo un contrato con dinero real?** Leé
> [`CONTRACT-SECURITY.md`](CONTRACT-SECURITY.md) — la checklist de seguridad para
> autores (qué garantiza el ledger vs qué tenés que hacer vos), y usá
> `templates/token/` (token fungible endurecido, verificado en vivo contra ataques)
> como punto de partida.

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

## Estado COMPARTIDO en cuentas del programa — PDAs (SDK v0.3)

Para estado que **ningún usuario firma** (un contador global, un supply, un
libro de órdenes), el contrato usa una cuenta **propia del programa** cuya
dirección es una **PDA** (Program-Derived Address) derivada de
`program_id + seed`. Cualquier usuario puede llamar al contrato; el estado
compartido vive en la PDA, no en la cuenta de nadie.

```rust
// Contador GLOBAL: cualquiera suma al mismo total, guardado en la PDA "global".
// accounts[0] = usuario (firma) ; accounts[1] = pda(program_id, "global")
fn dispatch([sel, x, _y, _z]: [i64; 4]) {
    require!(use_pda(1, b"global"));   // accounts[1] ES nuestra PDA (la reclama la 1ª vez)
    let mut buf = [0u8; 16];
    let n = get_data(1, &mut buf);
    let mut total = if n >= 8 { read_u64(&buf, 0) } else { 0 };
    total = total.saturating_add(x as u64);
    write_u64(&mut buf, 0, total);
    set_data(1, &buf);                 // persiste en la PDA (program-owned)
}
```

Ejemplo completo: `crates/qchain-sdk/templates/shared_counter/`.

**El cliente deriva la dirección de la PDA off-chain** (con la MISMA fórmula) y
la incluye en `accounts`:

```
pda = SHA3-256("qchain-program-pda-v1" ‖ program_id(32) ‖ seed)
```

Con el signer: `qchain-wasm-signer program-pda <program_id> <seed>`. En el nodo:
`qchain_execution::wasm::derive_pda`; para JS/wallet: `qchain_wasm::program_pda`.

**Seguridad:** `use_pda` verifica que la cuenta declarada sea genuinamente la PDA
de ESTE programa (`address == derive(program_id, seed)`), y la reclama
(`owner = program_id`) solo si está **fresca**. Como el `program_id` entra en la
derivación, **un programa nunca puede reclamar la PDA de otro** → sin
front-running. Una vez reclamada, solo ese programa escribe su `data` (autorizado
por `owner == program_id`, el mismo borde que los saldos).

## Tesorerías de programa + control de acceso por dueño (SDK v0.4)

Una PDA puede guardar **fondos** además de estado — una **tesorería del
programa**. Lo que faltaba en v0.3 era mover fondos DESDE la PDA: `transfer`
exige que el ORIGEN haya firmado, y **nadie firma como una PDA**. `pda_transfer`
es el pago desde una PDA (el ledger autoriza el débito porque el programa la
posee, `owner == program_id` — el mismo borde de siempre), y `pubkey(idx)` lee la
dirección de una cuenta para el **control de acceso por dueño** (guardá al admin
en la data de la PDA y, al retirar, exigí que el firmante coincida).

```rust
// Bóveda con dueño: cualquiera deposita, sólo el admin retira.
// accounts[0]=firmante  accounts[1]=PDA "vault"  accounts[2]=destino del retiro
fn dispatch([sel, x, _, _]: [i64; 4]) {
    require!(use_pda(1, b"vault"));
    let mut buf = [0u8; 40];               // [admin: 32][total: u64 @32]
    let n = get_data(1, &mut buf);
    match sel {
        1 => { // init: fija al firmante como admin (una vez)
            require!(n < 40); require_signer(0);
            buf[0..32].copy_from_slice(&pubkey(0)); set_data(1, &buf);
        }
        2 => { deposit(0, 1, x); }          // cualquiera deposita: firmante -> PDA
        3 => {                              // sólo el admin retira: PDA -> accounts[2]
            let mut admin = [0u8; 32]; admin.copy_from_slice(&buf[0..32]);
            require!(pubkey(0) == admin, "sólo el admin");
            pda_transfer(1, 2, x);
        }
        _ => abort(),
    }
}
```

Plantilla completa en `crates/qchain-sdk/templates/vault/`. **Verificado en vivo
end-to-end** (nodo real): deploy → init (admin) → deposit 5 QCH (user1) → el admin
retira 3 QCH a un destino → un **NO-admin es RECHAZADO** (los fondos de la bóveda
quedan intactos, sólo pagó el fee de su intento).

> **Seguridad:** la garantía dura sigue en el LEDGER: `pda_transfer` sólo funciona
> si el programa POSEE el origen (si no, el borde rechaza el débito y descarta la
> tx entera); acuñar sigue siendo imposible; `pubkey` es read-only (las direcciones
> son públicas). El control de acceso por dueño lo hace el CONTRATO, respaldado por
> esas garantías del ledger.

Los syscalls crudos del host (`host_get_balance`, `host_set_balance`,
`host_is_signer`, `host_get_pubkey`, `host_log`, `host_verify_signature`) siguen
disponibles para casos avanzados; el SDK cubre el 99% de los contratos.

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
