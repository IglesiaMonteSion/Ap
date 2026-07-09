# SuperSol (SSOL)

Una blockchain propia inspirada en la arquitectura de Solana (cuentas, Proof
of History, ejecución de programas) pero con tres mejoras deliberadas:

1. **Criptografía híbrida resistente a ataques cuánticos.** Cada firma
   combina Ed25519 (clásico, rápido, probado) con **ML-DSA-65**
   ([NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
   el estándar sucesor de CRYSTALS-Dilithium). Una transacción solo es válida
   si **ambas** firmas verifican. Si algún día se rompe Ed25519 (por ejemplo
   con un computador cuántico suficientemente grande) o se encuentra una
   falla en ML-DSA (todavía joven como estándar), los fondos siguen
   protegidos mientras el otro esquema aguante.
2. **Fee de transacción extremadamente bajo.** 500 "photon" (0.0000005 SSOL)
   por transacción, ~10x más barato que el fee típico de Solana (~5000
   lamports / 0.000005 SOL). Es posible porque este MVP corre con un solo
   validador (sin mercado de fees todavía); el roadmap explica cómo se
   mantiene bajo al escalar a varios validadores.
3. **Descentralización real desde el génesis.** No hay pre-mine ni
   asignación privilegiada a una fundación: el génesis solo fija una semilla
   aleatoria para el reloj criptográfico. Todo el suministro se emite después
   (hoy vía faucet de devnet; a futuro vía recompensas de validador).

> ⚠️ **Esto es un MVP de un solo validador, no auditado.** Implementa ideas
> reales de forma correcta y con pruebas automatizadas, pero ni el esquema
> híbrido ni el resto del código han pasado una auditoría de seguridad
> externa. No lo uses para custodiar valor real todavía — ver
> [Limitaciones](#limitaciones-actuales) y el [roadmap](#roadmap).

## Arquitectura

| Componente | Inspiración en Solana | Qué hace aquí |
|---|---|---|
| **Proof of History** (`supersol-core::poh`) | Reloj verificable basado en un hash-chain secuencial | `Poh::tick()` encadena SHA-256; `Poh::record(data)` mezcla datos (p. ej. el hash de una transacción) probando que existieron *antes* de cada tick posterior. Cualquiera puede re-verificar la cadena con `verify_poh_sequence`. |
| **Modelo de cuentas** (`supersol-core::account`) | Cuentas con `owner`, `balance` y `data`, no UTXO | Cada cuenta tiene balance en "photon" (1 SSOL = 1e9 photon), un programa dueño, y datos arbitrarios. |
| **Programas nativos** (`supersol-runtime`) | Programas on-chain (System Program, SPL Token, ...) | `ProgramProcessor` es un trait: un programa nuevo es una función Rust, no bytecode BPF/eBPF compilado y desplegado. Incluye `SystemProgram` (crear cuentas, transferir) y `MemoProgram` (ejemplo mínimo). Compensación: hoy los programas son código Rust de confianza, no bytecode de terceros en sandbox — ver roadmap. |
| **Ledger** (`supersol-core::ledger`) | Estado de cuentas + historial de bloques | Aplica transacciones inmediatamente al recibirlas (firma + fee + instrucciones), y el bloque es solo el registro auditable de lo que pasó en cada slot. |
| **Nodo validador** (`supersol-node`) | Validador + RPC JSON estilo Solana | Un hilo genera ticks de PoH constantemente; otro empaqueta bloques cada slot; un servidor JSON-RPC (`axum`) expone `getBalance`, `getAccountInfo`, `sendTransaction`, `requestAirdrop`, `getSlot`, `getLatestBlockhash`, `getBlock`, `getHealth`. |
| **Wallet CLI** (`supersol-cli`, binario `supersol`) | `solana-keygen` / `solana` CLI | `keygen`, `address`, `balance`, `airdrop`, `transfer`. |

## Seguridad: cómo funciona la firma híbrida

- Una `Keypair` contiene un par Ed25519 **y** un par ML-DSA-65.
- La dirección (`Pubkey`) es `sha256(pubkey_ed25519 || pubkey_mldsa)` — se
  mantiene compacta (32 bytes, base58, igual que una dirección de Solana) en
  vez de exponer la clave pública ML-DSA completa (1952 bytes) en cada
  dirección.
- Cada transacción lleva el *bundle* de claves públicas completas del pagador
  (`payer_keys`). Al verificar, el validador primero recalcula el hash del
  bundle y confirma que coincide con la dirección reclamada, y solo entonces
  verifica **ambas** firmas sobre el mensaje. Si cualquiera de las dos
  verificaciones falla, la transacción se rechaza.
- Esto es el mismo patrón "revela la clave solo al gastar" que usa Bitcoin
  con P2PKH, aplicado para no inflar el tamaño de cada dirección.

## Fees

`BASE_FEE_UNITS = 500 photon` (0.0000005 SSOL) por transacción, cobrado al
pagador y acreditado al validador (líder) que la procesó — no se quema ni se
regala a una fundación. Se cobra **aunque la instrucción falle** (igual que
en redes reales), para desincentivar spam. Configurable por nodo con
`--fee-units`.

## Cómo correr un devnet local

```bash
# 1. Compilar todo
cargo build --workspace

# 2. Levantar un nodo devnet con faucet habilitado
./target/debug/supersol-node --ledger-dir ./supersol-ledger --enable-faucet --rpc-port 8899

# 3. En otra terminal: crear wallets
./target/debug/supersol keygen --outfile alice.json
./target/debug/supersol keygen --outfile bob.json

# 4. Pedir fondos de prueba (máx. 10 SSOL por request por defecto)
./target/debug/supersol airdrop $(./target/debug/supersol address alice.json) 10

# 5. Ver saldo
./target/debug/supersol balance alice.json

# 6. Transferir
./target/debug/supersol transfer alice.json $(./target/debug/supersol address bob.json) 3

# 7. Confirmar
./target/debug/supersol balance alice.json
./target/debug/supersol balance bob.json
```

Este flujo completo (keygen → airdrop → balance → transfer → balance) se
probó manualmente durante el desarrollo y funciona de punta a punta,
incluyendo la verificación híbrida de firmas y el cobro del fee.

### Tests automatizados

```bash
cargo test --workspace
```

21 pruebas cubren: cadena PoH verificable y detección de manipulación, firma
y verificación híbrida (incluyendo intentos de falsificar el bundle de
claves), aplicación de transacciones y rechazo de firmas inválidas, cobro de
fee (incluso si la instrucción falla), y los programas nativos (transferencia,
fondos insuficientes, memo).

## Estructura del repo

```
crates/
  supersol-crypto/    Keypair híbrida (Ed25519 + ML-DSA-65), direcciones, firmas
  supersol-core/      Proof of History, cuentas, transacciones, bloques, ledger
  supersol-runtime/   Programas nativos (System, Memo)
  supersol-node/      Validador: ticking de PoH, productor de bloques, RPC JSON
  supersol-cli/       Wallet de línea de comandos (binario `supersol`)
```

## Roadmap

**Fase 1 (hecho en este MVP):** un solo validador, PoH simplificado, modelo
de cuentas, programas nativos en Rust, firma híbrida post-cuántica, fee fijo
bajo, faucet de devnet, wallet CLI, RPC JSON.

**Fase 2 — Multi-validador real:**
- Gossip de red entre validadores (hoy todo corre en un proceso).
- Consenso tipo Tower BFT / HotStuff sobre el líder rotativo, para que el
  estado no dependa de un único nodo de confianza.
- Mercado de fees por congestión (mantiene el fee bajo en condiciones
  normales, sube solo si hay spam real).

**Fase 3 — Contratos de terceros en sandbox:**
- Reemplazar los "programas nativos de confianza" por una VM en sandbox
  (probablemente WASM) para poder desplegar programas de terceros sin
  comprometer al validador — hoy cualquier programa nuevo requiere confiar en
  el código Rust del binario del nodo.

**Fase 4 — Endurecimiento de la criptografía híbrida:**
- Auditoría externa del esquema Ed25519 + ML-DSA-65 y de `fips204`.
- Evaluar añadir SPHINCS+ (basado en hashes, aún más conservador) como tercera
  capa opcional para cuentas de alto valor.
- Rotación de claves y multisig nativo.

**Fase 5 — Producción:**
- Persistencia real (hoy es un snapshot JSON completo por bloque — no escala).
- Explorador de bloques, más métodos RPC (`getTransaction`, `getSignatureStatuses`),
  suscripciones websocket.
- Testnet pública con múltiples operadores independientes.

## Limitaciones actuales

- Un solo validador: no hay tolerancia a fallas bizantinas todavía (fase 2).
- Los "programas" son código Rust nativo de confianza, no bytecode en sandbox
  de terceros (fase 3).
- Persistencia por snapshot JSON completo — funcional para un devnet, no para
  producción (fase 5).
- El esquema criptográfico híbrido no ha sido auditado externamente.
