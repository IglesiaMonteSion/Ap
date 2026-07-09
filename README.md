# SuperSol (SSOL)

Una blockchain propia inspirada en la arquitectura de Solana (cuentas, Proof
of History, ejecución de programas) pero con cuatro mejoras deliberadas:

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
3. **Suministro fijo de 700,000,000 SSOL, sin pre-mine a insiders.** Toda la
   emisión ocurre una sola vez, en el génesis, hacia una cuenta de tesoro sin
   dueño (ninguna clave privada puede firmar como ella). Nada en el código
   puede crear unidades nuevas después de eso — ver
   [Suministro fijo](#suministro-fijo).
4. **Nodos validadores baratos de operar.** El costo de cómputo por nodo es
   deliberadamente mínimo (un hash SHA-256 por tick) y la persistencia en
   disco no crece por bloque — ver [Eficiencia](#eficiencia-y-requisitos-de-hardware).

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
| **Ledger** (`supersol-core::ledger`) | Estado de cuentas + historial de bloques | Aplica transacciones inmediatamente al recibirlas (firma + fee + instrucciones). Mantiene solo una ventana acotada de bloques recientes en RAM (`recent_blocks`, 256 por defecto) — el historial completo vive en disco, no en memoria. |
| **Nodo validador** (`supersol-node`) | Validador + RPC JSON estilo Solana | Un hilo genera ticks de PoH constantemente; otro empaqueta bloques cada slot; un servidor JSON-RPC (`axum`) expone `getBalance`, `getAccountInfo`, `sendTransaction`, `requestAirdrop`, `getSlot`, `getLatestBlockhash`, `getBlock`, `getSupply`, `getHealth`. |
| **Wallet CLI** (`supersol-cli`, binario `supersol`) | `solana-keygen` / `solana` CLI | `keygen`, `address`, `balance`, `airdrop`, `transfer`, `supply`. |

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

## Suministro fijo

- `TOTAL_SUPPLY_SSOL = 700_000_000` — constante en el código
  (`supersol-core::account::TOTAL_SUPPLY_UNITS`), no un parámetro que un
  validador pueda inflar.
- En el primer arranque de un ledger nuevo (cuando no existe todavía
  `meta.json` en el directorio del nodo), `Ledger::genesis_mint` acuña el
  supply completo **una sola vez** hacia `Pubkey::treasury()`: una dirección
  centinela fija en el código, no derivada de ningún par de claves real. Nadie
  puede firmar una transacción como el tesoro — no existe ni puede existir una
  clave privada que le corresponda — así que la única forma de mover esos
  fondos es a través de la lógica explícita del validador
  (`Ledger::disburse_from_treasury`), nunca por una firma falsificada.
- `requestAirdrop` ya **no imprime dinero de la nada**: mueve unidades del
  tesoro hacia la dirección solicitada, acotado por el balance real del
  tesoro. Si el tesoro se agota, el faucet simplemente falla — el supply total
  jamás puede superar 700,000,000 SSOL.
- Verifícalo en cualquier momento con `getSupply` (RPC) o `supersol supply`
  (CLI): muestra el total fijo, cuánto está en circulación y cuánto queda en
  el tesoro. `circulante + tesoro` siempre suma exactamente el total.

## Eficiencia y requisitos de hardware

Montar un nodo aquí es deliberadamente barato, con dos decisiones concretas:

- **Cómputo:** cada tick de Proof of History es **un solo hash SHA-256**
  (`Poh::tick`), no la cadena de hashing a máxima velocidad de un solo núcleo
  que usa Solana real para maximizar TPS. A 20 ticks/segundo por defecto, el
  costo de CPU es insignificante incluso en hardware muy modesto (una
  Raspberry Pi, una VPS de 1 vCPU). La contrapartida explícita: menor
  throughput que Solana a cambio de que participar como validador no requiera
  hardware caro — una decisión de diseño, no un descuido.
- **Disco y memoria acotados, no crecientes por bloque:** antes, cada bloque
  reescribía *todo* el historial de la cadena a disco (costo creciente sin
  límite). Ahora la persistencia son tres piezas separadas:
  - `accounts.json` — snapshot del estado actual de cuentas (crece con el
    número de cuentas activas, no con la longitud de la cadena).
  - `meta.json` — checkpoint de unos pocos bytes (slot + último blockhash)
    que permite reanudar el nodo en tiempo O(1), sin releer nada.
  - `blocks.log` — historial completo, pero *append-only*: cada bloque nuevo
    se agrega al final, nunca se reescribe lo anterior.
  - En memoria, `Ledger` solo retiene una ventana acotada de bloques
    recientes (`--recent-blocks-window`, 256 por defecto) para responder
    `getBlock` rápido; los bloques más antiguos se sirven con un escaneo de
    `blocks.log` bajo demanda — el mismo compromiso que usan los validadores
    reales de Solana al podar su ledger y delegar el historial completo a
    nodos de archivo separados.

Esto significa que el costo de operar un nodo (CPU, RAM, I/O por bloque) se
mantiene aproximadamente constante sin importar cuánto tiempo lleve corriendo
la cadena o cuántos bloques se hayan producido — a diferencia de guardar todo
el historial en memoria o reescribirlo en cada bloque.

## Cómo correr un devnet local

```bash
# 1. Compilar todo
cargo build --workspace

# 2. Levantar un nodo devnet con faucet habilitado
# (la primera vez que corre contra un directorio nuevo, acuña los 700M SSOL
# en el tesoro - esto pasa exactamente una vez)
./target/debug/supersol-node --ledger-dir ./supersol-ledger --enable-faucet --rpc-port 8899

# 3. En otra terminal: confirmar el supply fijo
./target/debug/supersol supply

# 4. Crear wallets
./target/debug/supersol keygen --outfile alice.json
./target/debug/supersol keygen --outfile bob.json

# 5. Pedir fondos de prueba, tomados del tesoro (máx. 10 SSOL por request por defecto)
./target/debug/supersol airdrop $(./target/debug/supersol address alice.json) 10

# 6. Ver saldo
./target/debug/supersol balance alice.json

# 7. Transferir
./target/debug/supersol transfer alice.json $(./target/debug/supersol address bob.json) 3

# 8. Confirmar
./target/debug/supersol balance alice.json
./target/debug/supersol balance bob.json
./target/debug/supersol supply   # circulante subió, tesoro bajó, total sigue igual

# 9. Reiniciar el nodo (Ctrl+C y volver a correr el mismo comando del paso 2)
# reanuda en el mismo slot con los mismos saldos, leyendo solo accounts.json
# + meta.json (no todo el historial).
```

Este flujo completo (arranque con acuñación de génesis → supply → keygen →
airdrop → balance → transfer → balance → reinicio del nodo) se probó
manualmente durante el desarrollo y funciona de punta a punta, incluyendo la
verificación híbrida de firmas, el cobro del fee, y la reanudación correcta
del estado tras reiniciar el proceso.

### Tests automatizados

```bash
cargo test --workspace
```

22 pruebas cubren: cadena PoH verificable y detección de manipulación, firma
y verificación híbrida (incluyendo intentos de falsificar el bundle de
claves), aplicación de transacciones y rechazo de firmas inválidas, cobro de
fee (incluso si la instrucción falla), acuñación de génesis y disburso
acotado del tesoro, la ventana acotada de bloques recientes, y los programas
nativos (transferencia, fondos insuficientes, memo).

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
bajo, suministro fijo de 700M SSOL con tesoro sin dueño, faucet de devnet
acotado por ese tesoro, persistencia O(1) por bloque con ventana acotada de
memoria, wallet CLI, RPC JSON.

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
- Base de datos real (RocksDB/sled) en vez de JSON plano para `accounts.json`,
  e indexado de `blocks.log` para que las consultas de historial antiguo no
  dependan de un escaneo lineal.
- Explorador de bloques, más métodos RPC (`getTransaction`, `getSignatureStatuses`),
  suscripciones websocket.
- Testnet pública con múltiples operadores independientes.

## Limitaciones actuales

- Un solo validador: no hay tolerancia a fallas bizantinas todavía (fase 2).
- Los "programas" son código Rust nativo de confianza, no bytecode en sandbox
  de terceros (fase 3).
- `accounts.json`/`blocks.log` son archivos planos, no una base de datos real
  — suficiente para un devnet de un solo nodo, no para producción (fase 5).
  El escaneo de `getBlock` para slots muy antiguos es lineal sobre
  `blocks.log`, sin índice todavía.
- El esquema criptográfico híbrido no ha sido auditado externamente.
