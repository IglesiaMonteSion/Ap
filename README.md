# SuperSol (SSOL)

Una blockchain propia inspirada en la arquitectura de Solana (cuentas, Proof
of History, ejecución de programas) pero con mejoras deliberadas:

1. **Criptografía híbrida resistente a ataques cuánticos.** Cada firma
   combina Ed25519 (clásico, rápido, probado) con **ML-DSA-65**
   ([NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf),
   el estándar sucesor de CRYSTALS-Dilithium). Una transacción solo es válida
   si **ambas** firmas verifican. Si algún día se rompe Ed25519 (por ejemplo
   con un computador cuántico suficientemente grande) o se encuentra una
   falla en ML-DSA (todavía joven como estándar), los fondos siguen
   protegidos mientras el otro esquema aguante.
2. **Fee de transacción extremadamente bajo, y quemado.** 500 "photon"
   (0.0000005 SSOL) por transacción, ~10x más barato que el fee típico de
   Solana (~5000 lamports / 0.000005 SOL) - y en vez de pagarse a un
   validador, se destruye por completo (deflacionario), ver [Fees](#fees).
3. **Suministro fijo de 700,000,000 SSOL, sin pre-mine a insiders.** Toda la
   emisión ocurre una sola vez, en el génesis, repartida entre una cuenta de
   tesoro y una reserva de recompensas de staking, ninguna con dueño (ninguna
   clave privada puede firmar como ellas). Nada en el código puede crear
   unidades nuevas después de eso — ver [Suministro fijo](#suministro-fijo).
4. **Staking sin inflación.** Puedes bloquear SSOL para respaldar al
   validador y ganar recompensas, financiadas por la reserva fija del punto
   anterior (nunca imprimiendo dinero nuevo) — ver [Staking](#staking).
5. **Nodos validadores baratos de operar.** El costo de cómputo por nodo es
   deliberadamente mínimo (un hash SHA-256 por tick) y la persistencia en
   disco no crece por bloque — ver [Eficiencia](#eficiencia-y-requisitos-de-hardware).
6. **Diseñado para escalar.** El motor de transacciones ya evita el cuello de
   botella más obvio (clonar todo el estado en cada transacción) y se midió
   con benchmarks reales, no adivinanzas — ver [Rendimiento](#rendimiento-cuántas-transacciones-por-segundo).

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
| **Programas nativos** (`supersol-runtime`) | Programas on-chain (System Program, Stake Program, ...) | `ProgramProcessor` es un trait: un programa nuevo es una función Rust, no bytecode BPF/eBPF compilado y desplegado. Incluye `SystemProgram` (crear cuentas, transferir), `StakeProgram` (Initialize/Deactivate/Withdraw) y `MemoProgram` (ejemplo mínimo). Compensación: hoy los programas son código Rust de confianza, no bytecode de terceros en sandbox — ver roadmap. |
| **Ledger** (`supersol-core::ledger`) | Estado de cuentas + historial de bloques | Aplica transacciones inmediatamente al recibirlas (firma + fee + instrucciones, sobre un *working set* acotado a las cuentas que la transacción realmente toca, no todo el ledger). Distribuye recompensas de staking por época. Mantiene solo una ventana acotada de bloques recientes en RAM (`recent_blocks`, 256 por defecto) — el historial completo vive en disco, no en memoria. |
| **Nodo validador** (`supersol-node`) | Validador + RPC JSON estilo Solana | Un hilo genera ticks de PoH constantemente; otro empaqueta bloques cada slot y dispara recompensas de staking cada época; un servidor JSON-RPC (`axum`) expone `getBalance`, `getAccountInfo`, `sendTransaction`, `requestAirdrop`, `getSlot`, `getLatestBlockhash`, `getBlock`, `getSupply`, `getIdentity`, `getStakeInfo`, `getHealth`. |
| **Wallet CLI** (`supersol-cli`, binario `supersol`) | `solana-keygen` / `solana` CLI | `keygen`, `address`, `balance`, `airdrop`, `transfer`, `supply`, `stake`, `unstake`, `withdraw-stake`, `stake-info`. |

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
pagador y **quemado** (destruido, `Ledger.total_burned`) - no va a un
validador ni a una fundación. Se cobra **aunque la instrucción falle** (igual
que en redes reales), para desincentivar spam. Configurable por nodo con
`--fee-units`.

Esto es deliberadamente deflacionario: el tope de 700M SSOL es un techo que
el supply nunca cruza hacia arriba, no una promesa de que el supply en
existencia nunca baja. Con fees quemándose, sí baja lentamente con el uso
real de la red - visible en todo momento vía `getSupply`/`supersol supply`.

Nota de diseño: como el fee se quema en vez de pagarse a quien produce el
bloque, este MVP de un solo validador no tiene hoy un incentivo económico
directo para operarlo (más allá de que el propio operador puede stakear su
SSOL y ganar recompensas de staking). Un esquema de recompensa de bloque más
completo es un ítem de fase 2, cuando haya multi-validador y competencia real
por producir bloques.

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
  (CLI): muestra el total fijo y cómo se reparte entre circulante, tesoro,
  reserva de staking y quemado. Esos cuatro números siempre suman exactamente
  700,000,000 SSOL.

## Staking

Cómo se resuelve la tensión entre "el fee se quema" (sin recompensa ahí) y
"supply fijo, nunca infla" (sin recompensa por inflación tampoco): al génesis
se reserva un 10% del supply (**70,000,000 SSOL**, `STAKING_RESERVE_UNITS`)
en una cuenta especial (`Pubkey::staking_rewards_pool()`, tan sin dueño como
el tesoro) dedicada exclusivamente a pagar recompensas de staking. Nunca se
imprime SSOL nuevo para esto - solo se redistribuye lo ya acuñado.

Flujo con la CLI:

```bash
# Bloquear 50 SSOL en una nueva cuenta de stake, delegada al validador del nodo
supersol stake alice.json stake1.json 50

# Ver cuánto lleva acumulado (el balance sube cada época mientras está activo)
supersol stake-info $(supersol address stake1.json)

# Dejar de ganar recompensas y habilitar el retiro
supersol unstake alice.json $(supersol address stake1.json)

# Retirar de vuelta a una wallet (solo permitido una vez desactivado)
supersol withdraw-stake alice.json $(supersol address stake1.json) alice.json 52.7
```

Mecánica interna:
- `StakeProgram` (nativo, `supersol-runtime`) maneja `Initialize` / `Deactivate`
  / `Withdraw`. Una cuenta de stake es una cuenta normal, dueña de sí misma el
  `StakeProgram`, cuyo `balance` **es** el monto stakeado y cuyo `data` guarda
  `{ authority, validator, status }`.
- Cada `--epoch-slots` (200 por defecto), el nodo reparte hasta
  `--reward-units-per-epoch` desde la reserva entre todas las cuentas de
  stake **activas**, proporcional a cuánto tiene stakeado cada una
  (`Ledger::distribute_staking_rewards`), acotado por el balance real de la
  reserva - cuando se agota, las recompensas simplemente paran.
- Este cálculo requiere ver *todas* las cuentas de stake a la vez (no solo
  las de una instrucción), así que vive como lógica de protocolo en el
  `Ledger`, no como parte del trait `ProgramProcessor` genérico.

> Nota de tokenomics: el 10% de reserva y la tasa de emisión por época son
> parámetros de partida razonables para un devnet, no un resultado de
> modelado económico. Calibrar una tasa de staking objetivo (Solana apunta a
> un rango de rendimiento anualizado, por ejemplo) es una decisión de
> gobernanza a tomar antes de cualquier lanzamiento real - ver
> [Limitaciones](#limitaciones-actuales).

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

## Rendimiento: ¿cuántas transacciones por segundo?

Números medidos, no adivinados. Reprodúcelos tú mismo:

```bash
cargo test --release -p supersol-crypto -- --ignored --nocapture
cargo test --release -p supersol-core   -- --ignored --nocapture
```

Resultados en el hardware de esta sesión de desarrollo (4 núcleos, Intel Xeon
2.80GHz - tu número variará con el hardware, pero las proporciones entre
pasos no deberían cambiar mucho):

| Operación | Resultado medido | Nota |
|---|---|---|
| Verificar firma Ed25519 sola | ~25,800 ops/s (38.7 µs) | Rápida, como siempre ha sido Solana |
| Verificar firma híbrida (Ed25519 + ML-DSA-65) | ~3,370 ops/s (297 µs) | El costo real por transacción - domina el precio de la seguridad post-cuántica |
| Firmar (híbrido, lado del cliente) | ~1,030 ops/s (974 µs) | Costo de la wallet al construir una tx, no del validador |
| `Ledger::apply_transaction` completo (firma + fee + programa) | ~3,490 tx/s | Prácticamente idéntico al costo de verificar sola - todo lo demás (HashMap, fee) es ruido |

**Conclusión honesta: en un solo núcleo, este motor procesa ~3,500
transacciones por segundo**, y el 99% de ese costo es la verificación
ML-DSA-65 (la parte "extremadamente segura" tiene un precio real en CPU,
~7-8x más cara que un Ed25519 solo). Una prueba de carga rápida contra el
propio servidor JSON-RPC (miles de requests concurrentes vía HTTP) confirmó
que axum/JSON no es el cuello de botella - se queda muy por debajo de ese
techo de ~3,500/s incluso con overhead de red y parseo, así que optimizar el
transporte no ayudaría hoy; optimizar o paralelizar la verificación criptográfica sí.

### ¿Se puede escalar? Sí, y así:

1. **Paralelizar la verificación entre núcleos (ya disponible, no implementado
   aún en el nodo).** Verificar la firma de una transacción es completamente
   independiente de verificar la de otra - es "embarrassingly parallel". En
   esta máquina de 4 núcleos, un pool de verificación paralela apuntaría a
   ~4 × 3,500 ≈ **14,000 tx/s** antes de tocar otro cuello de botella. Esto
   es una ganancia casi gratis: no cambia el formato de datos ni el consenso,
   solo cómo se reparte el trabajo de CPU. Próximo paso concreto de esta rama.
2. **El refactor del "working set" (ya hecho, ver arriba) es la base para
   ejecutar en paralelo transacciones que no comparten cuentas** - el mismo
   modelo "Sealevel" de Solana. Hoy el ledger sigue detrás de un único
   `Mutex`, pero como verificar (~300 µs) domina sobre aplicar (unas pocas
   operaciones de HashMap, sub-microsegundo), un pool que verifica en
   paralelo y solo toma el lock brevemente para aplicar puede acercarse al
   límite del punto 1 sin rediseñar el modelo de cuentas.
3. **Una implementación más rápida de ML-DSA.** `fips204` es Rust puro,
   simple y auditable, pero no está optimizada con instrucciones SIMD
   (AVX2/NEON) como las implementaciones de referencia en C que usan
   despliegues serios de post-cuántica. Como ML-DSA-65 es ~87% del costo por
   transacción, esta es la palanca individual más grande disponible.
4. **Verificación por lotes.** Investigar si ML-DSA-65 admite amortizar la
   verificación de muchas firmas juntas más barato que N llamadas separadas
   (algunos esquemas post-cuánticos lo permiten).
5. **Formato binario en vez de JSON-sobre-HTTP** para la ruta caliente de
   envío de transacciones - hoy no es el cuello de botella (ver la prueba de
   carga arriba), pero en una red gossip real entre validadores tampoco se
   usaría JSON de todos modos.
6. **Sharding / múltiples validadores en paralelo (fase 2 del roadmap).** La
   verdadera escalada a largo plazo de Solana viene de más núcleos y más
   validadores procesando en paralelo con un pipeline real (su "banking
   stage"), no de un truco único. Los puntos 1-2 de arriba son exactamente lo
   que hace falta construido *antes* de llegar a esa fase.

Con los pasos 1-3 (paralelizar verificación, aprovechar el working set, mejor
implementación de ML-DSA) juntos, un ~10x sobre el número actual de un solo
núcleo es una meta razonable en hardware de consumo, sin tocar el consenso
todavía. Ir más allá de eso (decenas de miles de tx/s sostenidas) sí requiere
la fase 2 (multi-validador real) para que el trabajo se reparta entre
máquinas, no solo entre núcleos de una.

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

# 9. Stakear una parte, delegada automáticamente al validador del nodo
./target/debug/supersol stake alice.json stake1.json 5
./target/debug/supersol stake-info $(./target/debug/supersol address stake1.json)
# ... espera unas cuantas épocas (--epoch-slots) y vuelve a consultar:
# el balance stakeado va subiendo con las recompensas.

# 10. Desestakear y retirar
./target/debug/supersol unstake alice.json $(./target/debug/supersol address stake1.json)
./target/debug/supersol withdraw-stake alice.json $(./target/debug/supersol address stake1.json) alice.json 5

# 11. Reiniciar el nodo (Ctrl+C y volver a correr el mismo comando del paso 2)
# reanuda en el mismo slot con los mismos saldos, leyendo solo accounts.json
# + meta.json (no todo el historial).
```

Este flujo completo (arranque con acuñación de génesis → supply → keygen →
airdrop → balance → transfer → staking con recompensas → unstake → withdraw
→ reinicio del nodo) se probó manualmente durante el desarrollo y funciona de
punta a punta, incluyendo la verificación híbrida de firmas, el cobro y quema
del fee, la distribución de recompensas de staking, y la reanudación
correcta del estado tras reiniciar el proceso.

### Tests automatizados

```bash
cargo test --workspace
```

28 pruebas cubren: cadena PoH verificable y detección de manipulación, firma
y verificación híbrida (incluyendo intentos de falsificar el bundle de
claves), aplicación de transacciones y rechazo de firmas inválidas (incluida
la que confirma que una transacción solo toca las cuentas que referencia),
quema de fee (incluso si la instrucción falla), acuñación de génesis y
disburso acotado del tesoro, recompensas de staking pro-rata acotadas por la
reserva, la ventana acotada de bloques recientes, y los programas
nativos (transferencia, fondos insuficientes, memo, ciclo de vida completo de
staking). Los benchmarks de rendimiento (ver
[Rendimiento](#rendimiento-cuántas-transacciones-por-segundo)) están
marcados `#[ignore]` y se corren aparte, no como parte de esta suite.

## Estructura del repo

```
crates/
  supersol-crypto/    Keypair híbrida (Ed25519 + ML-DSA-65), direcciones, firmas
  supersol-core/      Proof of History, cuentas, transacciones, bloques, ledger, staking
  supersol-runtime/   Programas nativos (System, Stake, Memo)
  supersol-node/      Validador: ticking de PoH, productor de bloques, epochs de staking, RPC JSON
  supersol-cli/       Wallet de línea de comandos (binario `supersol`)
```

## Roadmap

**Fase 1 (hecho en este MVP):** un solo validador, PoH simplificado, modelo
de cuentas, programas nativos en Rust (incluyendo staking), firma híbrida
post-cuántica, fee fijo bajo y quemado, suministro fijo de 700M SSOL con
tesoro y reserva de staking sin dueño, faucet de devnet acotado por el
tesoro, persistencia O(1) por bloque con ventana acotada de memoria,
ejecución de transacciones sin clonar todo el estado, wallet CLI, RPC JSON,
benchmarks reales de rendimiento.

**Fase 2 — Multi-validador real y más TPS:**
- Gossip de red entre validadores (hoy todo corre en un proceso).
- Consenso tipo Tower BFT / HotStuff sobre el líder rotativo, para que el
  estado no dependa de un único nodo de confianza.
- Verificación de firmas en paralelo entre núcleos, y ejecución paralela de
  transacciones con cuentas disjuntas (el *working set* de `apply_transaction`
  ya deja el terreno preparado) — ver [Rendimiento](#rendimiento-cuántas-transacciones-por-segundo).
- Mercado de fees por congestión (mantiene el fee bajo en condiciones
  normales, sube solo si hay spam real) y un esquema de recompensa de bloque
  ahora que el fee se quema en vez de pagarse al líder.
- Delegación de stake a más de un validador (el campo `validator` en
  `StakeState` ya existe para esto).

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
- Calibración seria de tokenomics: tasa de emisión de staking, tamaño de la
  reserva, y si el fee debería seguir siendo 100% quemado o repartirse en
  parte con validadores (fase 2), con modelado económico real en vez de los
  valores de partida usados hoy.
- Explorador de bloques, más métodos RPC (`getTransaction`, `getSignatureStatuses`),
  suscripciones websocket.
- Testnet pública con múltiples operadores independientes.

## Limitaciones actuales

- Un solo validador: no hay tolerancia a fallas bizantinas todavía (fase 2).
- El motor de transacciones ya no clona todo el estado por transacción, pero
  sigue siendo de un solo hilo (un único `Mutex<Ledger>`) - la paralelización
  real de verificación/ejecución es trabajo de fase 2, no implementado
  todavía, ver [Rendimiento](#rendimiento-cuántas-transacciones-por-segundo).
- Los "programas" son código Rust nativo de confianza, no bytecode en sandbox
  de terceros (fase 3).
- `accounts.json`/`blocks.log` son archivos planos, no una base de datos real
  — suficiente para un devnet de un solo nodo, no para producción (fase 5).
  El escaneo de `getBlock` para slots muy antiguos es lineal sobre
  `blocks.log`, sin índice todavía.
- El esquema criptográfico híbrido no ha sido auditado externamente.
- Los parámetros de staking (10% de reserva, cadencia de época, emisión por
  época) son valores de partida razonables, no un resultado de modelado
  económico - fácilmente ajustables vía flags del nodo (`--epoch-slots`,
  `--reward-units-per-epoch`), pero pendientes de calibración real (fase 5).
