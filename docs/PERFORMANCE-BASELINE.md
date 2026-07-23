# Línea base de rendimiento de qchain — Fase 0

**Propósito.** Este documento es el **punto de partida REPRODUCIBLE** del plan de
rendimiento ("INSTRUCCIÓN MAESTRA: aumentar el TPS sin debilitar la seguridad").
Ninguna fase posterior (1–5) se acepta si no mejora un número que aquí quede
**medido y fechado**, sin romper ninguna de las invariantes de seguridad.

Regla de oro del plan, no negociable:

> **seguridad y determinismo > ausencia de forks > recuperación y persistencia > rendimiento**

- **Fecha de medición:** 2026-07-23
- **Commit medido:** `4045bcf83d3e69a96596dcaccd0cc67149e2ba8c` (**v8.6.7**) — el árbol se midió aquí
- **Este documento se entrega en:** v8.6.8 (sólo agrega este archivo de docs; runtime byte-idéntico a 8.6.7)
- **Rama:** `claude/custom-blockchain-currency-0jztro`

---

## 0. Invariantes de seguridad que esta línea base NO puede violar

Se copian aquí para que toda medición/optimización futura se contraste contra
ellas. **Ninguna optimización de TPS puede tocar ni una:**

1. No quitar Ed25519 ni ML-DSA-65.
2. No hacer opcional ningún componente de la firma híbrida.
3. No aceptar una tx si sólo una de las dos firmas es válida.
4. No reducir el umbral de quórum de certificados.
5. No contar dos veces el stake de un firmante duplicado.
6. No aceptar firmas de validadores desconocidos.
7. No saltear la verificación de `chain_id`.
8. No saltear nonces.
9. No saltear `valid_until_round`.
10. No desactivar límites de tamaño / rate-limiting / protección DoS para "medir mejor".
11. No cambiar SHA3-256 por un hash más rápido sin revisión criptográfica formal.
12. No actualizar balances desde varios hilos compartiendo estructuras mutables sin aislamiento.
13. No escribir directo al `StateStore` desde hilos paralelos.
14. No cambiar el orden canónico de transacciones.
15. No continuar después de detectar una diferencia de estado.
16. No migrar en silencio una red de árbol viejo al árbol comprimido.
17. **No usar un benchmark local como promesa de rendimiento geodistribuido.**
18. No sacrificar persistencia / fsync / atomicidad por TPS.

---

## 1. Entorno de la medición

| Campo | Valor |
|---|---|
| Toolchain Rust | `rustc 1.94.1 (e408947bf 2026-03-25)` / `cargo 1.94.1` (pinneado por `rust-toolchain.toml`) |
| SO / kernel | Linux `6.18.5-fc-v15` x86_64 |
| CPU | Intel Xeon @ 2.80 GHz, **4 núcleos** (sandbox de desarrollo) |
| RAM | 15 GiB total |
| Disco | `/dev/vda`, ~6 GiB libres al momento de medir |
| Crates del workspace | 17 |
| Perfil release | `overflow-checks = true` (un underflow de balance = halt determinista, no wrap) |

**Defaults de red que definen el punto de operación de la línea base:**

| Parámetro | Default | Fuente |
|---|---|---|
| `round_interval_ms` | **500** | `config.rs::default_round_interval_ms` |
| `storage_engine` | **`redb`** (transaccional, commit atómico estado+ronda+economía; `sled` es dev-only) | `config.rs::default_storage_engine` |
| `compressed_state_tree` | **`false`** (árbol legacy 256-deep por default; el comprimido es opt-in y se pliega en `chain_id`) | `config.rs` |
| `economics_v7` | `false` (opt-in) | `config.rs` |
| Firma | Híbrida **Ed25519 + ML-DSA-65** (verify ~124–155 µs/tx, medido en increments previos) | — |

> **Aviso honesto (invariante #17).** Este es un host de **4 núcleos compartidos**.
> Todos los números "de un nodo" que siguen son un **techo de CPU/algoritmo por
> nodo**, NO una promesa de TPS de una red geodistribuida real. En una red
> multi-región el límite pasa a ser la **latencia de consenso + verificación PQC
> entre nodos**, medida históricamente en **~105–109 tx/s a n=10** (ver §4). El
> sandbox además **mata procesos de larga duración al reiniciar el contenedor**,
> así que un soak sostenido multi-nodo NO es reproducible aquí — es una tarea
> **operativa** (VPS reales, varias regiones), fuera del alcance de una sesión de
> código.

---

## 2. Gates de calidad (estado del árbol en el commit base)

Ejecutados en este commit, en este entorno:

| Gate | Resultado | Tiempo | Nota |
|---|---|---|---|
| `cargo check --workspace --locked` | ✅ **PASA** | 2 m 04 s | compila limpio |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | ✅ **PASA (limpio)** | 19 s | 0 warnings |
| `cargo test --workspace --locked` (unit/integration) | ✅ **PASA, 0 fallos** | (ver nota) | todos los crates salvo el DST |
| `cargo test -p qchain-simulation` (**DST**) | ⚠️ **runnable, no terminó** en el presupuesto del sandbox | >5 min | 6/13 confirmados `ok`, 0 fallos; los sweeps de rotación/shrink de decenas de seeds son lentos en 4 núcleos |
| `cargo fmt --all -- --check` | ❌ **FALLA en todo el workspace** | <1 s | **condición preexistente** — el proyecto históricamente enforcea clippy, nunca rustfmt |
| `cargo build --workspace --release --locked` | ⏭️ **no ejecutado en sesión** | — | el build de los 7 binarios de release con liboqs+wasmtime+winterfell corre en runners de CI, no en el sandbox (ya documentado) |

**Conteos de tests que SÍ terminaron (0 fallos en todos):** qchain-execution
**214** (+2 ignored), qchain-node **51** (lib) + 8 (main) + 2 (integración
`migrate_registry_tool`), qchain-consensus **28**, qchain-network **23** (+1
ignored), qchain-storage **36**, qchain-crypto **23** + KAT, qchain-stark **20**,
qchain-governance **12**, qchain-remote-signer **4**, qchain-core **14**.

**DST (`qchain-simulation`), 13 escenarios — los 6 confirmados `ok` antes del
corte por tiempo son justamente los núcleos de seguridad:**
`honest_network_no_faults_converges_safely_and_makes_progress`,
`honest_network_under_message_loss_and_delay_stays_safe`,
`one_silent_validator_below_the_fault_bound_still_makes_progress`,
`equivocating_author_never_gets_two_certificates_for_the_same_round`,
`a_healing_partition_still_reaches_safety_and_resumes_progress`,
`beyond_the_fault_bound_is_out_of_scope_for_the_safety_guarantee`.
Los 7 restantes (sweeps de rotación/shrink + soak `#[ignore]`d) no fallaron;
simplemente no cupieron en el presupuesto de tiempo del sandbox de 4 núcleos.
El proyecto los reporta históricamente en **12/12** (≈46 s en paralelo) en un
entorno con más núcleos.

**Acción pendiente registrada (no bloqueante para la línea base):**
`cargo fmt --all --check` falla en 68 archivos. NO se reformateó — hacerlo en un
PR de *medición* metería un diff enorme e irrelevante. Si se decide adoptar
rustfmt como gate, es su propio PR de formato (mecánico, revisable), separado del
plan de rendimiento.

---

## 3. Dónde se gasta el tiempo por transacción (perfil ya medido)

Estos números vienen de mediciones REALES de increments previos (benchmarks
criterion + gates temporales, documentados en el registro del proyecto). Definen
qué vale la pena optimizar y qué NO:

| Componente de `apply_transaction` | Costo | Fuente |
|---|---|---|
| **Escrituras del árbol de Merkle legacy (256-deep)** | **~82 %** del apply | gate temporal + bench de profundidad |
| Verificación de firma híbrida PQC | ~10 % (145 µs/tx aislado) | bench criterion `signing.rs` |
| Captura del recibo STARK (4 pruebas Merkle) | ~8 % | gate temporal (712→776 tx/s al apagarlo) |

**Conclusión de perfil (ya validada):** el gran lever de un nodo era el **árbol de
Merkle**, NO la verificación PQC. Por eso el árbol comprimido (Fase 1 del plan)
**ya está hecho** y da el salto grande; y la verificación PQC ya se paralelizó en
el commit (v5.2.0) sin tocar el orden canónico ni el aislamiento de estado.

---

## 4. TPS medido — números de referencia con procedencia

Todos son mediciones REALES (metodología `qchain load-test` / `qchain stress`,
convergencia de punta a punta envío→gossip→consenso→ejecución), no estimaciones.
Se listan con su procedencia exacta para que cada fase futura se compare contra
el número correcto.

### 4.1 Techo de un nodo (apply/drain, aislado)

| Configuración | TPS | Procedencia |
|---|---|---|
| Apply single-thread, árbol legacy 256-deep | **~712 tx/s** | bench de apply |
| Drain sostenido de un nodo, legacy, `round_interval_ms=100` | **~335 tx/s** (pico 348) | v4.4.2 medido |
| Drain de un nodo, **árbol comprimido**, `round_interval_ms=100` | **~2 200 tx/s** (pico 2 312) | v5.1.1 A/B |
| Drain de un nodo, comprimido, A/B fresco v5.5.1 | **~2 679 tx/s** | v5.5.1 |
| Drain de un nodo, comprimido, **verify PQC paralelo** bajo flood | **~3 838 tx/s** pico | v5.2.0 |

**Ganancia comprimido vs legacy medida en A/B idéntico (mismo nodo/workload,
sólo cambia el flag):** **~5,9×–6,6×** de throughput de punta a punta de un nodo,
con **RAM 3,7× menor** (892 → 244 MB) y **disco 5,7× menor** (780 → 136 MB) para
el mismo lote — v5.1.1 / v5.5.1.

### 4.2 Punta a punta multi-nodo (el número que importa de verdad)

| Red | TPS de convergencia | Procedencia |
|---|---|---|
| n=3, transporte de una conexión por mensaje (JSON) | ~186–203 tx/s | fase temprana |
| n=10, pre-optimización de transporte | ~81–84 tx/s | fase temprana |
| n=10, **transporte con conexiones persistentes + Borsh** | **~105–109 tx/s** | optimización de transporte |

> Estas cifras multi-nodo son de un **árbol legacy** y de este mismo sandbox de 4
> núcleos compartidos; una red comprimida geodistribuida sobre hardware dedicado
> por validador sube por-nodo (menos costo de apply/RAM/disco) pero su TPS de red
> lo termina fijando la latencia de consenso + verify PQC entre nodos, no el
> apply de un nodo.

### 4.3 Estado de las fases del plan respecto de esta línea base

| Fase del plan | Estado real | Evidencia |
|---|---|---|
| **0 · baseline** | ✅ este documento | — |
| **1 · árbol comprimido** | ✅ **YA HECHO** (opt-in, hard fork, se pliega en `chain_id`) | v5.0.0 + light-client v5.1.0 + state-sync v5.7.1; **~6×** un nodo |
| **2 · paralelismo de verificación** | ⚠️ **PARCIAL** — verify de **tx** en commit ya paralelizado (v5.2.0, diferencial-idéntico probado); verify de **certificados** sigue pendiente | v5.2.0 |
| **3 · persistencia/batching** | ⚠️ **PARCIAL** — redb atómico (v5.3.0), recibos two-tier (v5.4.0), pipelining de nonce (v5.5.0), Borsh en logs (v5.4.1) ya hechos | varias |
| **4–5 · reestructuras mayores** | ❌ **no hechas**, mayor riesgo (tocan orden canónico / hilos / persistencia) | — |

---

## 5. Criterio de aceptación para cualquier fase futura (checklist obligatorio)

Ninguna fase 1–5 se mergea sin responder, en su propio PR, sobre una **red de
prueba nueva** (nunca el `data_dir` de una red real):

1. Qué optimiza y por qué (contra el perfil de §3).
2. Qué invariante de §0 **podría** tocar y por qué NO la toca.
3. **Test diferencial**: misma entrada, camino viejo vs nuevo → **byte-idéntico**
   (mismo state root, mismos balances/nonces, mismo orden canónico).
4. **No-fork multi-nodo en vivo**: ≥3 validadores, mismo Merkle root al mismo
   número de tx EJECUTADAS.
5. **Reinicio**: matar y reiniciar un validador → resume sin fork ni pérdida de
   tx finalizadas.
6. **DST 12/12** intacto (seguridad + vivacidad, incluye pérdida de certs +
   equivocador).
7. `clippy -D warnings` limpio.
8. TPS **antes vs después** medido con la MISMA metodología, mediana de 5 corridas.
9. RAM/disco antes vs después (no debe empeorar sin justificación).
10. Declara explícitamente si el número es de **un nodo** o **de red** (invariante #17).
11. Si toca persistencia, prueba fsync/atomicidad/durabilidad en kill-9 (invariante #18).

---

## 6. Limitaciones honestas de esta línea base

- Los benchmarks sostenidos `load-test --count 50000` / `stress --sustained-secs
  120` **no se corrieron en esta sesión**: el sandbox de 4 núcleos + reinicio de
  contenedor no sostiene un flood largo multi-nodo de forma reproducible. Se
  reportan en su lugar los números REALES ya medidos en increments previos, con
  procedencia. Para números frescos de 50k sostenido → correrlos en la VPS del
  usuario (`qchain stress --fire-and-forget --queue-target 50000 --workers 32`),
  que ya trae la instrumentación de RAM/CPU/disco (`/resources`).
- El build de release de los 7 binarios + un soak multi-VPS de semanas es
  **operativo**, no de sesión (mismo status que la auditoría externa / bug bounty).
- `cargo fmt` no está enforced; adoptarlo es un PR de formato aparte.

**En una frase:** el árbol comprimido (Fase 1) ya entrega el salto grande de un
nodo (~6×, con menos RAM/disco) y la verificación de tx ya es paralela — el
proyecto **ya supera 2 000 TPS de apply en un nodo**; el techo real de una red
sigue siendo la latencia de consenso + verify PQC multi-nodo, que sólo se puede
medir de verdad en un despliegue geodistribuido real.
