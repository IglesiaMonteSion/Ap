# Límites formales de memoria y disco (tarea #18)

> **Qué formaliza.** El espejo de recursos de `docs/INVARIANTS.md` (#15): así como
> aquél enumera las invariantes económicas/estructurales y dónde se fuerzan, éste
> enumera **toda estructura de datos que crece** durante la vida de un nodo — cada
> colección en RAM, cada árbol en disco, y cada blob Borsh on-chain — junto con su
> **cota formal** (constante o ventana), **dónde se fuerza**, y si un atacante o el
> crecimiento orgánico puede empujarla sin bound. El objetivo: que ninguna
> estructura quede sin un límite explícito o un bound implícito documentado.
>
> El inventario salió de una auditoría de 3 agentes sobre los 11 crates; las
> cotas ya existentes se cruzaron una a una, y las 3 estructuras genuinamente sin
> acotar se cerraron con código (marcadas **#18** abajo). Las demás ya estaban
> acotadas por incrementos previos.

La regla del proyecto — *"si no hay una optimización segura mejor no se hace nada"* —
aplica: se cerró con código sólo lo genuinamente sin bound Y seguro; las cotas
implícitas (bound por el tamaño del estado, por el orden comprometido, por la
ventana de consenso) se **documentan** en vez de forzar un cambio riesgoso.

---

## 1. Nodo — memoria (`qchain-node::engine::EngineState` + `Engine`)

| Estructura | Crece con | Cota | ¿Atacante sin bound? |
|---|---|---|---|
| `mempool` (por pagador) | cada tx admitida | `MAX_MEMPOOL_TXS_PER_PAYER=4096` por pagador; colas vacías removidas | No — pagadores distintos gated por solvencia + `AdmissionQuota` + costo Sybil |
| `pipeline_next` | cada pagador con cola | podado a los pagadores del mempool activo | No |
| `batches` (caché) | cada worker-batch gossipeado | ventana `BATCH_RETENTION_ROUNDS=1024` + cap speculative | No |
| `speculative_batches` | cada batch no referenciado | cap `16` por `(validador,ronda)` + ventana | No |
| `wanted_batches` | cada digest referenciado por un vértice válido | ventana `ROUND_STATE_RETENTION=512` × ≤`WORKER_COUNT`/vértice | Ventana × cap estructural |
| `pending_cert_requests` / `pending_batch_requests` | cada padre/batch faltante referenciado | ventana `ROUND_STATE_RETENTION` | Ventana × cap estructural (ver §7) |
| `pending_votes_to_send` / `pending_availability_votes` | cada voto/aviso debido | ventana `ROUND_STATE_RETENTION` | No |
| `round_committed` / `voted_for` / `first_seen_vertex` | cada ronda / (ronda,autor) | ventana `ROUND_STATE_RETENTION` | No |
| `equivocation_evidence` | cada equivocación observada | **una** entrada por autor | No |
| `participation_credits` (v7) | cada cert comprometido | alimentado+removido en `gc_floor/rpq`; interno ≤ comité | No |
| `dag` (`DagStore`) | cada certificado | `prune_below(gc_floor)`, `DAG_RETENTION_ROUNDS` | No |
| `consensus.seen` / `committed_cache` | cada cert comprometido | `forget_seen` en la poda / `retain(>=gc_floor)` | No (en producción) |
| `sig_cache` | cada tx verificada-true | `MAX_SIG_CACHE=200_000` FIFO | No |
| `admission_quota` / rate-limiters RPC | cada IP/txid | `WindowMap`, `MAX_TRACKED_IPS=100_000` fail-closed | No |
| `snapshot_cache` / `disk_size_cache` | request de snapshot / `/resources` | valor único con TTL (120s / 3s) | No |
| `SIM_CACHE` (`/simulate`) | cada simulación | `SIM_CACHE_MAX=8192` FIFO | No |
| **`validator_schedule` (comités por época)** | **una época** (rotación ON) | **#18 — `prune_epochs_below(gc_floor)`** en la poda del nodo | No (rotación-ON, orgánico) |
| `pending_execution` (`VecDeque`) | cada cert comprometido sin batch local | ver §7 (orden comprometido + snapshot-sync) | Bound implícito |

## 2. Nodo — disco (árboles sled)

| Store | Crece con | Cota | ¿Atacante? |
|---|---|---|---|
| `receipt_log` / `receipt_full_log` | cada transfer | `MAX_INMEM_RECEIPTS=5000` / `600` con pruebas | No |
| `staking_log` | cada evento de staking | `MAX_INMEM_STAKING_EVENTS=5000` | No |
| `cert_log` (DAG) / `batch_log` | cada cert / batch persistido | `gc_floor = finalized_floor − DAG_RETENTION_ROUNDS` | No |
| **`committee_log`** | **una época** (rotación ON) | **#18 — `prune_committee_log_below(anchor)`**, mismo `gc_floor` que el DAG | No (rotación-ON, orgánico) |
| `economics` / `round_checkpoint` | cada ronda | archivo único sobrescrito | No |

> **Nota sled:** sled reclama las claves borradas de forma perezosa (log-structured),
> así que las podas acotan el **conteo de entradas lógico / el costo de recarga en
> boot**, no inmediatamente los bytes en disco. Documentado desde v5.3.1.

## 3. Ejecución / consenso / storage

| Estructura | Crece con | Cota | ¿Atacante? |
|---|---|---|---|
| `Ledger.transfer_receipts` / `staking_events` | cada transfer / evento | acotado por el nodo (`cap_receipt_log`/`cap_staking_events`) | No |
| `Ledger.participation_by_quanto` | cada tally por cuanto | `retain(>= cutoff)`, `PARTICIPATION_RETENTION_QUANTOS=64` | No |
| `working` (working set por tx) | cuentas declaradas de la tx | efímero, ≤ `MAX_TRANSACTION_BYTES` | No |
| `TreasuryState.signers` / `pending` / `approvals` | op de tesorería | `MAX_TREASURY_SIGNERS=16` / `MAX_TREASURY_PENDING=16` + `prune_expired` (#17) | No |
| `ValidatorV7Registry.validators` | cada `BondAndRegister` (bono 500 QCH) | `MAX_V7_VALIDATORS=1000` | No |
| `active_committee` (derivado) | por época | `truncate(MAX_ACTIVE_V7_VALIDATORS=100)` | No |
| `ModuleCache` (WASM) | cada contrato distinto llamado | `MAX_CACHED_MODULES=256` LRU | No |
| `crypto RegistryEntry` Vec | alta de algoritmo | gated por gobernanza (supermayoría + timelock) | No |
| `DagStore.by_digest` / `by_round` | cada cert | `prune_below`; interno ≤ comité | No |
| `Ledger.validator_commissions` | primer bloque de un proponente | **sin podar** — ver §7 (bound por proponentes distintos) | Bound implícito |
| `RedbStore.mem` / `IncrementalStateTree` / `IncrementalCompressedTree` | cada cuenta creada | **sin cap** — el término fundamental de estado, ver §7 | Bound implícito (fee-gated) |

## 4. Blobs on-chain (Borsh en `account.data` — crecen la hoja Merkle + el costo de re-serialización de TODO nodo)

| Blob | Crece con | Cota | ¿Atacante? |
|---|---|---|---|
| `TreasuryState.pending` / `.signers` | op de tesorería | 16 / 16 (§3) | No |
| `ValidatorV7Registry.validators` | validador registrado | `MAX_V7_VALIDATORS=1000` (§3) | No |
| `EmergencyState` (guardianes / aprobaciones) | aprobación | `.clear()` en cada flip; guardianes de génesis | No |
| **`Proposal.voted_stake_accounts`** | **cada votante distinto** | **#18 — `MAX_PROPOSAL_VOTES=100_000`** (`at_vote_capacity`) + reclamado por `CloseProposal` (#16) | No — cap duro generoso + costo económico por voto |

## 5. Red / wallet / faucet / remote-signer

| Estructura | Crece con | Cota | ¿Atacante? |
|---|---|---|---|
| `ConnTracker.per_ip` / `per_validator` | conexión entrante / validador auth | ≤ conexiones vivas ≤ `max_inbound_connections=2048` / set autorizado | No |
| **`ConnTracker.banned_ips` / `banned_ids`** | IP/identidad baneada | **#18 — fail-closed** en `MAX_BANNED=100_000` (GC + skip-si-lleno) | No — bans gated por conexión viva |
| `Network.connections` / `peers` | peer dialeado / rotación | set de peers configurado/comité (no atacante) | No |
| wallet `WindowMap` (`per_ip` / `per_txid`) | IP / txid de cliente | `MAX_TRACKED_KEYS=100_000` **fail-closed** cada llamada | No |
| faucet `last_claim` / `recent_payouts` | payout confirmado | podado a la ventana + `max_payouts_per_window` gatea el insert | No (Sybil de dirección fresca gated por el cap global) |
| remote-signer `DoubleSignGuard` / `conn` | request de voto / reconexión | `Option` único | No |

---

## 6. Cerradas con código en #18 (las 3 genuinamente sin acotar)

1. **`committee_log` (disco) + `validator_schedule` (memoria)** — una entrada por
   época, para siempre, en una red con `validator_rotation=true`. `ValidatorSchedule::prune_epochs_below(gc_floor)`
   (consenso) descarta los comités de las épocas cuyo rango de rondas cae entero
   bajo el `gc_floor` del DAG — el mismo floor que ya poda los certificados, y
   esos certs nunca se re-piden ni re-verifican, así que `for_round(r)` queda
   idéntico para toda ronda aún resoluble. `prune_committee_log_below(anchor)`
   (nodo) borra las mismas épocas en disco, así un reinicio reconstruye el
   schedule idéntico desde los comités retenidos. **Rotación-ON solamente** →
   una red sin rotación (el default del usuario) nunca escribe `committee_log` ni
   instala más de la época 0: inerte, byte-idéntico.
2. **`Proposal.voted_stake_accounts` (blob on-chain)** — sin techo duro; crecía un
   pubkey por votante distinto durante la vida activa de una propuesta.
   `MAX_PROPOSAL_VOTES=100_000` (cota formal generosa, muy por encima de cualquier
   participación realista para la escala de esta red → nunca rechaza un votante
   legítimo, una red por debajo del cap es byte-idéntica) forzado en el borde de
   ejecución (`at_vote_capacity` antes de `record_vote`). El blob además se
   reclama al podar la propuesta (`CloseProposal`, #16).
3. **`ConnTracker.banned_ips` / `banned_ids` (red)** — el cap `MAX_BANNED` era
   *soft* (GC-luego-insert-incondicional). Ahora es **fail-closed**: tras el GC,
   se inserta sólo si hay lugar o la clave ya existe (refrescar un ban no crece el
   mapa); si sigue lleno de bans vivos, se saltea. No alcanzable por un atacante
   (un ban requiere abuso sostenido sobre una conexión viva, con tope global), pero
   convierte el 100k en un techo duro.

## 7. Cotas implícitas documentadas (no se tocan — la regla "sin optimización segura, nada")

- **Tamaño del estado — `RedbStore.mem`, los árboles Merkle (`Incremental*Tree`).**
  RAM ∝ nº de cuentas distintas. **Monotónico**: el ledger nunca borra cuentas
  (el trait tiene `remove` pero el ledger no lo llama; `CloseProposal` vacía la
  `data` pero la hoja persiste). Cota implícita: fee + dust por creación de
  cuenta (crear una cuenta cuesta). Es el término fundamental de estado de
  cualquier L1; el **árbol comprimido** (v5.0.0, ~1 nodo/cuenta vs 256×/cuenta del
  legacy) es la mitigación estructural. No hay forma de "acotar" el estado sin
  borrar cuentas (imposible en un ledger). Documentado, no un bug.
- **`pending_execution` (`VecDeque`).** Crece un `Certificate` por cert
  comprometido-pero-no-ejecutable mientras se espera un batch faltante/retenido.
  NO se capea a propósito: el invariante "bloquear-nunca-saltear" (v3.0.3) es lo
  que evita un fork al ejecutar el orden comprometido — descartar un cert
  comprometido rompería esa seguridad. Acotado en la práctica por el orden
  comprometido + la ventana de resync; un nodo demasiado atrasado pasa a
  snapshot-sync (#109). Un cap aquí sería una optimización insegura.
- **`Ledger.validator_commissions` (BTreeMap).** Una entrada por proponente
  distinto, sin podar. Dato **report-only** (ganancias por-validador del
  dashboard, persistido en `EconomicSnapshot`). Bound implícito: nº de
  validadores distintos que alguna vez propusieron — pequeño en la práctica
  (~KB aún con churn de rotación), orgánico, no acelerable por un atacante.
  Podarlo tocaría el formato del snapshot de economía por un beneficio marginal
  → se documenta, no se capea.
- **Mapas por-ventana** (`pending_cert_requests`, `pending_batch_requests`,
  `wanted_batches`). Acotados por `ROUND_STATE_RETENTION=512` × caps
  estructurales (`parents.len() ≤ n` por mensaje, el candado `voted_for` limita
  propuestas aceptadas por `(ronda,autor)`). Un peer Bizantino puede inflarlos
  hasta el **techo de la ventana** (no sin bound) antes de que la poda alcance;
  ese techo es el diseño aceptado del transporte no-autenticado.

---

## Modelo de despliegue

Los 3 fixes de #18 son **node-local / gated**: no cambian el wire, el consenso ni
el estado de una red sin rotación ni el `chain_id`. El cap de votantes es
consensus-affecting sólo para el voto #100 001 (inalcanzable en la práctica →
byte-idéntico). Para la red del usuario: `git pull && sudo ./deploy/update-node.sh`.

**Límite honesto:** los dos fixes de rotación (`committee_log` + `validator_schedule`)
sólo se ejercitan con `validator_rotation=true` (default OFF, la red del usuario no
los toca), y su corrección se prueba por unit tests + el argumento de que la poda
usa el mismo `gc_floor` que la poda del DAG ya verificada en vivo; la verificación
multi-nodo de rotación en vivo multi-época sigue siendo territorio del harness (la
rotación es opt-in y su live-test es flaky en el sandbox de 4 núcleos).
