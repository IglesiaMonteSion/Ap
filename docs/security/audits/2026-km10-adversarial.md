# Auditoría KM#10 — pasada adversarial del ciclo de vida de claves (interna)

- **Fecha / versión:** v8.6.36
- **Alcance:** el ciclo de vida COMPLETO de claves de validador (registro con roles
  separados → comité de recuperación → timelocks de clave fría → rotación de
  consenso en dos fases → freeze/unfreeze → expiry → revoke → recuperación del
  bono), ejercitado **entre varios nodos** y con un **actor adversario** dentro,
  más pérdida de disponibilidad de un nodo (kill -9 + reinicio).
- **Método:** test del exploit escrito ANTES del fix (debe fallar), + harness
  multinodo sobre un testnet real (`deploy/km-lifecycle-test.sh`), + enumeración
  manual de la superficie (EC-17).
- **Motivo:** los puntos KM#1–#9 se verificaron cada uno EN AISLAMIENTO. Esta
  pasada busca específicamente huecos en la **COMPOSICIÓN** de dos controles que
  por separado funcionan.

## Hallazgos

| # | Severidad | Hallazgo | Estado |
|---|---|---|---|
| 1 | **ALTO** | El freeze de emergencia (KM#9) no cubría el bono ni el ciclo de vida de claves: con la validadora CONGELADA, el atacante podía aterrizar un `RotateWithdrawal` pendiente (KM#5) vía el `ApplyPendingKeyChange` permissionless y drenar los 500 QCH del bono. | **CERRADO** (`require_not_frozen`) |
| 2 | Doc | La tabla de "qué rechaza la pausa" clasificaba 15 de las 17 variantes de `ValidatorV7Instruction` (faltaban `BondAndRegister` y `CancelConsensusKeyRotation`) — precisamente el fallo de disciplina que EC-17 define. | **CERRADO** (tabla exhaustiva 17/17) |
| 3 | Doc/test | El estado compuesto **"revocado y todavía congelado"** era alcanzable y no estaba ni documentado ni cubierto por test (el test previo saltaba el quanto más allá del deadline, así que nunca lo ejercitaba). | **CERRADO** (documentado + test que lo fija) |

### Hallazgo 1 (ALTO) — detalle

1. El atacante roba la clave fría de operador.
2. Propone `RotateWithdrawal` hacia su dirección; el timelock de KM#5 lo deja
   pendiente ~72 h — **la ventana de reacción funciona**.
3. El comité de recuperación reacciona dentro de la ventana y **congela** el
   validador (KM#9): sale del comité de consenso y del reparto de fees.
4. Pasada la ventana, el atacante llama `ApplyPendingKeyChange`, que es
   **permissionless a propósito** (el operador ya autorizó al proponer; quien
   aplica es un relayer). El freeze **no lo miraba** → la rotación aterrizaba →
   `BeginExit` + `WithdrawBond` **drenaban el bono**.

**Causa raíz.** `is_frozen` se OR-eó dentro de `consensus_key_disabled` — elegante,
porque ése es el único gate que `active_committee` y `fees_v7::is_eligible` ya
consultan —, pero el ciclo de vida de claves y el bono **nunca consultan ese
gate**. El control se cableó donde era cómodo, no en toda la superficie que
prometía pausar.

**Cierre.** `ValidatorV7Program::require_not_frozen`, cableado en los 7 handlers
que mueven bono o cambian claves (todos ya pinnean `STAKING_GLOBAL` — sin ese pin
`current_quanto` lee 0 y el gate no vería el freeze). La lista de rechazadas y
permitidas, con su razón, está en el doc-comment del helper y en
[`key-management-program.md`](../key-management-program.md#10). Byte-idéntico para
cualquier validador que nunca se congeló.

## Evidencia

- **Test del exploit escrito primero y FALLANDO** →
  `an_emergency_freeze_blocks_the_bond_drain_and_pending_key_changes`
  (ahora test de regresión: falla si se quita el gate).
- **Harness multinodo en vivo:** `./deploy/km-lifecycle-test.sh` →
  **23 de 23 aserciones OK, 0 fallos**, con **root byte-idéntico en los dos nodos
  en cada paso** del ciclo (la prueba de no-fork que el DST no puede dar, porque
  `qchain-simulation` modela consenso, no ejecución). Incluye:
  `pending cold-key change did NOT land while frozen`,
  `BeginExit REFUSED while frozen (state Active)`,
  `bond still 500 QCH, fully escrowed`,
  `the restarted node re-derived the FROZEN state from disk`,
  `both nodes agree on head_hash d99bd87c63f85de4…`.
- **Determinismo / no-fork a nivel de ejecución:**
  `the_whole_key_lifecycle_is_deterministic_across_nodes` — dos ledgers
  independientes con la misma secuencia terminan con el mismo
  `economic_state_root` (hash independiente del orden de lectura).
- **Conservación:** `the_bond_is_conserved_across_the_adversarial_lifecycle` — el
  bono ni se acuña ni se destruye con el atacante dentro.
- **Estado compuesto:**
  `a_validator_revoked_while_frozen_keeps_its_bond_parked_until_the_committee_lifts_the_pause`.
- **Aislamiento de autorización:**
  `a_recovery_approval_is_bound_to_one_validator_and_cannot_cross_over`.

## Clase de error registrada

**EC-17** — *un control de PAUSA gateado en una decisión, no en toda su
superficie* → [`../LESSONS-LEDGER.md`](../LESSONS-LEDGER.md#ec-17--un-control-de-pausa-gateado-en-una-decisión-no-en-toda-su-superficie),
con su barrido manual sobre todos los demás controles de pausa/bloqueo del repo
(`Revoked`, `Jailed`, expiry/revoke de #20, `EmergencyPause` de gobernanza, guards
del firmante remoto) — todos verificados cubiertos o con alcance correcto y
documentado.

**Pregunta recurrente que esta auditoría deja instalada:** *para cada control que
se llame pausa, freeze, lock o bloqueo — ¿qué instrucciones se siguen aceptando
mientras está activo, y alguna de ellas mueve dinero, cambia una clave o avanza un
timelock? ¿Y hay alguna que quede bloqueada y no debería (el escape hatch de quien
puede levantarlo)?*

## Límite honesto

El harness prueba **ejecución** multinodo (no-fork por comparación de roots, y los
rechazos on-chain). No sustituye al DST de **consenso** (`qchain-simulation`), que
es ortogonal y no se ve afectado por este cambio: `qchain-simulation` depende de
core/crypto/consensus y **no** de `qchain-execution`. Los actores bizantinos a
nivel de consenso (equivocación, pérdida de certs) siguen cubiertos por el DST.
