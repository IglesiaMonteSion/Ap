# Auditoría externa — commit v8.6.13 (rastreador de hallazgos)

**Fuente.** Auditoría externa independiente entregada por el operador sobre el
commit v8.6.13 (jerarquía de umbrales de tesorería + expiración de ops, #17).
Este archivo es el **rastreador de corrección**: cada hallazgo se mapea a su
clase de error (`../LESSONS-LEDGER.md`), su estado, la prueba de explotación
planeada, y el barrido de la clase. El texto canónico completo de cada hallazgo
es el que entregó el operador; acá se registra el trabajo.

**Conteo.** 2 Críticos · 2 Altos · 4 Medios · 3 Bajos = 11.

> Disciplina (QSEP-1 §13 + LESSONS-LEDGER): un hallazgo se cierra sólo con
> (1) parche, (2) prueba de explotación que falla sin el fix, (3) causa raíz en
> el ledger, (4) barrido de TODA la clase en el repo con la lista de sitios.

## Tabla de hallazgos

| # | Sev | Título | Clase(s) | Prioridad | Estado |
|---|-----|--------|----------|-----------|--------|
| 1 | **Crítico** | Falsificación de propuesta de gobernanza: `read_proposal` decodifica cualquier cuenta sin owner/dirección/magic; `CreateProposal` acepta dirección arbitraria; `passed_round + timelock` puede desbordar | EC-01, EC-05 | **P0** | CONFIRMADO — en corrección |
| 2 | **Crítico** | Gate de arranque de tesorería usa un decodificador DISTINTO al del runtime → puede brickear una red viva al actualizar | EC-02, EC-07, EC-09 | **P0** | por verificar |
| 3 | **Alto** | `TreasuryStateV0` (migración) reusa el enum `PendingOp` NUEVO → no representa el formato histórico (regresión introducida en #17) | EC-02, EC-09 | **P0** | por verificar |
| 4 | **Alto** | Firmante remoto: `SignPeerVote` no pasa por la guardia anti-doble-firma; el daemon no autentica la identidad del cliente | EC-06 | P1 | por verificar |
| 5 | Medio | Mezcla de aritmética de expiración/timelock de ops de tesorería sin `checked_*` / invariante | EC-05 | P1 | por verificar |
| 6 | Medio | `Cancel` de tesorería ejecutable por un solo firmante → un firmante puede paralizar el multisig | EC-10 | P1 | por verificar |
| 7 | Medio | `tx.version` va firmado pero NO se rechaza en la ejecución comprometida (sólo se asume) | EC-08, EC-02 | P1 | por verificar |
| 8 | Medio | Shamir de la wallet: checksum de 16 bits → 1/65536 de reconstruir una semilla equivocada que pasa la validación; sin id de grupo/consistencia K-N fuerte | EC-15 | P1 | por verificar |
| 9 | Bajo | *(ver texto canónico del operador)* | por mapear | P2 | pendiente de mapear |
| 10 | Bajo | Parámetros Argon2id (m/t/p) leídos del blob de respaldo sin topes → DoS de descifrado | EC-14 | P2 | por verificar |
| 11 | Bajo | `byte_size()` no cuenta todo el framing borsh del wire → fee/cap inexacto | EC-13 | P2 | por verificar |

## Orden de corrección

- **P0 (fondos/consenso, ahora):** #1, #2, #3, + endurecer el borde WASM para que
  una cuenta program-owned no pueda mutar su `data` sólo por ser firmante (defensa
  en profundidad de #1).
- **P1 (autoridad/DoS acotado):** #4, #5, #6, #7, #8.
- **P2 (endurecimiento):** #9, #10, #11.

---

## #1 — Falsificación de propuesta de gobernanza (Crítico) — CONFIRMADO

**Verificado leyendo el código** (`crates/qchain-execution/src/governance.rs`):
- `read_proposal` (línea 102) hace `Proposal::read_or_legacy(&account.data)` y
  **no** verifica `account.owner == GOVERNANCE_PROGRAM_ID`, ni dirección
  canónica, ni magic/versión. Cualquier cuenta cuyos bytes decodifiquen como
  `Proposal` es aceptada.
- `CreateProposal` toma `proposal_pk = accounts[1]` (provisto por el usuario) y
  sólo chequea `if accounts.contains_key(&proposal_pk)` (línea 178); la cuenta
  legítima se crea `Account::new_wallet(GOVERNANCE_PROGRAM_ID)` (línea 219) — sin
  dirección derivada.
- El vector de composición: el borde WASM permite a un firmante escribir el
  `data` de su PROPIA cuenta; una cuenta así, con bytes que decodifican como una
  `Proposal` ya "Passed", podría ser ejecutada por `Execute` sin pasar por
  votación real si el lector no valida owner/dirección/magic.
- `passed_round + timelock_rounds` (ruta de `Execute`) sin `checked_add` → con un
  `passed_round` adversario cercano a `u64::MAX`, panic-halt determinista
  (EC-05).

**Fix (P0):**
1. Dirección canónica de propuesta:
   `SHA3-256("qchain-governance-proposal-v1" || proposer || proposal_id)`.
   `CreateProposal` deriva la dirección y RECHAZA `accounts[1]` que no coincida.
2. `read_proposal` (helper canónico único) verifica: `owner ==
   GOVERNANCE_PROGRAM_ID` **Y** dirección canónica **Y** `magic == MAGIC` **Y**
   `version == V` antes de confiar en los bytes.
3. `Proposal` gana `magic`/`version` explícitos (formato nuevo; `read_or_legacy`
   migra los viejos y los re-sella al escribir).
4. `checked_add` en `passed_round + timelock_rounds` (y todo cálculo de
   ronda/tiempo de la ruta) → overflow rechaza la transición.
5. Borde WASM: una cuenta program-owned NO puede tener su `data` mutado por ser
   sólo firmante (defensa en profundidad).

**Prueba de explotación (debe fallar sin el fix):** construir una cuenta
`GOVERNANCE_PROGRAM_ID`-owned en una dirección NO canónica con bytes de una
`Proposal` "Passed" y confirmar que `Execute` la RECHAZA; y una propuesta con
`passed_round ≈ u64::MAX` no hace panic.

**Barrido de clase (EC-01):** listar cada lector de cuenta privilegiada
(gobernanza/tesorería/registro v7/emergencia/params/staking) y demostrar
owner+dirección+magic+versión en cada uno.

## #2 — Gate de arranque de tesorería ≠ decodificador de runtime (Crítico)

**Hipótesis (del audit):** `validate_critical_singletons`/el gate de arranque
decodifica la cuenta de tesorería con un camino distinto al que usa el runtime
(`treasury_v7::read_state`/`read_or_legacy`), así que una red viva cuya tesorería
está en un formato que el runtime tolera pero el gate no, se **brickea** al
actualizar (clase EC-09 + EC-02; precedente directo: el brick de #8.2.2).

**Fix (P0):** un único `TreasuryState::decode_any_version` compartido por
arranque, runtime, inspección, migración y state-sync. El gate usa EXACTAMENTE
ese decodificador.

**Por verificar en código** antes de parchar (QSEP-1: verify-before-patch):
ubicar el gate y `read_state`, confirmar que difieren.

## #3 — `TreasuryStateV0` reusa el enum nuevo (Alto)

**Hipótesis (del audit):** la struct histórica `TreasuryStateV0` (ruta de
migración legacy→#17) referencia el enum `PendingOp` ACTUAL en vez de una copia
histórica exacta `PendingOpV0`/`TreasuryOpV0`, así que "el formato viejo" que
pretende decodificar no es el que realmente se publicó → migración incorrecta
(clase EC-09).

**Fix (P0):** structs históricas EXACTAS (`TreasuryStateV0`/`PendingOpV0`/
`TreasuryOpV0` tal como se publicaron antes de #17) + conversión
variante-por-variante + un fixture binario REAL de la versión anterior + prueba
de migración + reinicio.

## #4 — Firmante remoto: guardia y autenticación (Alto)

Ver EC-06. `SignPeerVote` debe pasar por la misma guardia anti-doble-firma
persistida (fsync) que el auto-voto; el daemon debe autenticar la identidad del
cliente (no basta alcanzar su dirección de red). Allowlist estricta ya existe
(#193) — verificar que cubre este camino.

## #5 — Aritmética expiración/timelock (Medio)

Ver EC-05. Invariante `op_expiry_rounds > timelock_rounds` ya existe (#17);
verificar que TODA la aritmética de `proposed_round + expiry` / `+ timelock` usa
`checked_*` y que no hay un camino donde una op caduque antes de poder ejecutarse
legítimamente.

## #6 — `Cancel` de un solo firmante (Medio)

Ver EC-10. `Cancel` debería exigir el mismo umbral que la clase de op que
cancela (o al menos que sólo el proponente / un umbral pueda), para que un
firmante comprometido no pueda paralizar el multisig cancelando todo.

## #7 — `tx.version` no enforzado en ejecución (Medio)

Ver EC-08. Re-verificar `tx.version` en `apply` comprometido, no sólo en
admisión/gossip.

## #8 — Shamir de la wallet (Medio)

Ver EC-15. Subir el checksum a ≥128 bits, id de grupo de 128 bits, exigir mismo
K/N/id, rechazar x=0, límites K/N, vectores de prueba; o migrar a un estándar
auditado. No afirmar interop SLIP-39 si el protocolo difiere.

## #10 — Argon2 sin topes (Bajo)

Ver EC-14. Clampar m/t/p del blob de respaldo a un rango documentado; aceptar los
valores legítimos históricos (19456 KiB / 2 / 1).

## #11 — `byte_size()` inexacto (Bajo)

Ver EC-13. Unificar el tamaño-wire a `borsh::to_vec(tx).len()` en
transporte/mempool/cobro.
