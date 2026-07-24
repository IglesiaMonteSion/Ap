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
| 1 | **Crítico** | Falsificación de propuesta de gobernanza: `read_proposal` decodifica cualquier cuenta sin owner/dirección/magic; `CreateProposal` acepta dirección arbitraria; `passed_round + timelock` puede desbordar | EC-01, EC-05 | **P0** | ✅ **CORREGIDO (v8.6.18)** — owner check + dirección canónica + saturating timelock + 2 tests de exploit + sweep EC-01 limpio |
| 2 | **Crítico** | Gate de arranque de tesorería usa un decodificador DISTINTO al del runtime → puede brickear una red viva al actualizar | EC-02, EC-07, EC-09 | **P0** | ✅ **CORREGIDO (v8.6.18)** — `TreasuryState::decode_any_version` único, compartido gate+runtime |
| 3 | **Alto** | `TreasuryStateV0` (migración) reusa el enum `PendingOp` NUEVO → no representa el formato histórico (regresión introducida en #17) | EC-02, EC-09 | **P0** | ✅ **CORREGIDO (v8.6.18)** — `TreasuryOpV0`/`PendingOpV0` históricos exactos + conversión + test |
| 4 | **Alto** | Firmante remoto: `SignPeerVote` no pasa por la guardia anti-doble-firma; el daemon no autentica la identidad del cliente | EC-06 | P1 | por verificar |
| 5 | Medio | Mezcla de aritmética de expiración/timelock de ops de tesorería sin `checked_*` / invariante | EC-05 | P1 | ✅ **YA CERRADO** (v8.6.18 verificado) — `saturating_add` + `arith::checked` + invariante `expiry>timelock` desde #17/#218 |
| 6 | Medio | `Cancel` de tesorería ejecutable por un solo firmante → un firmante puede paralizar el multisig | EC-10 | P1 | ✅ **CORREGIDO (v8.6.18)** — `Cancel` proponente-only + test |
| 7 | Medio | `tx.version` va firmado pero NO se rechaza en la ejecución comprometida (sólo se asume) | EC-08, EC-02 | P1 | ✅ **CORREGIDO (v8.6.18)** — `CURRENT_TX_VERSION` re-verificado en `apply` + test |
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

## #1 — Falsificación de propuesta de gobernanza (Crítico) — ✅ CORREGIDO (v8.6.18)

**Estado:** cerrado. `read_proposal` exige `owner == GOVERNANCE_PROGRAM_ID`;
`CreateProposal` exige la dirección canónica `derive_proposal_address(proposer,
id)`; el time-lock usa `saturating_add` (fail-closed). Dos tests de exploit
(`a_forged_passed_proposal_in_a_non_governance_account_cannot_be_executed`,
`create_proposal_requires_the_canonical_address`) + barrido EC-01 limpio (todos
los demás lectores privilegiados usan un id de singleton fijo o pinnean el owner).
El CLI deriva la dirección canónica en sus 8 comandos `propose-*`. 235 tests de
execution en verde, clippy limpio. Byte-idéntico para toda propuesta legítima; el
enforcement de dirección canónica en `CreateProposal` es un cambio coordinado
node+CLI (la wallet nunca crea propuestas). Detalle en LESSONS-LEDGER EC-01.

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

**Barrido de clase (EC-01):** hecho — ver LESSONS-LEDGER EC-01. Sweep limpio.

**Límite honesto (magic/version diferido):** el owner check + dirección canónica
cierran la falsificación POR CONSTRUCCIÓN (un atacante no puede producir una
cuenta governance-owned con datos arbitrarios, y la dirección es determinista).
Un `magic|version` antepuesto en la struct `Proposal` es defensa-en-profundidad
adicional pero cambia el FORMATO persistido de una cuenta viva → requiere su
propia migración tolerante + fixtures binarios reales (la clase EC-09 que este
mismo audit ataca en #2/#3). Se difiere a un incremento propio para NO introducir
un bug de migración nuevo dentro del fix crítico — la regla "si no hay una
optimización segura mejor no se hace nada".

## #2 — Gate de arranque de tesorería ≠ decodificador de runtime (Crítico) — ✅ CORREGIDO (v8.6.18)

**Confirmado leyendo el código:** el gate (`ledger.rs:1318`) decodificaba con
`TreasuryState::try_from_slice` (SÓLO el layout actual) mientras el runtime
`read_state` (`treasury_v7.rs`) usa `read_or_legacy` (que ACEPTA además el layout
pre-#17). Un blob pre-#17 (multisig sin los 3 campos de tier/expiry) FALLA
`try_from_slice` (borsh EOF) y no es de 32 bytes → **el gate haltea** = brick al
actualizar, aunque el runtime lo migraría (clase EC-09; precedente: brick de
#8.2.2). El propio `deploy/qsep-sweep.sh EC-01` destapó el sitio exacto.

**Fix:** `TreasuryState::decode_any_version` — el ÚNICO decodificador (current →
pre-#17 `read_or_legacy` → 32-byte authority) — compartido por el gate y
`read_state`. Test `decode_any_version_accepts_every_live_layout_and_rejects_garbage`.

## #3 — `TreasuryStateV0` reusaba el enum nuevo (Alto) — ✅ CORREGIDO (v8.6.18)

**Confirmado:** `TreasuryStateV0.pending` era `Vec<PendingOp>` con el `PendingOp`/
`TreasuryOp` ACTUALES. `TreasuryOp` CAMBIÓ en #17 (`SetSigners` pasó de 2 a 4
campos; `SetPolicy` ganó `op_expiry_rounds`), así que decodificar los bytes
pre-#17 de un pending `SetSigners`/`SetPolicy` con el enum nuevo MISPARSEA (el
layout de bytes difiere).

**Fix:** `TreasuryOpV0` (Release / SetSigners{signers,threshold} /
SetPolicy{4 campos}) + `PendingOpV0` — copias históricas EXACTAS (mismo orden de
variantes; #17 sólo apéndió campos) — con conversión variante-por-variante
`into_current()` (tiers = threshold de la op, expiry = 0). Test de regresión
`a_pre17_treasury_with_pending_ops_migrates_each_op_exactly` construye los bytes
pre-#17 reales (vía los tipos V0) y confirma que cada op migra exacta; falla sin
el fix. **Límite honesto:** el fixture es sintético-pero-real (se serializan los
tipos V0, que SON el layout pre-#17 byte-a-byte); no se pudo linkear un test de
integración de reinicio en el sandbox (ENOSPC, documentado en #20), pero la
migración está cubierta por este unit test + `decode_any_version`.

## #4 — Firmante remoto: guardia y autenticación (Alto)

Ver EC-06. `SignPeerVote` debe pasar por la misma guardia anti-doble-firma
persistida (fsync) que el auto-voto; el daemon debe autenticar la identidad del
cliente (no basta alcanzar su dirección de red). Allowlist estricta ya existe
(#193) — verificar que cubre este camino.

## #5 — Aritmética expiración/timelock (Medio) — ✅ YA CERRADO (verificado v8.6.18)

Verificado en código: `prune_expired` (`current_round <= proposed_round.saturating_add(expiry)`),
`ready_round` (`threshold_reached_round.saturating_add(timelock)`) y la ventana
rodante usan `saturating_add`; los movimientos de fondos usan `arith::sub_u64`/
`add_u64` (checked, rechazan la transición). El invariante `op_expiry_rounds >
timelock_rounds` se valida en génesis y en `validate_op` de `SetPolicy`. No hay
`+`/`-`/`*` crudo sobre round/amount/expiry en el módulo (barrido EC-05). Cerrado
por #17/#218; sin cambio de código necesario.

## #6 — `Cancel` de un solo firmante (Medio) — ✅ CORREGIDO (v8.6.18)

Confirmado: `cancel` sólo exigía `require_signer` → cualquier firmante cancelaba
cualquier op. Fix: sólo el PROPONENTE (primer aprobador, `approvals[0]`) puede
cancelar su op; una op abandonada se reaje por expiración o la descarta un
`SetSigners`, así que no hace falta cancelación cruzada. Test
`only_the_proposer_can_cancel_a_pending_op`. Barrido EC-10 limpio.

## #7 — `tx.version` no enforzado en ejecución (Medio) — ✅ CORREGIDO (v8.6.18)

Confirmado: `tx.version` no se chequeaba en ninguna parte (ni admisión ni
ejecución). Fix: `pub const CURRENT_TX_VERSION: u8 = 1` en `qchain-core` +
chequeo en `apply_transaction_inner` (el choke point de RPC/simulate/commit). Un
proposer bizantino no puede colar una tx de versión desconocida en su batch;
determinista, byte-idéntico en el camino honesto. Test
`a_transaction_with_an_unsupported_version_is_rejected_at_execution` (tx v2
válidamente firmada rechazada por el gate de versión). Barrido EC-08 limpio.

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
