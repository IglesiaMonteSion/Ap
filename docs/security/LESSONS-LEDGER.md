# QChain — Libro Mayor de Clases de Error (Lessons Ledger)

**Propósito.** Que de CADA hallazgo se aprenda una vez y para siempre. Este
archivo es la memoria de **clases** de error (no de instancias sueltas): cada
vez que aparece un bug de seguridad, se clasifica aquí, se registra su causa
raíz, la regla que lo cierra, cómo se detecta automáticamente, y **la pregunta
que toda auditoría futura DEBE volver a responder**. Ninguna auditoría se cierra
sin recorrer las 15 clases de abajo y demostrar (con test o grep) que cada una
sigue cerrada.

> Regla operativa (QSEP-1 §13, obligatoria): un hallazgo NO está resuelto cuando
> se corrige la línea. Está resuelto cuando: (1) hay parche, (2) hay prueba de
> regresión que reproduce el fallo exacto, (3) hay causa raíz en este ledger,
> (4) se barrió TODA la clase en el repo (`deploy/qsep-sweep.sh`) y se listó cada
> sitio revisado. El barrido se corre en cada cambio R2/R3 y en cada auditoría.

## Cómo se usa

1. **Al empezar un cambio** (AGENTS.md): leer las clases relevantes; el diseño
   debe cerrar por construcción las que toca.
2. **Al encontrar un bug**: buscar si encaja en una clase existente (casi
   siempre sí — es la señal de que es recurrente). Si es nueva, agregar `EC-NN`.
   Registrar la instancia, el parche, el test, y **volver a barrer el repo** por
   esa clase.
3. **Al cerrar una auditoría**: correr `deploy/qsep-sweep.sh` + responder la
   "pregunta recurrente" de cada clase con evidencia (test/grep/línea).
4. **Comparación con errores previos** (lo que pidió el operador): la columna
   *Instancias* acumula cada reaparición con su commit; si una clase reaparece,
   es prueba de que su *enforcement* no fue universal → se endurece el detector,
   no sólo el sitio.

---

## Índice de clases

| ID | Clase | Enforcement automatizable | Estado |
|---|---|---|---|
| EC-01 | Autenticidad de cuenta privilegiada no forzada | parcial (grep de lecturas sin owner-check) | **CERRADA-VIGILADA** (v8.6.13 #1 corregido v8.6.18; sweep limpio) |
| EC-02 | Detección de versión por "trial-borsh" | sí (grep de decoders en cascada / structs `*V0`) | **PARCIAL** (#2 gate=runtime corregido v8.6.18; #7 pendiente) |
| EC-03 | Se arregla la instancia, no la CLASE | proceso (este ledger + sweep) | permanente |
| EC-04 | Crecimiento de recurso sin cota | parcial | cerrada-vigilada (#18) |
| EC-05 | Aritmética de dinero/ronda/tiempo sin `checked_*` | sí (grep en módulos de valor) | **CERRADA-VIGILADA** (#1 timelock corregido v8.6.18; #5 ya cerrado por #17/#218) |
| EC-06 | Falta separación de dominio de firma / guardia con camino hermano no guardado | parcial | **CERRADA-VIGILADA** (#187; #4 SignPeerVote corregido v8.6.20) |
| EC-07 | No-determinismo / riesgo de fork | proceso (DST) | cerrada-vigilada |
| EC-08 | La interfaz como frontera de seguridad | parcial (grep de `.version` no comparada) | **CERRADA-VIGILADA** (#7 tx.version corregido v8.6.18; sweep hecho) |
| EC-09 | Peligros de migración (struct nueva para formato viejo; gate ≠ runtime) | sí | **CERRADA-VIGILADA** (#2/#3 corregidos v8.6.18; sweep hecho) |
| EC-10 | Hueco de autorización en flujo privilegiado | parcial | **CERRADA-VIGILADA** (#6 Cancel corregido v8.6.18; sweep hecho) |
| EC-11 | Sesgo de test al camino feliz / al modelo de amenazas propio | proceso | permanente |
| EC-12 | Punto ciego del auditor = autor/mismo modelo | proceso (revisión externa) | permanente |
| EC-13 | Tamaño-wire / cobro de fee inexacto | sí | **ABIERTA** (#11) |
| EC-14 | Parámetro controlado externamente sin topes | parcial | **ABIERTA** (#10) |
| EC-15 | Cripto/recuperación propia con checksum/estándar insuficiente | no (revisión manual) | **CERRADA-VIGILADA** (#8 Shamir v2: chk 136-bit + id de grupo, corregido v8.6.21) |

---

## EC-01 — Autenticidad de cuenta privilegiada no forzada

- **Clase:** leer/confiar en una cuenta por su FORMA (los bytes decodifican) sin
  exigir **propietario canónico + dirección canónica + magic + versión + prueba
  de que fue creada por el flujo legítimo**.
- **Causa raíz:** se fijó "pinnear la cuenta canónica / chequear owner" para
  casos ESPECÍFICOS pero nunca como regla UNIVERSAL en el borde de lectura de
  toda cuenta privilegiada. Cada lector nuevo escrito sin esa disciplina reabre
  la clase.
- **Instancias:**
  - v8.6.13 #1 (CONFIRMADO leyendo el código + exploit reproducido → CORREGIDO en
    v8.6.18): `governance::read_proposal` decodificaba cualquier cuenta como
    `Proposal` sin owner/dirección/magic. **Exploit end-to-end verificado:** un
    firmante escribe bytes de una `Proposal` "Passed" en su PROPIA cuenta
    (system-owned) vía el borde WASM `host_set_data` (ledger.rs:2762) y llama
    `Execute` → aplicaba la acción SIN votación. **Fix:** `read_proposal` exige
    `owner == GOVERNANCE_PROGRAM_ID` (una cuenta program-owned por gobernanza sólo
    la crea `CreateProposal` con una propuesta `Voting`; el borde WASM NUNCA puede
    poner owner=gobernanza); `CreateProposal` exige la dirección canónica
    `derive_proposal_address(proposer,id)` = SHA3-256(dominio‖proposer‖id);
    `passed_round + timelock` → `saturating_add` (EC-05, fail-closed). Byte-idéntico
    para toda propuesta legítima (todas son governance-owned). Tests de explotación:
    `a_forged_passed_proposal_in_a_non_governance_account_cannot_be_executed`,
    `create_proposal_requires_the_canonical_address`.
  - Precedentes parciales del MISMO patrón (arreglados sólo para su sitio):
    Finalize/Execute pinnean los singletons destino (v2.0.4); reward pool en
    Delegate/Undelegate/ClaimReward (#172); lista `RESERVED` de singletons en
    Stake v7 (#210/audit v6.3.25); cuenta de tesorería (#222). Ninguno cerró la
    clase para el lector de la PROPIA cuenta de propuesta.
- **Barrido de la clase (v8.6.18, QSEP-1 §13):** enumerados TODOS los lectores de
  cuenta privilegiada. La cuenta de propuesta era el ÚNICO caso con dirección
  **provista por el usuario** (`accounts[1]`) leída por forma sin owner-check.
  Todos los demás usan un **id de singleton FIJO** (canónico por construcción, y
  program-owned → el borde WASM no puede reescribir su `data`): treasury
  `read_state`→`TREASURY_ACCOUNT_ID`; params `PARAMS_ACCOUNT_ID`; crypto-registry
  `REGISTRY_ACCOUNT_ID`; validator-v7 `decode_registry`→`VALIDATOR_REGISTRY_ACCOUNT_ID`
  (todos los handlers #20 pinnean `registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID`);
  emergency `EMERGENCY_ACCOUNT_ID`; staking global/stats/pool por id fijo. El único
  otro lector de una cuenta de dirección user-supplied es `Vote`, que ya pinnea
  `owner == STAKING_PROGRAM_ID` (governance.rs:246). **Sweep limpio.**
- **Regla que lo cierra (invariante universal):** antes de leer o mutar una
  cuenta con significado privilegiado, verificar en UN helper canónico:
  `owner == PROGRAMA_ESPERADO` **Y** `address == derive_canónica(...)` **Y**
  `magic == MAGIC_ESPERADO` **Y** `version == VERSION_ACTUAL`. Una cuenta
  program-owned NO debe poder mutar su `data` sólo por ser firmante (endurecer
  el borde WASM).
- **Detección (sweep):** flaggea toda llamada a `read_or_legacy`/`try_from_slice`
  sobre una cuenta de un programa privilegiado (governance/treasury/validator/
  staking/emergency) que no esté precedida por un chequeo de `owner`.
- **Pregunta recurrente de auditoría:** *para CADA cuenta privilegiada que el
  código lee (propuesta, tesorería, registro, emergencia, params, staking): ¿se
  verifica owner canónico + dirección canónica + magic + versión ANTES de
  confiar en sus bytes? Listar cada sitio.*

## EC-02 — Detección de versión por "trial-borsh"

- **Clase:** determinar el formato probando decodificadores en orden y cayendo
  al primero que no falla, en vez de un encabezado explícito `magic|version|
  payload`. Se agrava cuando dos caminos (arranque vs runtime) usan decodificadores
  DISTINTOS, o cuando una struct "histórica" `*V0` embebe el enum NUEVO.
- **Causa raíz:** `read_or_legacy` fue cómodo y se generalizó sin un byte de
  versión persistido; #19 lo mitigó a nivel de singleton (manifiesto) pero los
  caminos por-struct siguen adivinando.
- **Instancias (v8.6.13):** #2 (CORREGIDO v8.6.18) el gate de arranque de tesorería
  usaba `TreasuryState::try_from_slice` mientras el runtime usa `read_or_legacy`
  → un blob pre-#17 (multisig sin tiers) pasaba el runtime pero el gate lo
  rechazaba = **brick al actualizar**. Fix: `TreasuryState::decode_any_version`,
  el ÚNICO decodificador, compartido por gate (`ledger.rs`) y runtime
  (`read_state`). #3 (CORREGIDO v8.6.18) `TreasuryStateV0.pending` reusaba el
  `PendingOp`/`TreasuryOp` NUEVO; como `TreasuryOp` CAMBIÓ en #17 (`SetSigners`
  ganó 2 campos, `SetPolicy` ganó `op_expiry_rounds`), un pending SetSigners/
  SetPolicy pre-#17 misparseaba. Fix: `TreasuryOpV0`/`PendingOpV0` históricos
  EXACTOS + conversión variante-por-variante. #7 `tx.version` firmado pero no
  enforzado (P1, pendiente).
- **Barrido (v8.6.18):** (a) **gate = runtime** para TODOS los singletons —
  treasury ahora comparte `decode_any_version`; validator-registry usa
  `decode_registry` en gate y runtime (#20); params/fee-state/crypto-registry/
  staking-global/pool/emergency usan el MISMO `read_or_legacy`/`try_from_slice`
  en el gate (`ledger.rs:1262-1320`) que su lector de runtime. Sólo treasury
  difería → cerrado. (b) **structs `*V0` que embeben un tipo cambiado:**
  `TreasuryStateV0` era el único con un enum interno cambiado (TreasuryOp) →
  corregido. `ProposalV0` (governance) embebe `ProposalAction`/`ProposalStatus`,
  que desde su cutover (#16) sólo AGREGARON variantes (nunca cambiaron los campos
  de una variante existente) → hoy decodifica correcto, pero **LATENTEMENTE
  frágil**: si alguna vez se agrega/cambia un CAMPO de una variante existente de
  `ProposalAction`/`ProposalStatus`, hay que congelar un `ProposalActionV0`
  (misma lección que TreasuryOp). `StakeAccountDataLegacy`/`EconomicParams`/
  `FeeState` sólo apéndan campos escalares → seguros.
- **Regla que lo cierra:** UN único decodificador canónico (`decode_any_version`)
  compartido por arranque/runtime/inspección/migración/state-sync. Todo formato
  persistente lleva `magic|version` explícito; las structs históricas se
  preservan EXACTAS como se publicaron (enum histórico propio, no el nuevo).
- **Detección (sweep):** flaggea funciones con ≥2 `try_from_slice` en cascada; y
  structs `*V0`/`*Legacy` que referencian tipos no-`*V0`.
- **Pregunta recurrente:** *¿el gate de arranque y el runtime usan EXACTAMENTE
  el mismo decodificador? ¿existe un fixture binario real de cada versión y una
  prueba de migración+reinicio desde él?*

## EC-03 — Se arregla la instancia, no la CLASE

- **Clase (meta):** cerrar la línea reportada sin barrer el repo por la misma
  clase. Es la razón #1 por la que los bugs "vuelven".
- **Enforcement:** este ledger + `qsep-sweep.sh` corrido en cada cambio y
  auditoría; el PR debe listar "sitios barridos por EC-NN".
- **Pregunta recurrente:** *para cada hallazgo, ¿se corrió el sweep de su clase y
  se listaron TODOS los sitios de esa clase, no sólo el reportado?*

## EC-04 — Crecimiento de recurso sin cota

- **Clase:** estructura/loop/asignación sin cota explícita → OOM/DoS.
- **Instancias:** #18 (auditoría formal), #103 (blowup 6.6GB), caches de batches,
  mapas de votos/pedidos, snapshot pages (#109).
- **Regla:** toda estructura controlable externamente tiene cota (constante +
  dónde se fuerza), documentada en `RESOURCE-LIMITS.md`.
- **Detección:** parcial (revisión); el sweep lista `Vec`/`HashMap` públicos sin
  cap cercano en módulos de red/mempool.
- **Pregunta recurrente:** *¿toda entrada externa tiene un límite de tamaño/
  cantidad/profundidad/tiempo/memoria/iteraciones/conexiones?*

## EC-05 — Aritmética de valor sin `checked_*`

- **Clase:** `+`/`-`/`*` sobre fondos/rondas/tiempos/pesos que puede desbordar
  silenciosamente (o panic-halt determinista en release con overflow-checks).
- **Instancias:** #132 (fee add panic), #218 (módulo `arith`), v8.6.13 #1
  (`passed_round + timelock` → panic con `passed_round` ≈ u64::MAX; CORREGIDO
  v8.6.18 con `saturating_add`), #5 (aritmética expiración/timelock de tesorería —
  **ya cerrado**: `prune_expired`/`ready_round`/ventana usan `saturating_add`, los
  movimientos de fondos usan `arith::sub_u64/add_u64` checked, y el invariante
  `op_expiry_rounds > timelock_rounds` se valida en génesis y en `SetPolicy`;
  verificado por barrido — sin `+`/`-`/`*` crudo sobre round/amount/expiry en el
  módulo).
- **Regla:** `checked_add/sub/mul/div` (o `saturating_*` documentado en no-dinero)
  en TODO cálculo de valor/ronda/tiempo; un overflow rechaza la transición.
- **Detección (sweep):** grep de `+`/`-`/`*` sin `checked_`/`saturating_` en
  archivos de tesorería/gobernanza/fees/staking/economía/ledger sobre variables
  de round/amount/timelock/expiry.
- **Pregunta recurrente:** *¿todo cálculo de dinero/ronda/tiempo usa aritmética
  comprobada, incluso con inputs adversarios cercanos a los extremos?*

## EC-06 — Falta separación de dominio de firma

- **Clase:** una firma válida para un propósito reutilizable en otro.
- **Instancias:** #187 (dominios `TX_SIG_V1`/`VERTEX_VOTE_V1`/`VALIDATOR_POP_V1`);
  allowlist del firmante remoto (#193).
  - v8.6.13 #4 (CONFIRMADO leyendo el código → CORREGIDO en v8.6.20): la
    `DoubleSignGuard` sólo cubría `SignOwnVote`; `SignPeerVote` alcanzaba la MISMA
    primitiva `sign_vertex_vote` SIN guardia → un nodo comprometido enrutaba su
    segundo vértice propio por ahí y auto-equivocaba (slasheable). Sub-patrón:
    **guardia efectiva en un camino, pero un camino HERMANO no guardado llega a la
    misma primitiva** — y `SignPeerVote` confiaba en la autoría por el NOMBRE del
    camino ('peer') en vez de PROBARLA. **Fix:** `SignPeerVote` recibe los bytes
    del vértice; el daemon recomputa el digest y rehúsa si `author == su clave`
    (un auto-voto debe ir por el camino guardado). Test:
    `sign_peer_vote_refuses_our_own_vertex_closing_the_self_equivocation_bypass`.
    **Diferido (follow-up):** autenticar la IDENTIDAD del cliente (token/mTLS) para
    bind no-loopback — el default loopback + el rehúso de auto-equivocación/valor
    ya acotan al socket-reacher.
- **Regla:** todo contenido firmado lleva dominio + tipo + chain_id + versión +
  nonce/caducidad según corresponda; el firmante remoto aplica allowlist por
  identidad de cliente + anti-replay. **Y toda guardia sobre una primitiva de
  firma cubre TODOS los caminos que la alcanzan (no un solo camino): si un camino
  asume 'esto es de otro' (peer), debe PROBARLO recomputando/verificando la
  autoría, no confiar en el nombre del camino.**
- **Pregunta recurrente:** *¿cada firma nueva tiene dominio único? ¿el firmante
  remoto puede firmar algo fuera de una allowlist estricta autenticada? ¿alguna
  guardia (anti-doble-firma, anti-replay) tiene un camino HERMANO sin guardar que
  llegue a la misma primitiva?*

## EC-07 — No-determinismo / riesgo de fork

- **Clase:** consenso/ejecución que depende de reloj/RNG/orden-de-mapa/float/
  nº-núcleos, o un decodificador que diverge y cambia el state root.
- **Instancias:** #106, #133, #4.0.4, #195; v8.6.13 #2 (dos decodificadores de
  tesorería → distinto arranque entre nodos).
- **Regla:** todo lo que alimenta consenso es función pura del estado
  comprometido; verificado por el DST (`qchain-simulation`).
- **Pregunta recurrente:** *¿algún camino comprometido depende de algo no
  determinista, o dos nodos con el mismo estado pueden decodificar distinto?*

## EC-08 — La interfaz como frontera de seguridad

- **Clase:** confiar en que wallet/RPC/mempool aplican una regla que el nodo debe
  re-verificar en la ejecución comprometida (un validador bizantino los saltea).
- **Instancias:** v8.6.13 #7 (CORREGIDO v8.6.18): `tx.version` iba firmado pero
  NO se rechazaba en la ejecución comprometida → un proposer bizantino podía
  colar una tx de versión desconocida/futura en su batch. Fix: `CURRENT_TX_VERSION`
  en `qchain-core` + chequeo en `apply_transaction_inner` (el choke point único de
  RPC/simulate/commit-loop). Determinista (versión en la tx comprometida) →
  byte-idéntico en el camino honesto (toda tx real es v1). Test
  `a_transaction_with_an_unsupported_version_is_rejected_at_execution` (una tx v2
  VÁLIDAMENTE FIRMADA es rechazada por el gate de versión, no por firma).
- **Regla:** toda regla de aceptación se re-verifica en `apply` comprometido, no
  sólo en RPC/gossip/mempool.
- **Barrido (v8.6.18):** las reglas que afectan estado/consenso se re-verifican
  en `apply_transaction`: `chain_id` (en `try_commit` antes de aplicar, v5.8.1),
  expiración `valid_until_round` (#191), `version` (#7), `fee_limit` (#87), nonce y
  solvencia. Las reglas SÓLO-mempool restantes (`MAX_TRANSACTION_BYTES`,
  rate-limits, cuota de admisión) son cotas de DoS que no afectan la corrección
  del estado comprometido (una tx grande igual se cobra por byte) → correctamente
  no se re-verifican en ejecución. Sweep limpio.
- **Detección (sweep):** grep de `.version` / campos de política leídos sin una
  comparación de rechazo cercana.
- **Pregunta recurrente:** *¿qué reglas se validan sólo en RPC/mempool y NO en la
  ejecución comprometida? Un bizantino las saltea.*

## EC-09 — Peligros de migración

- **Clase:** reusar la struct actual para interpretar un formato histórico cuyos
  campos/variantes cambiaron; gate de arranque ≠ decodificador de runtime; sin
  fixtures reales; brick-on-upgrade.
- **Instancias:** v8.6.13 #2/#3; brick de #8.2.2 (gate demasiado agresivo).
- **Regla:** estructuras históricas EXACTAS + conversión variante-por-variante +
  fixtures binarios reales por versión + prueba de migración + reinicio + corte
  de energía; un decodificador canónico único.
- **Detección (sweep):** ver EC-02.
- **Pregunta recurrente:** *¿la migración se probó desde un fixture binario REAL
  de la versión anterior, con reinicio y con corte a mitad?*

## EC-10 — Hueco de autorización en flujo privilegiado

- **Clase:** una operación ejecutable/cancelable/aprobable sin el umbral/owner/
  proponente requerido.
- **Instancias:** v8.6.13 #6 (CORREGIDO v8.6.18): `Cancel` de tesorería lo podía
  ejecutar CUALQUIER firmante sobre CUALQUIER op → un firmante malicioso/
  comprometido paralizaba el multisig cancelando toda propuesta. Fix: sólo el
  PROPONENTE (el primer aprobador de la op) puede cancelar la SUYA; una op vieja
  se reaje por expiración o la descarta un `SetSigners`. Test
  `only_the_proposer_can_cancel_a_pending_op`. Precedente: denominador de quorum
  de Finalize (v2.0.4).
- **Regla:** cada transición privilegiada declara quién puede + qué umbral; una
  aprobación se vincula criptográficamente a una op única e inmutable.
- **Barrido (v8.6.18):** revisadas todas las transiciones privilegiadas: treasury
  Propose/Approve exigen firmante (dedup en Approve), Execute permissionless pero
  re-chequea umbral+timelock+límites, Cancel ahora proponente-only; governance
  Finalize/Execute permissionless pero gateadas por estado/timelock, Emergency
  Pause/Unpause exigen guardián, CloseProposal gateada por terminal+retención;
  validator-v7 Bond/Exit/Withdraw exigen operador (#20); staking owner-checked.
  Cancel era el único hueco. Sweep limpio.
- **Pregunta recurrente:** *para cada operación privilegiada: ¿quién puede
  iniciarla/cancelarla/ejecutarla, y se exige el umbral correcto en CADA una?*

## EC-11 — Sesgo de test al camino feliz / al modelo de amenazas propio

- **Clase:** los tests atacan sólo los vectores que el autor imagina.
- **Regla:** cada función R2/R3 incluye ≥5 casos de abuso concretos + un test de
  EXPLOTACIÓN que intenta el ataque real (p.ej. propuesta falsificada desde una
  cuenta system-owned / governance-owned-controlada-por-clave / modificada por
  WASM / dirección no canónica).
- **Pregunta recurrente:** *¿existe un test que intente el exploit exacto del
  hallazgo, y falla sin el fix?*

## EC-12 — Punto ciego del auditor = autor/mismo modelo

- **Clase:** auditorías hechas por el mismo autor/modelo comparten puntos ciegos
  sistemáticos; los bugs de COMPOSICIÓN entre subsistemas (WASM × gobernanza ×
  ledger) se escapan.
- **Instancias:** TODA la auditoría v8.6.13 la encontró un tercero independiente;
  los self-audits (3/5/6 agentes del mismo modelo) no la vieron.
- **Regla:** la revisión externa independiente es un gate OBLIGATORIO antes de
  valor real (no lo puede cubrir un agente solo — QSEP-1 §9/§11). Mitigación
  interna: al auditar, componer flujos ENTRE subsistemas a propósito, no revisar
  cada módulo aislado.
- **Pregunta recurrente:** *¿esta revisión compuso flujos entre subsistemas
  (borde WASM × lectores privilegiados × ledger × firmante)? ¿la revisó alguien
  que no la escribió?*

## EC-13 — Tamaño-wire / cobro inexacto

- **Clase:** calcular el tamaño para fees/límites distinto de los bytes realmente
  serializados.
- **Instancias:** v8.6.13 #11 (`byte_size()` no cuenta todo el framing borsh).
- **Regla:** una única función de tamaño = `borsh::to_vec(tx).len()` compartida
  por transporte/mempool/cobro.
- **Pregunta recurrente:** *¿el fee y el cap usan EXACTAMENTE los bytes del wire?*

## EC-14 — Parámetro externo sin topes

- **Clase:** parámetros (Argon2 m/t/p, nº de páginas, límites) tomados de un input
  no confiable sin máximos → DoS.
- **Instancias:** v8.6.13 #10 (Argon2 del blob de respaldo sin topes); #109
  (páginas de snapshot, ya acotadas).
- **Regla:** todo parámetro de un input externo se clampa a un rango documentado;
  los valores legítimos históricos se aceptan explícitamente.
- **Pregunta recurrente:** *¿qué parámetros vienen de datos externos sin un
  máximo?*

## EC-15 — Cripto/recuperación propia con checksum/estándar insuficiente

- **Clase:** implementación propia (Shamir) con checksum débil (16 bits), sin id
  de grupo, sin consistencia K/N, o afirmar interoperabilidad con un estándar por
  usar su lista de palabras.
- **Instancias:** v8.6.13 #8 (Shamir 1/65536 de recuperar una semilla equivocada
  que pasa la validación → CORREGIDO en v8.6.21): el checksum de SEMILLA era de 16
  bits (`chk0,chk1`) y no había id de grupo → mezclar fragmentos que no encajan
  (K-N mal / dos respaldos) podía reconstruir una semilla EQUIVOCADA y aceptarla
  (1/65536), o combinar en silencio fragmentos de splits distintos. **Fix (formato
  v2, retro-compatible):** cada fragmento pasa a `[VER=2, K, N, x, group(4),
  chk(17), y(32)]` = 48 palabras — checksum de SEMILLA de **136 bits** (falso-OK
  2^-136) + **id de grupo aleatorio de 4 bytes** por respaldo; al combinar se exige
  que TODOS los fragmentos compartan versión/K/N/grupo/chk (cierra el mezclado
  SILENCIOSO). El v1 (37 B / 32 palabras) se SIGUE leyendo (respaldos ya emitidos)
  con su chk de 16 bits — límite documentado del formato viejo, no se puede
  fortalecer retroactivamente. **Verificado (harness node sobre el app.js real,
  10 aserciones):** round-trip v2 K-de-N; mezclar dos respaldos → RECHAZADO; <K →
  RECHAZADO; un fragmento CORRUPTO (bit flip con su word-checksum recompuesto, que
  en v1 pasaría 1/65536) → RECHAZADO por el chk de 136 bits; y un fragmento v1
  legacy sigue reconstruyendo (backward-compat).
- **Regla:** usar un estándar auditado, o como mínimo id de grupo de 128 bits +
  checksum ≥128 bits + mismo K/N/id obligatorio + rechazo de x=0 + límites K/N +
  vectores de prueba + recuperación cross-dispositivo. No afirmar compat con un
  estándar si el protocolo difiere.
- **Pregunta recurrente:** *¿la recuperación de fondos puede aceptar una entrada
  incorrecta con probabilidad no despreciable?*

---

## Registro de auditorías

| Auditoría | Archivo | Hallazgos | Estado |
|---|---|---|---|
| Externa v8.6.13 | [`audits/2026-audit-v8.6.13.md`](./audits/2026-audit-v8.6.13.md) | 2C/2A/4M/3B | en corrección (P0 primero) |
