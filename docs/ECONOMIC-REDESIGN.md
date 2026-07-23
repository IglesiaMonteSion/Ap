# Rediseño económico de qchain (v7 — SPEC DEFINITIVA, en DISEÑO, todavía no construido)

> Documento vivo y **spec oficial** del modelo económico v7. Consolida el diseño
> cerrado con el usuario + el complemento técnico. Nada está implementado aún: es
> lo que se va a construir por fases, cada una con DST + testnet en vivo, y un
> **génesis nuevo** al final. Es un cambio de consenso/economía → todos los nodos
> con la misma versión, bump MAYOR (v7.0.0).

---

## 0. El modelo en una frase

QChain v7 separa por completo las dos actividades económicas:

- **Staker** — no corre nodo; deposita QCH en un pool global; recibe **hasta 12%
  APY de protocolo** por emisión, **compuesto** vía un índice global; no elige
  validador, no paga comisión, no comparte su recompensa.
- **Validador** — deposita **exactamente 500 QCH** como bono (colateral, NO gana
  rendimiento), corre consenso, y cobra **una parte igual de la mitad no quemada
  de los fees**; puede perder el bono completo por equivocación BFT demostrable.
- **Protocolo** — quema ≥50% de cada fee, manda el resto al pool de validadores,
  acuña SOLO las recompensas de los stakers, y cierra la economía cada **cuanto**
  de forma determinista e idempotente, conservando invariantes verificables.

---

## 1. Decisiones cerradas

- **1A — Staking = solo recompensas (no DPoS).** El stake de la gente no afecta el
  poder de consenso; solo da rendimiento. Los validadores pesan por su bono.
- **2A — Pago por cuanto vía índice global O(1).** El valor de cada posición sube
  solo al avanzar el índice; no se recorren las cuentas (escala a millones).
- **3A — Génesis nuevo + coordinado.** Bump MAYOR (v7.0.0).
- **Génesis: Política A (reinicio total).** No se migra nada de v6 (es un testnet;
  el QCH no tiene valor de mercado). **10.000.000 QCH al génesis, solo a la
  dirección FUNDADORA** — único saldo inicial; desde ahí distribuye el fundador.
  Los nodos que se sumen después arrancan en **0**. Ver §9.
- **Economía fee-only del validador: ACEPTADA conscientemente.** El validador gana
  SOLO fees; con poca actividad de red el ingreso puede ser ~0 y los 500 QCH no
  rinden. Es consecuencia elegida del modelo; la wallet NO promete rentabilidad
  fija (muestra estimación por fees reales). Ver §16.
- **Nombre del período = `cuanto`** (paquete discreto de tiempo; on-brand
  post-cuántico, no suena a Solana). ≈ 1 día en producción, corto en pruebas.

---

## 2. Staking — representación O(1) por shares + índice

Las posiciones NO se guardan como cantidades nominales de QCH, sino como **shares**.
El índice global creciendo ES la composición de TODAS las posiciones a la vez.

**Estado global mínimo:** `total_staking_shares`, `staking_index`,
`staking_reward_reserve`, `current_quanto`, `last_settled_quanto`.

**Estado por posición:** `owner`, `shares`, `created_quanto`, `last_modified_quanto`,
`net_deposited`, `estado`.

**Valor de una posición:** `position_value = shares × staking_index / INDEX_SCALE`.

**Al cerrar un cuanto** (O(1), sin tocar posiciones):
1. Se calcula `rate_per_quanto` (constante, ver §3).
2. `new_index = old_index + floor(old_index × rate_per_quanto)`.
3. `reward_minted = floor(total_shares × (new_index − old_index) / INDEX_SCALE)`.
4. `reward_minted` se acuña en `staking_reward_reserve`.
5. No se recorren ni modifican las posiciones.

Cuando un usuario retira, los QCH salen de `staking_reward_reserve`.

**Precisión:** `INDEX_SCALE` amplio (a definir en build, ver §14). Toda multiplicación
que pueda exceder el entero nativo usa aritmética segura (u256 o staging en u128).
**Todo redondeo va hacia abajo** → el rendimiento real es ≤ 12%, nunca más.

---

## 3. Tasa de staking — APY (no APR), ≤12% de protocolo

El objetivo es que un staker **nunca reciba más del 12% efectivo anual**.

- Constante: **`STAKING_TARGET_APY_BPS = 1200`** (12%). Se llama **APY**, no APR,
  porque compone automáticamente.
- La tasa por cuanto se calcula ANTES del lanzamiento, en aritmética de precisión
  fija, y queda fija en el génesis/constantes de consenso:

  `rate_per_quanto = (1 + 0.12)^(1 / QUANTOS_PER_YEAR) − 1`

  Para 365 cuantos/año ≈ **0,0310538%** por cuanto (NO `12%/365 ≈ 0,0328767%`, que
  daría ~12,7475% efectivo — el bug del diseño previo).
- **12% de PROTOCOLO, no de reloj.** El APY se define sobre el calendario de
  protocolo (`ROUND_INTERVAL_MS`, `ROUNDS_PER_QUANTO`, `QUANTOS_PER_YEAR`,
  `YEAR_MS`). Si la red se frena o produce rondas más lento, el rendimiento por
  reloj será **menor** al 12%, nunca mayor. Garantía honesta: *"QChain distribuye
  como máximo 12% APY según el calendario de protocolo del génesis"*.
- Cambiar `ROUND_INTERVAL_MS`, `ROUNDS_PER_QUANTO` o la duración del año económico
  obliga a recalcular la tasa y **es un cambio de consenso**.

---

## 4. Claim y auto-compound

No hay claim obligatorio: las recompensas YA son parte del valor de la posición
(el índice). Operaciones: `stake(amount)`, `increase_stake(amount)`,
`begin_unstake(amount)`, `withdraw_unbonded()`.

"Retirar recompensas" en la wallet = un **retiro parcial** del valor acumulado, NO
una segunda fuente de recompensa. No existe operación que duplique una recompensa
ya incorporada al índice. La UI puede separar visualmente capital neto / recompensa
acumulada / valor total, pero económicamente es UNA sola posición en shares.

**Historial:** no se emite un registro on-chain por usuario por cuanto (mataría el
O(1)). En cada cierre se emite un evento global **`QuantoClosed`** con: nº de cuanto,
índice anterior/nuevo, shares totales, stake efectivo total, emisión acuñada, fees
acumulados/quemados/a-validadores, nº de validadores elegibles, residuos de redondeo.
La wallet/explorador **reconstruyen** el historial individual a partir de los eventos
globales + los movimientos de shares + depósitos/retiros del usuario (derivado e
indexado, no una transferencia diaria por cuenta).

---

## 5. Estados de una posición de staking

`Active` → `Unbonding` → `Withdrawable` → `Closed`.

- Solo el valor **Active** recibe recompensas.
- Al iniciar unstake, esas shares dejan de recibir recompensas de inmediato y salen
  de `total_active_stake`.
- Hay un **período de unbonding de staking** (`STAKING_UNBONDING_QUANTOS`),
  **independiente** del unbonding del bono del validador.
- Una dirección de validador (registrado / en salida / en unbonding del bono) NO
  puede abrir staking. Solo puede volverse staker tras retirar el bono por completo
  y salir del registro.

---

## 6. Bono del validador

Constante: **`VALIDATOR_BOND = 500 QCH` EXACTOS** (ni 499,999999 ni 500,000001).

El bono: se bloquea en un escrow de protocolo; **no** se convierte en shares, **no**
participa en staking, **no** recibe emisión ni rendimiento; puede quemarse por
slashing; se recupera tras una salida válida + su unbonding. Una dirección puede
tener exactamente un bono activo.

**Poder de consenso:** como todos los bonos valen lo mismo, cada validador activo =
una unidad de poder. No se compra más poder depositando más de 500. Un actor con más
capital puede registrar **varios** validadores (500 c/u) → el bono es una **barrera
económica lineal contra Sybil, no una eliminación absoluta** (documentarlo así).

**Anti-doble-dipping — alcance honesto:** la regla on-chain garantiza que *una
dirección registrada como validador no puede tener staking activo* (y viceversa: hay
que cerrar el staking antes de registrarse). NO puede impedir que un mismo actor use
**dos direcciones distintas** (una para el bono, otra para stakear) — eso requeriría
identidad/KYC, que rompería el carácter permissionless. La doc dice "por dirección
registrada", nunca "por persona".

---

## 7. Registro y moniker on-chain

El registro del validador contiene, como mínimo: dirección operadora, clave de
consenso, moniker, ronda/cuanto de activación, estado, bono bloqueado, cuanto de
solicitud de salida, cuanto de liberación, info de slashing, contadores de
participación.

**Reglas del moniker** (deterministas entre implementaciones): 3–32 chars;
`[a-z0-9_-]`; comparación case-insensitive; sin espacios al borde; **único mientras
el registro esté activo**; palabras reservadas bloqueadas; inmutable mientras el
validador esté registrado. (Un nombre visual Unicode puede guardarse aparte como
campo informativo; el identificador de consenso queda normalizado y simple.) El
moniker no prueba identidad legal ni propiedad del nodo.

---

## 8. Flujo `become-validator` (con crash-safety)

1. Pedir el moniker; validar formato localmente.
2. Consultar saldo confirmado de la wallet del nodo.
3. Comprobar que la dirección **no** tenga staking activo.
4. Comprobar que no haya bono/registro anterior sin cerrar.
5. Exigir ≥ 500 QCH **más** los fees de las transacciones (no mandar el saldo
   completo como bono — reservar para pagar tx).
6. `bond_validator(500 QCH)` → esperar confirmación/finalidad.
7. `register_validator(moniker, consensus_key)` → verificar on-chain que quedó.
8. Mostrar el cuanto en que el validador será elegible.

**Falla a mitad** (bono depositado pero registro no): debe existir una operación
segura para **completar el registro** o **recuperar el bono tras expiración**. El
bono nunca queda bloqueado indefinidamente por una instalación interrumpida.

---

## 9. Ciclo de vida del validador

`BondedPending` → `Active` → (`Jailed`) → `Exiting` → `Unbonding` → `Withdrawable`
→ (`Slashed`) → `Removed`.

- **Activación:** un validador registrado durante un cuanto entra al conjunto activo
  al **inicio del cuanto siguiente** (no se registra 5s antes del cierre y cobra
  igual que los que trabajaron todo el período).
- **Salida:** solicitud en el cuanto Q → permanece hasta el cierre, sale del conjunto
  en el borde siguiente, arranca el unbonding del bono, se libera tras un cuanto
  completo **si no hay evidencia de slashing pendiente**. No puede stakear en
  `Exiting` ni `Unbonding`.
- **Reingreso:** tras retirar el bono puede quedar como cuenta común, abrir staking, o
  re-registrarse con un bono nuevo. Un validador slasheado deposita un bono completo
  nuevo para volver (con posible período de espera).

---

## 10. Slashing — definición precisa

**Quema del bono completo (500) SOLO ante evidencia criptográfica determinista** de
falta grave: firmar dos bloques incompatibles para la misma altura/ronda; votos
contradictorios para la misma etapa de consenso; firmar estados incompatibles; o
evidencia deliberadamente falsa probable on-chain.

**NUNCA se quema el bono por** desconexión temporal, latencia, reinicio, pérdida
momentánea de conectividad, no proponer un bloque, o unas pocas rondas sin firmar.
Esas faltas de **disponibilidad** producen: pérdida del derecho a fees del cuanto,
**jailing** temporal, y posible expulsión por reincidencia. (Así una falla de VPS no
destruye los 500 QCH.)

**Evidencia durante el unbonding:** una salida no borra la responsabilidad por faltas
cometidas mientras estaba activo. El bono solo se libera cuando terminó el unbonding,
venció la **ventana de evidencia** (`SLASH_EVIDENCE_WINDOW_QUANTOS`), y no hay
evidencia pendiente. La ventana de evidencia ≤ el tiempo que el bono sigue slashable.

---

## 11. Fees — split, elegibilidad y reparto

**Split por fee** (en la unidad atómica mínima): `burn = ceil(fee/2)`,
`validator = floor(fee/2)` → la proporción quemada nunca baja del 50%. Invariante:
`fee = burned + validator_pool`.

**Elegibilidad para cobrar el cuanto:** no basta estar registrado. El validador debe
haber estado activo el período requerido, no estar jailed, no haber sido slasheado,
cumplir `VALIDATOR_MIN_PARTICIPATION_BPS` (p.ej. 9000 = 90%), y no haber entrado
después del snapshot del cuanto. Los que no llegan al mínimo no cobran ese cuanto
(un nodo caído no cobra igual que uno disponible).

**Snapshot del conjunto:** nuevos entran desde el cuanto siguiente; salidas se aplican
en el borde siguiente; un slasheado pierde la recompensa del cuanto en curso; un
jailed puede perderla; no se entra justo antes del cierre para cobrar retroactivo.

**Reparto 1/N en el cierre:** `validator_reward = floor(fee_pool / eligible_count)`;
cada validador elegible recibe lo mismo. El **residuo**
(`fee_pool − reward × eligible_count`) **queda en el pool** para el próximo cuanto
(no se quema, no va al proponente, no se pierde). **Si no hay validadores elegibles:**
los fondos quedan en el pool, sin división ni quema extra, para el próximo cuanto con
elegibles.

**Alternativa escalable (recomendada):** un `validator_fee_index` (como el de
staking) donde cada validador activo acumula virtualmente lo mismo y liquida al
consultar/salir/cambiar de estado — evita el pago O(N) directo. (El protocolo igual
puede necesitar recorrer el conjunto para calcular participación/jailing/elegibilidad.)

---

## 12. Separación estricta de pools

Cuentas/módulos separados, **sin subsidio cruzado**:
1. `validator_bond_escrow`
2. `staking_reward_reserve`
3. `validator_fee_pool`
4. `staking_unbonding_pool`
5. `validator_unbonding_pool`
6. contador de burn

Prohibido: pagar staking con fees; pagar validadores con emisión de staking; usar
bonos para recompensas; usar recompensas no reclamadas para otro fin; contar bonos
como stake circulante; incluir bonos en el cálculo del 12%. La emisión de cada cuanto
se calcula **solo** sobre el valor efectivo de las posiciones **Active** de stakers
comunes.

---

## 12-bis. Suministro definitivo — CAP DURO de 100M (decisión #221)

**Decisión firme del proyecto (elegida por el usuario, severidad Alta):** el
suministro máximo real es **100.000.000 QCH y NUNCA se supera**. Esto es un
**invariante de consenso**, no una promesa de marketing.

**Cómo se garantiza — por CONSTRUCCIÓN, no por vigilancia:**
- El staking **NO acuña** monedas nuevas. Toda la emisión sale de una **reserva
  pre-acuñada en génesis** (`EMISSION_RESERVE`, id `[20;32]`), parte del reparto de
  los 100M. Cada cierre de cuanto **transfiere** (no acuña) de `EMISSION_RESERVE` a
  `STAKING_RESERVE`; el índice avanza sólo por el monto **respaldado** por esa
  transferencia (`economics_v7::index_for_backed_emission`). Como nada se acuña
  después de génesis, **`Σ balances` es constante** al total de génesis para siempre.
- **Los fees financian el staking:** bajo el cap duro, el 45% del fee que en el
  modelo inflacionario se **quemaba** se **acredita a `EMISSION_RESERVE`** en vez de
  destruirse (`route_fee_v7`). Así la reserva se **recarga con los ingresos reales**,
  y `Σ balances` se mantiene EXACTAMENTE en el total de génesis (ni crece ni encoge).
- **Cuando la reserva se agota, el rendimiento depende sólo de los ingresos reales
  (fees):** si `EMISSION_RESERVE` cae por debajo del paso de emisión de un cuanto, la
  emisión de ese cuanto floorea a 0 y el índice se congela — el yield efectivo baja a
  lo que los fees vuelvan a aportar a la reserva. No hay "yield garantizado" sin
  respaldo: el 12% APY es un **techo** que sólo se alcanza mientras la reserva (o los
  fees) lo respalden.

**Invariantes automáticos (obligatorios):**
- **GÉNESIS (fail-loud):** el nodo **se niega a arrancar** si el suministro sembrado
  (asignaciones + tesorería + reserva de emisión + bonos 500×N) **excede el cap**
  (`Ledger::assert_supply_cap` → `invariants_v7::check_supply_cap`). `qchain-genesis-build`
  lo verifica ANTES de escribir los configs.
- **RUNTIME:** `total_supply ≤ cap` en todo momento — se cumple **estructuralmente**
  (nada acuña bajo el cap duro), verificado como defensa-en-profundidad y por el
  monitor de soak (`soak-canary.py`, invariante SUPPLY).

**Config (plegado en `chain_id`, decisión de génesis):** `hard_cap_supply: bool`
(default `false` = modelo inflacionario, compatible con la red viva), `supply_cap_qch`
(default 100M), `emission_reserve_qch` (pre-acuñado). `qchain-genesis-build
--hard-cap-supply [--supply-cap-qch N] [--emission-reserve-qch N]`.

**Despliegue:** el cap duro cambia la semántica económica y se pliega en el
`chain_id` → **NO es un update en caliente** de la red inflacionaria viva; requiere
**relanzamiento con génesis nuevo** (mismo procedimiento que §15). El reparto de los
100M (circulante + tesorería + reserva de emisión + bonos) lo decide el operador al
crear la red, y debe sumar ≤ 100M o el nodo no arranca.

---

## 13. Invariantes económicas obligatorias (todo bloque)

- **Oferta (modelo inflacionario, `hard_cap_supply` off):**
  `Δoferta = emisión_staking − fees_quemados − bonos_slasheados`. Las
  transferencias entre pools NO cambian la oferta.
- **Oferta (CAP DURO, `hard_cap_supply` on — §12-bis):** `Σ balances` es
  **CONSTANTE** al total de génesis (la emisión es transferencia reserva→reserva, el
  fee no se quema sino que recarga la reserva), y **≤ 100M** siempre.
- **Staking:** `total_active_stake = total_shares × staking_index / INDEX_SCALE`.
  Los bonos no forman parte de `total_active_stake`. Las posiciones en unbonding no
  reciben emisión.
- **Validadores:** Σ bonos del registro == saldo del `validator_bond_escrow`. Cada
  validador activo == exactamente 500 QCH. Una dirección de validador no tiene shares.
- **Fees:** `fees_totales = quemados + al_pool`; tras el cierre,
  `pool_anterior + fees_nuevos = distribuidos + residuo_nuevo`.
- **Redondeo:** ninguna operación de redondeo crea QCH; los residuos quedan en un
  pool identificable o se queman por una regla explícita.

---

## 14. Terminología: `cuanto` ≠ `consensus_epoch`

**No** reemplazar a ciegas todos los "epoch". El motor BFT puede seguir usando una
época técnica interna (rotación del conjunto validador — fase 3.3, cambios de clave,
checkpoints, sync, params de consenso). Se distinguen:
- `consensus_epoch` — la época técnica del consenso (ya existe: `EPOCH_ROUNDS`).
- `reward_quanto` — el período económico de recompensas.

Aunque en v7 coincidan temporalmente, se mantienen **conceptualmente separados** para
no acoplar consenso y economía. Nombres: `QUANTO_ROUNDS`, `CURRENT_QUANTO`,
`QUANTO_START_ROUND`, `QUANTO_END_ROUND`, `QuantoClosed`, `quanto_reward_rate`,
`validator_fee_pool_by_quanto`.

---

## 15. Génesis (Política A — reinicio total)

La red arranca de cero: NO se migran saldos, posiciones ni validadores de v6.
- **10.000.000 QCH al génesis, solo a la dirección fundadora** (único saldo inicial).
  El suministro crece luego por emisión de staking (≤12% APY).
- Nodos que se suman después arrancan en **0**; para ser validador consiguen los 500
  del bono aparte.
- Requiere: `chain_id` nuevo, hash de génesis nuevo, dominio de firma nuevo,
  protección anti-replay v6↔v7, versión mínima obligatoria, rechazo de peers con
  génesis distinto, archivo público de asignaciones, procedimiento de verificación
  independiente, y altura/fecha de corte documentadas.

---

## 16. Riesgo económico del validador (aceptado)

Con el modelo, `ingreso_validadores = fees_totales × 50%`, e
`ingreso_por_validador = fees_totales × 50% / N`. Poca actividad → ingreso ~0. Más
validadores sin más uso → menos ingreso por cabeza. El bono de 500: no cubre el VPS,
no da flujo de caja, no garantiza rentabilidad — es solo colateral en riesgo.

Antes del lanzamiento se **simulan** escenarios (TPS bajo/medio/alto × fee
mínimo/promedio × 10/50/100/500/1000 validadores × costo de VPS → ingreso
diario/mensual/anual por validador). La wallet/explorador **no prometen** rentabilidad
fija: muestran estimación por fees reales de los últimos cuantos.

---

## 17. Parámetros de consenso (fijos en v7)

Fijos, solo cambian por actualización coordinada, **visibles en el génesis y parte del
hash de configuración de la red**:
`VALIDATOR_BOND_ATOMS`, `MIN_VALIDATOR_STAKE_ATOMS`, `STAKING_TARGET_APY_BPS`,
`FEE_BURN_BPS`, `VALIDATOR_FEE_BPS`, `ROUNDS_PER_QUANTO`, `ROUND_INTERVAL_MS`,
`QUANTOS_PER_YEAR`, `STAKING_UNBONDING_QUANTOS`, `VALIDATOR_BOND_UNBONDING_QUANTOS`,
`SLASH_EVIDENCE_WINDOW_QUANTOS`, `VALIDATOR_MIN_PARTICIPATION_BPS`, `INDEX_SCALE`,
`MAX_MONIKER_LENGTH`, `MIN_MONIKER_LENGTH`.

Modificarlos requiere: bump de versión, nueva config consensuada, actualización de
todos los nodos, y — si rompe reglas incompatibles — hard fork o génesis nuevo.

---

## 18. Casos límite a especificar (obligatorio)

Definir explícitamente: total stakeado = 0; sin validadores elegibles; un solo
validador; validador que entra/solicita salida en el último bloque del cuanto;
slashing durante el borde; cierre de cuanto coincidiendo con cambio de conjunto;
rondas omitidas; recuperación de un bono cuyo registro falló; **cierre idempotente**
(procesar dos veces el mismo cuanto NO re-emite ni re-distribuye); recuperación tras
reiniciar exactamente en el borde; evitar doble-emisión; acumuladores tras años de
operación; evitar overflow; distribución de residuos; reconstrucción del historial
tras sync desde cero.

---

## 19. DST y pruebas obligatorias

**Propiedades:** la oferta nunca cambia sin causa identificable; ningún staker supera
el APY máximo; el bono nunca recibe recompensa; validador registrado nunca tiene
staking activo (y viceversa); los fees siempre se parten en burn+pool; todos los
elegibles reciben lo mismo; los residuos nunca desaparecen; **el acumulador da el
mismo resultado que una simulación cuenta-por-cuenta**; tocar o no una posición da el
mismo valor; reiniciar nodos no cambia el resultado; el orden de lectura de cuentas
no cambia el state root.

**Simulación diferencial:** un modelo lento de referencia O(N) que recorre todas las
cuentas vs la implementación O(1). Tras cada cuanto deben coincidir: oferta, valor por
posición, pool, bonos, fees, y **state root económico**.

**Estrés:** millones de posiciones; depósitos/retiros en el borde; muchos años
simulados; participación variable; validadores entrando/saliendo; slashing simultáneo;
todos offline; pool < N; fees impares; valores máximos; particiones y recuperación;
cambio de líder en el cierre.

---

## 20. Fases de construcción

1. **Ejecución/economía** (`qchain-execution`): shares + índice de staking, tasa APY
   por cuanto, 6 pools separados, bono 500 exacto (colateral, no gana), reglas
   validador↔staker, split de fee ceil/floor + elegibilidad + reparto 1/N (o fee
   index), emisión = 12% del stake efectivo sin bonos, invariantes. Tests + DST
   diferencial.
2. **Nodo** (`qchain-node`): borde de cuanto (idempotente, corre aunque rotación off),
   `reward_quanto` separado de `consensus_epoch`, moniker en el registro, cierre
   económico, `QuantoClosed`, `ROUNDS_PER_QUANTO`/`QUANTOS_PER_YEAR` consistentes.
   Verificación en vivo.
3. **CLI + `become-validator`**: flujo con crash-safety (§8), quitar `--validator` del
   staking (pool global).
4. **Wallet + explorador**: quitar selector de validador; mostrar valor de posición
   creciendo por el índice (≤12% compuesto); reconstruir historial desde `QuantoClosed`;
   panel del validador con su 1/N de fees (estimación por fees reales, sin prometer).
5. **Génesis + docs**: génesis nuevo (Política A, 10M al fundador), `become-validator.sh`,
   `ARCHITECTURE.md`/`DEPLOY.md`. Bump v7.0.0.

---

## 21. Detalles técnicos a fijar durante el build (no bloquean el diseño)

1. **`INDEX_SCALE` / aritmética.** El complemento sugiere 10²⁷ + 256-bit. Rust tiene
   `u128` nativo pero no `u256`. **Medir primero** la precisión necesaria y usar el
   scale más chico que deje el error de redondeo despreciable manteniendo los productos
   en `u128` con staging; recurrir a u256 (dependencia o mul/div propio) solo donde un
   producto genuinamente desborde. Decisión en fase 1.
2. **`VALIDATOR_MIN_PARTICIPATION_BPS` — métrica exacta.** Definir de forma
   determinista y anti-Bizantina qué cuenta como "participación" (¿certificados de sus
   vértices incluidos? ¿rondas propuestas?) y que no sea gameable. Decisión en fase 1/2.
3. **Valores exactos de las constantes de §17** (números finales), fijados antes del
   génesis y plegados en el hash de config.

---

## Estado del diseño

**D4–D13 y la nomenclatura de `cuanto` están CERRADOS.** Génesis (Política A + 10M) y
la economía fee-only del validador, aceptados. Permanecen por formalizar, ya en el
build: los parámetros técnicos exactos (§21), las reglas exactas de elegibilidad/
participación, y los casos límite de implementación (§18). Próximo paso: construir por
fases (§20) con DST + verificación en vivo, y el génesis nuevo.
