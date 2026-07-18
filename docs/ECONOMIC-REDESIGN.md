# Rediseño económico de qchain (v7 — en DISEÑO, todavía no construido)

> Documento vivo. Captura el modelo económico nuevo pedido por el usuario.
> Nada de esto está implementado aún: es la especificación que vamos a construir
> una vez cerrados los detalles. Es un cambio de consenso/economía → génesis
> nuevo, todos los nodos con la misma versión, DST + testnet en vivo antes de
> darlo por bueno.

## Decisiones ya cerradas

**1A — Staking = solo recompensas (no DPoS).**
El stake de la gente NO afecta el poder de consenso de los validadores; solo da
rendimiento. Los validadores pesan en el consenso por su propio bond. (Es lo que
ya hay: el peso BFT está desacoplado del staking, y el pool de recompensas es
global.)

**2A — Pago por época vía acumulador auto-compuesto (O(1)).**
La recompensa se acredita/compone al final de cada época sin recorrer todas las
cuentas (reward-per-share tipo Synthetix/MasterChef, ya implementado). Misma
experiencia que Solana (aparece cada época), pero escala a millones de stakers.

**3A — Génesis nuevo + coordinado.**
Es un cambio económico/consenso determinista. Se construye, se prueba con DST +
un testnet en vivo, y la red arranca de cero con las reglas nuevas. Bump MAYOR
(v7.0.0).

## El modelo unificado

### Validadores (nodos)
- **Nombre (moniker) on-chain**: al registrarse, el validador da un nombre que
  queda en el registro on-chain (hoy `RegisteredValidator` no tiene nombre →
  campo nuevo). El instalador/`become-validator` lo pide.
- **Bono de entrada = 500 QCH EXACTOS (D6 B)** — un COLATERAL bloqueado, **NO es
  stake y NO gana recompensas**. Solo queda trabado como garantía (anti-Sybil +
  para poder slashearlo si el validador equivoca). Congelado mientras valida,
  recuperable al salir tras el unbonding. Sin esos 500 QCH depositados no se
  puede registrar el validador.
  - A nivel de cuentas: se distingue **bono** (colateral del validador, no gana)
    de **delegación** (staking normal, gana 12%). El registro crea un bono; un
    validador que además quiera rendir stakea aparte como cualquier staker.
  - `MIN_VALIDATOR_STAKE` (el umbral de registro) pasa a 500 QCH; el bono es
    fijo en 500 exactos.
- **Ingreso de los validadores = fees, EN PARTES IGUALES.**
  De cada fee: 50% se quema, 50% va a los validadores, dividido **1/N entre
  todos los validadores activos de la época**, pagado por época. (Hoy se lo
  queda el proponente del bloque → cambia a reparto parejo por época.)
  - Se elimina `staking_commission_bps` (los validadores ya no cobran comisión
    del staking; cobran por fees).

### Staking (para toda la gente, incluidos los validadores con su bond)
- **Sin elegir validador.** Un solo pool global; el rendimiento es proporcional
  al stake, sin favoritismo. Se quita el selector de la wallet (se deja el
  historial de recompensas).
- **Recompensa = emisión, tope 12% anual** de lo stakeado, distribuida
  automáticamente cada época (acumulador, 2A).
- **Cómo se garantiza el ≤12% exacto:** la emisión por época = 12% anual del
  total stakeado, y va **100% a los stakers** (sin comisión que la recorte). Los
  fees NO alimentan el pool de staking (van a los validadores). Así el
  rendimiento del staker es 12% por construcción, ni un punto más.

### Quién gana qué, por **CUANTO** (el período de recompensas)
| Rol | Ingreso | Fuente |
|---|---|---|
| Staker común (no validador) | ≤ 12%/año sobre su stake, **compuesto** (D4 A) | Emisión (acuñación) |
| Validador | **1/N de los fees** (partes iguales), y NADA MÁS | Fees |

**Roles separados, sin doble-dipping (D13):** un validador **NO puede stakear** —
gana SOLO por las comisiones/fees. Su bono de 500 QCH es colateral puro (no gana).
Un staker común no corre nodo; solo pone QCH y cobra el 12%. Regla on-chain: una
dirección registrada como validador no puede abrir una posición de staking (y
para registrarse como validador no debe tener staking activo).

Nota: ni el bono del validador ni el propio validador entran al 12%. La emisión =
12% anual del total realmente **stakeado por stakers comunes**, no de los bonos.

### Detalles cerrados en esta ronda
- **D4 A** — la recompensa de staking se **compone** al principal. Con el
  acumulador O(1) (2A), esto es compound "perezoso": la recompensa se acumula
  virtual cada período (visible en vivo como "pendiente") y se pliega al
  principal cuando la posición se toca (claim/re-stake). La wallet muestra el
  saldo creciendo cada período; no hace falta recorrer todas las cuentas.
- **D5 A** — período ≈ 1 día en producción (configurable; corto en el testnet de
  pruebas para ver los pagos rápido). El NOMBRE del período NO es "época" (ver
  sección de nombre).
- **D6 B** — bono fijo de 500 QCH, colateral, no gana (arriba).
- **D7 C** — todo FIJO por ahora (12% APR, fee split, bono de 500): constantes en
  código, nada gobernable todavía.
- **D8 (confirmado)** — `become-validator` pide nombre, exige ≥500 QCH en la
  wallet del nodo (si no, corta y explica cómo conseguirlos), y hace
  bono(500) + register(nombre).
- **D9** — la equivocación quema el bono completo (500).
- **D10** — unbonding del bono ≈ 1 período al salir.
- **D11** — cuenta singleton nueva junta la mitad-no-quemada de los fees durante
  el período y la reparte 1/N en el borde.
- **D12** — `ROUNDS_PER_YEAR` se recalcula según `round_interval_ms` real para
  que el 12% sea 12% de reloj.

## Lo que este modelo REEMPLAZA del diseño actual
- Selector de validador en la wallet (v5.6.0) → se quita.
- Comisión de staking al proponente (`staking_commission_bps`) → a 0 / eliminada.
- Fee del proponente = "se lo queda quien propone" → reparto parejo 1/N por época.
- Claim manual de recompensas → distribución automática por época (el claim
  puede quedar como opción, ver detalles abiertos).

## Nombre del período de recompensas: **CUANTO** (cerrado)
El período se llama **cuanto** (un "cuanto" = el paquete discreto e indivisible de
algo; un cuanto de tiempo — máximo on-brand para una cadena post-cuántica, y no
suena copiado de Solana). En el código reemplaza a "epoch/época" para el período
de recompensas. Dura ≈ 1 día en producción (configurable; corto en pruebas).

## Estado del diseño: CERRADO ✅ — listo para construir
Todas las decisiones (1A/2A/3A, D4–D13, nombre) están tomadas. El modelo es
coherente e internamente consistente. Próximo paso: construir por fases con DST +
verificación en vivo, y un génesis nuevo.

### Fases de construcción (borrador)
1. **Ejecución/economía** (`qchain-execution`): bono de 500 vs delegación,
   `MIN_VALIDATOR_STAKE`=500 QCH, validador no puede stakear, emisión = 12% del
   stakeado sin bonos, quitar `staking_commission_bps`, pool de fees por-cuanto
   + reparto 1/N, distribución por-cuanto (acumulador, compound perezoso).
   Tests + DST.
2. **Nodo** (`qchain-node`): borde de cuanto (correr aunque rotación off),
   nombre on-chain en el registro, reparto de fees en el borde, `ROUNDS_PER_YEAR`
   consistente. Verificación en vivo (testnet nuevo).
3. **CLI + `become-validator`**: pedir nombre, exigir ≥500 QCH, bono + register;
   quitar `--validator` del staking (pool global).
4. **Wallet + explorador**: quitar el selector de validador, mostrar el 12%
   compuesto por cuanto, historial; panel del validador con su 1/N de fees.
5. **Génesis + docs**: génesis nuevo con las reglas nuevas, `become-validator.sh`,
   actualizar `ARCHITECTURE.md`/`DEPLOY.md`. Bump v7.0.0.

## Detalles ya resueltos (referencia)
- **D4 — Recompensa de staking: ¿líquida o compuesta al stake?**
  (auto-compound al principal vs acreditada como saldo gastable cada época).
- **D5 — Largo de la época** en tiempo real (cadencia de pago). Solana ≈ 2 días.
- **D6 — 500 QCH: ¿bond fijo o mínimo** (un validador puede stakear más como
  staker común y ganar 12% sobre el extra)?
- **D7 — ¿Qué params son gobernables** (12% APR, fee split, bond de 500)?
- **D8 — `become-validator`**: pide nombre + exige ≥500 QCH en la wallet +
  self-stake(500) + register(nombre). El "no se crea sin 500 QCH" es un gate en
  el flujo.
- **D9 — Slashing**: la equivocación quema el bond completo (500). Confirmar.
- **D10 — Unbonding del bond** al salir (hoy 2 pasos, 100 rondas). ¿Alinear a
  época?
- **D11 — Acumulación de fees para el reparto 1/N**: cuenta singleton nueva que
  junta la mitad-no-quemada durante la época y se reparte en el borde.
- **D12 — ROUNDS_PER_YEAR** consistente con el `round_interval_ms` real (el 12%
  nominal por-ronda debe coincidir con el año de reloj).

## Estado de construcción
Nada construido todavía. Próximo paso: cerrar D4–D12, luego implementar por fases
con DST + verificación en vivo, y documentar el génesis nuevo.
