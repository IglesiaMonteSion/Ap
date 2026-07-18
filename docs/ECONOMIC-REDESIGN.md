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
- **Bond de entrada = 500 QCH** de self-stake, **congelado** (locked, slashable)
  mientras valida, recuperable al salir tras el unbonding. Sin esos 500 QCH
  depositados no se puede registrar el validador.
  - Cambio: `MIN_VALIDATOR_STAKE` pasa de 10.000.000 unidades (0,01 QCH) a
    500.000.000.000 unidades (500 QCH).
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

### Quién gana qué, por época
| Rol | Ingreso | Fuente |
|---|---|---|
| Staker común | ≤ 12%/año sobre su stake | Emisión (acuñación) |
| Validador | 12%/año sobre sus 500 QCH **+** 1/N de los fees | Emisión + fees |

## Lo que este modelo REEMPLAZA del diseño actual
- Selector de validador en la wallet (v5.6.0) → se quita.
- Comisión de staking al proponente (`staking_commission_bps`) → a 0 / eliminada.
- Fee del proponente = "se lo queda quien propone" → reparto parejo 1/N por época.
- Claim manual de recompensas → distribución automática por época (el claim
  puede quedar como opción, ver detalles abiertos).

## Detalles abiertos (a decidir para que no quede nada suelto)
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
