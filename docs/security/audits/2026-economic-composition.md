# Auditoría de COMPOSICIÓN de la economía v7 (interna)

- **Fecha / versión:** v8.6.37
- **Alcance:** las features económicas que hoy corren juntas en una red v7 —
  ruteo de fees (45/45/10), emisión respaldada por reserva bajo **hard cap**,
  barrido de polvo, tesorería multisig con wallet administrativa **configurable**,
  slashing/quema del bono, y las invariantes formalizadas de `invariants_v7`.
- **Método:** aplicar la lección de KM#10 (**EC-17**) al otro subsistema grande:
  no auditar cada feature en aislamiento —todas ya lo estuvieron— sino los
  **PUNTOS DE CONTACTO** entre ellas. Para cada par que se toca: ¿el segundo
  feature enumeró todos los sitios que el primero dejó, o asumió que "por defecto
  coinciden"? Test negativo escrito ANTES del fix en el hallazgo real.
- **Motivo:** KM#10 encontró un ROBO real componiendo dos controles individualmente
  correctos (timelocks + freeze). La economía v7 tiene la misma forma: features
  que aterrizaron en incrementos distintos (#221 hard cap, #222 tesorería
  configurable, barrido de polvo de fase 1, invariantes de la fase 1f) y que hoy
  operan sobre las MISMAS cuentas.

## Hallazgos

| # | Severidad | Hallazgo | Estado |
|---|---|---|---|
| 1 | **REAL (alcanzable)** | El barrido de polvo excluía la constante `ADMIN_FEE_WALLET` mientras `route_fee_v7` acredita el 10% administrativo a `self.admin_fee_wallet` (el campo **configurable** de #222). Un operador que configuró otra wallet admin tenía el dinero en una dirección y la protección en otra: con el acumulado bajo `dust_threshold`, un contrato que la nombrara en `ix.accounts` lo hacía **QUEMAR**. | **CERRADO** |
| 2 | Latente (defensa en profundidad) | `EMISSION_RESERVE_ID` no estaba en el conjunto de exclusión del barrido, pese a recibir el 45% del fee bajo hard cap. Hoy está protegido porque se siembra program-owned y el barrido salta lo no-system-owned — pero `Ledger::credit` crea una cuenta AUSENTE como **system-owned**, así que la protección era emergente, no explícita. | **CERRADO** |
| 3 | Latente (invariante inaplicable) | `invariants_v7::SupplyTally` no tenía término de **polvo quemado**, así que la invariante formalizada de suministro (§13) reportaba una violación FALSA contra cualquier red real que hubiera barrido polvo alguna vez — el ledger estaba perfectamente conservado y la invariante decía que no. | **CERRADO** |
| 4 | Doc | Dos comentarios afirmaban que bajo hard cap el suministro es "CONSTANTE para siempre". Es falso en un sentido que importa: bajo hard cap el suministro **nunca CRECE** (nada se acuña; el 45% del fee se recicla a la reserva en vez de destruirse), pero **sí puede ENCOGER** por el barrido de polvo y por el slashing del bono. | **CERRADO** |

### Hallazgo 1 (REAL) — detalle

`route_fee_v7` acredita el 10% administrativo con:

```rust
self.credit(self.admin_fee_wallet, admin)?;   // el campo CONFIGURABLE (#222)
```

…mientras el barrido de polvo construía su lista de exclusión con:

```rust
let fee_targets = [*fee_collector, VALIDATOR_FEE_POOL_ID, ADMIN_FEE_WALLET, STAKING_REWARDS_POOL_ID];
//                                                        ^^^^^^^^^^^^^^^^ la CONSTANTE
```

`NodeConfig.admin_fee_wallet` tiene como default esa misma constante, así que **toda
red que no configura nada, y todo test existente, pasan** — la divergencia sólo
existe para quien EJERCIÓ la opción de configurarla, que es exactamente el operador
que más cuidado quiso tener. El acumulado administrativo empieza en cero y sube de
a fracciones del fee, así que pasa por un tramo real por debajo de
`dust_threshold`: durante ese tramo, cualquier transacción que nombre esa cuenta
entre sus `accounts` la barre a cero y quema el acumulado.

**Cierre.** El conjunto de exclusión se deriva ahora de la MISMA fuente que el
ruteo del valor:

```rust
let fee_targets = [
    *fee_collector,
    VALIDATOR_FEE_POOL_ID,
    self.admin_fee_wallet,   // el campo de config, no la constante
    STAKING_REWARDS_POOL_ID,
    EMISSION_RESERVE_ID,     // hallazgo 2: recibe el 45% bajo hard cap
];
```

**Byte-idéntico** para cualquier red que no configuró una wallet admin distinta
(el campo *es* la constante) y para cualquier red que nunca barrió esas cuentas.

## Evidencia

- **Test negativo escrito y verificado CON DIENTES** (se revirtió el fix a propósito
  para confirmar que falla):
  `the_dust_sweep_protects_the_configured_admin_wallet_not_just_the_constant` →
  sin el fix: `panicked at ledger.rs: the configured admin wallet's accrual must
  never be swept as dust (was 250000, now 0)`. Con el fix: pasa.
- **Test diferencial contra el LEDGER REAL** (la invariante formalizada deja de ser
  una afirmación y pasa a ser un chequeo ejecutable contra el motor):
  `the_formalized_supply_invariant_holds_against_the_real_ledger_including_the_dust_sweep`
  — aplica transferencias reales que disparan el barrido, verifica que la ecuación
  de 5 términos cuadra, y verifica que **quitar el término de polvo la rompe por
  exactamente `ledger.dust_burned`** (o sea: el término nuevo no es decorativo).
- **Suite completa:** qchain-execution **264 tests, 0 fallos**.

## Composiciones verificadas LIMPIAS (resultados negativos, igual de valiosos)

- **Emisión × hard cap:** `index_for_backed_emission` avanza el índice sólo por lo
  que la reserva respalda; con la reserva vacía el índice **se congela** (yield 0)
  en vez de acuñar de la nada. El descenso a "sólo fees" es suave y no puede
  sobrepasar el cap.
- **Gobernanza × emisión:** `SetEmissionApr` está acotada por `MAX_EMISSION_APR_BPS`
  en el borde de ejecución, así que un voto no puede escalar la emisión más allá de
  la cota aunque la reserva tuviera saldo.
- **Tesorería × límites:** `Release` re-chequea umbral, timelock, tope por operación
  y tope por ventana rodante contra el estado **comprometido** antes de mover un
  solo QCH, con aritmética chequeada; el destino va pinneado.
- **Siembra × barrido:** `EMISSION_RESERVE_ID` y los pools v7 se siembran
  program-owned, así que el owner-check del barrido ya los salta hoy (el hallazgo 2
  hace esa protección explícita en vez de emergente).

## Clase de error registrada

**EC-18** — *protección cableada a una identidad HARDCODEADA mientras el valor se
rutea a una CONFIGURABLE* →
[`../LESSONS-LEDGER.md`](../LESSONS-LEDGER.md#ec-18--protección-cableada-a-una-identidad-hardcodeada-mientras-el-valor-se-rutea-a-una-configurable),
con su barrido de la clase sobre el resto del repo.

**Pregunta recurrente que esta auditoría deja instalada:** *para cada dirección/id
que pasó de constante a configurable — ¿qué sitios la siguen nombrando por la
constante, y alguno de ellos es una PROTECCIÓN (exclusión, allowlist, pin de
cuenta)? Listar cada sitio, no asumir que "por defecto coinciden".*

## Límite honesto

Esta pasada audita la **COMPOSICIÓN** de features económicas dentro de
`qchain-execution` (el motor de ejecución). No re-audita cada feature en
aislamiento (ya lo estaban) ni toca consenso/DST — `qchain-simulation` no depende
de `qchain-execution`, así que el cambio no lo afecta. La conservación de valor a
nivel de red (multinodo, sin fork) sigue cubierta por el `economic_state_root`
diferencial y por el harness multinodo de KM#10.
