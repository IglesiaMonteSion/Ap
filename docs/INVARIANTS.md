# Invariantes formalizadas de qchain (roadmap #15)

Las propiedades que **DEBEN** sostenerse en todo estado/transición válido, escritas
como **funciones puras checkeables** (no assertions dispersos) para poder correrlas
en tests diferenciales, en un canary de runtime, o como defensa-en-profundidad. Cada
una nombra los valores que discreparon en su error (diagnosticable, no un panic
pelado).

Dos familias, en dos módulos de `qchain-execution`:

- **Económicas (§13)** — `qchain_execution::invariants_v7` (roadmap Fase 1f).
- **Estructurales** — `qchain_execution::invariants` (roadmap #15).

Todas son **deterministas** (sin reloj/RNG/f64/orden-de-HashMap que se filtre) para
no violar las invariantes de determinismo/no-fork del consenso.

---

## 1. Económicas — `invariants_v7` (supply / bonos / shares)

| Invariante | Enunciado | Función | Dónde se fuerza en runtime |
|---|---|---|---|
| **supply** | `Σ balances == génesis + emitido − quemado(fee) − slashed` | `check_supply(accounts, tally)` | conservación por-path en `apply_transaction`; canary `soak-canary.py` |
| **supply cap** | `total ≤ cap` (hard-cap 100M) | `check_supply_cap(total, cap)` | gate de arranque `assert_supply_cap` + estructural (nada acuña) |
| **bonos (escrow)** | `Σ bonos escrowados == saldo de VALIDATOR_BOND_ESCROW`, y cada bono `== VALIDATOR_BOND_ATOMS` | `check_bond_escrow(accounts, registry)` | `bond_and_register` toma exactamente 500 QCH |
| **fee split** | `validador + quema + admin == fee` (45/45/10) | `check_fee_split(fee)` | `route_fee_v7` |
| **shares (reserve)** | `reserve ≥ Σ valor_de_posiciones`, y el agregado O(1) nunca floorea por debajo de la suma O(N) de floors | `check_staking_reserve(reserve, agregado, suma_ref)` | `staking_v7` acuña shares floor-valuadas; el residuo queda EN el reserve |

**Verificación diferencial:** `invariants_v7::EconWorld` corre un modelo de referencia
O(N) contra la implementación O(1) sobre 2 años de cuantos (§19), exigiendo que las 5
se sostengan en CADA cuanto + `economic_state_root` read-order-independiente.

---

## 2. Estructurales — `invariants` (no-duplicados / nonce / expiración)

| Invariante | Enunciado | Función | Dónde se fuerza en runtime |
|---|---|---|---|
| **no-duplicados (registro)** | entre validadores VIVOS (no-`Removed`), ninguna dirección (consenso/operador/retiro) ni moniker se repite | `check_registry_uniqueness(registry)` | `bond_and_register` / `addresses_in_use` rechaza el alta duplicada |
| **no-duplicados (firmantes)** | un conjunto de firmantes (certificado / aprobaciones de tesorería / votos) no cuenta la misma identidad dos veces | `check_unique_signers(&[Pubkey])` | dedup en `verify_certificate` + multisig de tesorería |
| **nonce (monotonía)** | entre dos estados comprometidos consecutivos, ninguna cuenta puede tener su nonce DECRECIDO | `check_nonce_monotonic(before, after)` | nonce-exacto + bump en `apply_transaction`; un replay se rechaza antes de tocar estado |
| **expiración** | una tx APLICADA no puede haber estado caducada (`valid_until_round == 0` o `current_round ≤ valid_until_round`) | `check_not_expired(valid_until, current_round)` | `apply_transaction` rechaza `Expired` (#191); admisión también |

**Verificación diferencial:** el test `formalized_nonce_and_expiration_invariants_hold_against_the_real_ledger`
(en `ledger.rs`) aplica transferencias REALES y confirma que el ledger mantiene las
invariantes de nonce y expiración — el nonce sube (nunca baja), un replay de nonce se
rechaza sin retroceder el nonce, y una tx caducada se rechaza en coincidencia EXACTA
con `check_not_expired`.

---

## Modelo de uso

Estas funciones **NO reemplazan** la aplicación de las reglas en el hot path (el
ledger/registro ya las fuerzan) — las **formalizan** para:

1. **Tests diferenciales** — verificar que la implementación real mantiene la
   propiedad contra un modelo de referencia o una secuencia de estados real.
2. **Canary de runtime** — `deploy/soak-canary.py` ya vigila supply/fork/txloss
   contra los nodos vivos; las económicas de §13 son las que ese canary computa.
3. **Defensa-en-profundidad** — un operador o un test de integración puede correr
   `check_*` sobre un estado comprometido y fallar ruidoso si algo se rompió, en vez
   de descubrirlo por una divergencia de state root.

**Límite honesto:** las invariantes de nonce y no-duplicados-de-registro cubren la
ruta de estado de cuentas y el registro v7; el determinismo/no-fork del ORDEN de
consenso lo cubre el DST (`qchain-simulation`), no este módulo. El fuzzing del borde
de deserialización (que ningún byte arbitrario panique) es #14 (`docs/FUZZING.md`),
ortogonal a estas invariantes de contenido.
