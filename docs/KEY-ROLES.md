# Separación avanzada de roles de clave del validador v7 (#20)

Este documento describe la **rotación, revocación y expiración por rol** de las
claves de un validador v7 — el roadmap **#20** (el último de #13–#20). Es la
continuación de #193 (que ya separó los **tres roles**) hacia poder **cambiar**
cada clave sin perder el bono, la activación ni la identidad.

## Los tres roles (recordatorio, #193)

Un validador v7 (`ValidatorV7Entry`) tiene tres claves con roles distintos:

| Rol | Campo | Naturaleza | Qué autoriza |
|---|---|---|---|
| **Consenso** | `address` / `pubkey_bundle` | CALIENTE (online, firma bloques) | producir/votar bloques; es la identidad que el slashing nombra como autor del vértice |
| **Operador** | `operator_address` | FRÍA (offline) | el ciclo de vida: begin-exit / withdraw-bond / unjail / **rotar/revocar/expirar** (todo lo de #20); pagó el bono |
| **Retiro** | `withdrawal_address` | FRÍA (offline) | destino del bono al retirarlo **y** de las comisiones de fee que gana el validador |

Una fuga de la clave de **consenso** (la más expuesta) puede firmar/equivocar
(slasheable) pero **NUNCA** mover el bono ni gastar lo ganado — eso lo controlan
las claves frías de operador/retiro.

## Lo que agrega #20

Todo lo siguiente lo autoriza la clave **fría de operador** (nunca la de
consenso), y **conserva el bono/activación/participación** del validador.

### 1. Rotación de las claves FRÍAS (operador / retiro)

- **`v7-rotate-operator --new-operator <b58>`** — traspasa el rol de operador a
  una clave fría nueva. Deterministic, sin impacto de consenso. Desde ese punto,
  sólo la clave nueva puede exit/withdraw/unjail/rotar.
- **`v7-rotate-withdrawal --new-withdrawal <b58>`** — cambia dónde vuelve el bono
  y dónde se acreditan las comisiones. Deterministic (lee el registro
  comprometido → el fee-routing de la próxima ventana usa el destino nuevo).

Ambas rechazan una dirección que ya sea la identidad (consenso/operador/retiro)
de **otro validador vivo**.

### 2. Rotación de la clave de CONSENSO

- **`v7-rotate-consensus-key --new-consensus-keypair <file> --new-p2p-address ip:port`**
  — cambia la clave de firma de bloques a una fresca. La clave **NUEVA** prueba
  posesión con un **proof-of-possession** fresco (firma sobre
  `VALIDATOR_POP_V1 ‖ operator ‖ withdrawal ‖ moniker`, lo mismo que exige el
  registro), así nadie puede rotar a una clave que no controla ni reusar un PoP
  para otro operador.

  **Efecto:** la `address` viva del validador pasa a ser la clave nueva; el bono,
  la activación y la participación se **conservan**; cualquier revocación/expiría
  previa se **limpia**. La rotación toma efecto en el **próximo borde de época**
  vía la derivación determinista estándar del comité (el mismo mecanismo que un
  cambio de membresía — sin fork: todo nodo honesto deriva el mismo comité del
  registro comprometido idéntico).

  **Slashing seguro de la clave rotada-afuera:** la clave VIEJA queda registrada
  en `retired_consensus_keys` como slasheable **a través de la ventana de
  evidencia** (`SLASH_EVIDENCE_WINDOW_QUANTOS`). Como el comité del epoch en curso
  se fijó en el borde anterior con la clave vieja, una equivocación por la clave
  vieja (p.ej. una clave filtrada todavía en el comité del epoch actual) **sigue
  slasheable** — `report_equivocation` la encuentra vía `find_slashable`, quema el
  bono del validador. La lista está acotada (`MAX_RETIRED_CONSENSUS_KEYS = 4`) y se
  poda cuando la ventana pasa.

### 3. Revocación y expiración de la clave de CONSENSO

- **`v7-revoke-consensus-key`** — EMERGENCIA (sospecha de fuga). Marca la clave de
  consenso como revocada: el validador queda **excluido del comité Y del reparto
  de fees** en el próximo epoch, hasta que el operador rote una clave fresca. La
  clave revocada **sigue siendo la `address` viva**, así que una equivocación
  todavía-en-epoch sigue slasheable por el camino normal. Recuperación:
  `v7-rotate-consensus-key`.
- **`v7-set-consensus-key-expiry --expiry-quanto N`** — fija (o limpia con `0`) un
  **deadline de rotación forzada**. En/después del quanto `N` el validador queda
  excluido del comité y de los fees hasta que el operador rote una clave fresca.
  Higiene de claves: obliga a rotar periódicamente.

La exclusión es determinista (una función pura del estado comprometido:
`ValidatorV7Entry::consensus_key_disabled(current_quanto)` = revocado **o**
(expiría ≠ 0 **y** expiría ≤ quanto)), aplicada en **el ÚNICO lugar canónico**
(`active_committee`) **y** en la elegibilidad de fees (`fees_v7::is_eligible`) —
las dos leen el mismo gate.

## Formato en disco: V3, migración tolerante

#20 agrega tres campos a `ValidatorV7Entry` — `consensus_key_expiry_quanto`,
`consensus_key_revoked`, `retired_consensus_keys` — apéndidos al final. El
registro de validadores pasa de la disposición **V2** (role-separada, #193) a la
**V3**. `decode_registry` prueba V3 → V2 → V1 en orden y **MIGRA** una V2/V1 a V3
defaulteando los campos nuevos (expiría 0, no revocado, sin claves retiradas), lo
que es **byte-idéntico en COMPORTAMIENTO** a la V2 (un validador que nunca rota se
comporta exactamente como antes). Borsh rechaza bytes de cola, así que una V2 (más
corta) nunca cross-decodifica como V3 y viceversa — sin ambigüedad.

El `schema_version` explícito (#19) del registro pasa a **3**;
`qchain-inspect-state` / `qchain-migrate-registry` lo reportan.

## Despliegue (precedente #6)

#20 es una **actualización COORDINADA**, **byte-idéntica en comportamiento** para
el camino honesto (un validador que nunca rota) — el mismo modelo que #6:

- El `chain_id` **NO cambia** (se computa de `validators`+`genesis`, no de la
  disposición del registro).
- La red viva v7 migra el registro V2→V3 **en lectura** (defaulteando los campos
  nuevos), produciendo el mismo comité/fees/slashing; la forma V3 persiste en la
  próxima escritura de registro.
- Todos los nodos deben correr el binario V3 **antes** de la primera mutación de
  registro (o dos nodos escribirían bytes distintos → fork). Para la red del
  usuario (single-validator / coordinada) esto es un `git pull &&
  update-node.sh` en TODOS los nodos.
- Un validador que nunca emite una instrucción de #20 se comporta **exactamente**
  como antes.

## Límite honesto

- La rotación de la clave de **consenso** cambia la identidad del validador en el
  comité y toma efecto en el borde de época (el mecanismo probado por el DST bajo
  pérdida de certs, v4.0.3/4.0.4). La ventana de slashing de la clave rotada-afuera
  la cubre `retired_consensus_keys`. No hay un protocolo de epoch-change dedicado
  estilo Sui/Mysticeti (drenar-y-cortar) — se apoya en la seguridad de
  ordenamiento del DAG-BFT ya probada.
- La verificación multi-nodo EN VIVO del ciclo de rotación completo (rotar/revocar
  en un validador de un comité multi-nodo real y confirmar la exclusión/re-entrada
  al borde sin fork) es el gate final recomendado antes de usarlo en producción con
  una red de varios validadores; la lógica está cubierta por unit tests y la
  derivación es determinista del estado comprometido.
