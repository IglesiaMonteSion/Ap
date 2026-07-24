# Programa de gestión de claves del validador (10 puntos)

Rastreador del programa de endurecimiento de gestión de claves entregado por el
operador. Cada punto es una tarea independiente; se implementan en el orden de
prioridad indicado, cada una probada por incremento (unit tests + verificación en
vivo donde toca el consenso/red), sin apurar los ítems de mayor riesgo. Ningún
cambio de este programa se pliega en el `chain_id` salvo que se indique lo
contrario (son node-LOCAL o formatos de firma/keystore, no consenso/estado).

**Regla del proyecto:** "si no hay una optimización segura mejor no se hace
nada" — un ítem que no se puede cerrar de forma SEGURA y verificable queda
documentado como pendiente con su razón, no forzado.

## Estado

| # | Punto | Prioridad | Estado |
|---|-------|-----------|--------|
| 1 | Separar la clave de CONSENSO de la clave de RED (P2P) | 1 | **HECHO** (v8.6.29) |
| 2 | Eliminar `sign_raw` → interfaz de firma TIPADA | 2 | **HECHO** (v8.6.28 — `sign_network_handshake`) |
| 3 | Autenticar el firmante remoto (UDS/token/canal) | 3 | **HECHO** (v8.6.26/27) |
| 4 | Recovery key offline (revoca/reemplaza/congela) | 4 | **HECHO** (v8.6.30 — REVOKE por comité M-de-N offline) |
| 5 | Timelocks on-chain de cambios de clave | 5 | **HECHO** (v8.6.31 — operator ~24h / withdrawal ~72h / recovery ~7d) |
| 6 | Rotación de clave en DOS fases (propuesta + aceptación PoP) | 6 | pendiente |
| 7 | El firmante remoto valida POLÍTICA (chain_id/round/height/nonce/anti-equivocación/rate-limit) | 7 | pendiente |
| 8 | Keystore V2 (Argon2id→HKDF-SHA3→XChaCha20-Poly1305) + HKDF jerárquico + anti-rollback | 8 | pendiente |
| 9 | `EmergencyFreezeValidator` + expiración/rotación obligatoria + audit trail | 9 | pendiente |
| 10 | Pruebas multinodo + adversariales del ciclo de vida de claves | 10 | pendiente |

## #1 — Separar la clave de consenso de la clave de red (HECHO, v8.6.29)

**Problema.** Con el transporte P2P autenticado, el handshake por-conexión lo
firmaba la clave de CONSENSO (la que firma bloques/votos, la identidad de
slashing). Así, la clave más valiosa se usaba también para la identidad de red —
una fuga que sólo necesitara la identidad de red exponía la clave que firma valor.

**Diseño (separación de roles por delegación, sin cambio on-chain).** La clave de
consenso emite UNA vez, al arrancar, un **certificado de delegación tipado**:

```
NETWORK_KEY_CERT_V1 ‖ chain_id ‖ validator_id ‖ network_addr
```

(dominio `qchain-network-key-cert-v1`, sobre un objeto de largo fijo 32+32+32,
nunca bytes arbitrarios). El cert ata la `network_key` a la identidad del
validador BAJO esta red. A partir de ahí:

- el handshake P2P por-conexión lo firma la **network_key**, nunca la de consenso;
- el cert viaja en el handshake (`HandshakeInit`/`HandshakeResp` ganan un campo
  `network: Option<(PublicKeyBundle, MultiSignature)>`);
- el par verifica el cert contra el bundle de consenso que el nodo anuncia (y sólo
  entonces verifica el transcript bajo la network_key).

**Propiedades.**

- Una fuga de la network_key permite impersonar la identidad P2P del nodo pero
  **NO firmar bloques/votos/certs** (sólo la clave de consenso los firma).
- **Node-LOCAL:** NO se pliega en el `chain_id` (no cambia consenso/estado/wire).
  Cada operador lo decide por su cuenta.
- **Interopera con un par legacy** durante el rollout: un nodo sin network_key
  anuncia `network: None` y firma el handshake con su clave de consenso; su firma
  se verifica bajo la clave de consenso (backward-compatible por los campos
  `Option`).
- Funciona igual si la clave de consenso vive en un **firmante remoto**: el daemon
  emite el cert vía la request tipada `SignNetworkKeyCert` (sin guardia de
  doble-firma — no es un voto ni valor).

**Config / tooling.** `network_keypair_path: Option<String>` en `NodeConfig`
(`None` = legacy). Si el archivo no existe, el nodo lo GENERA (0600) al primer
arranque y emite el cert. `install-node.sh --clave-red-separada` lo activa.

**Verificado.** Unit tests (handshake de red autentica y revela el id de
CONSENSO; cert para otro validador rechazado; interop con un par legacy; el
firmante remoto produce un cert que verifica para su tupla y no para otra). **En
vivo:** 2 validadores con claves de red separadas (0600) hacen el handshake,
avanzan en lockstep, y una transferencia real converge con **root idéntico en
ambos** (`d871d6b6…`), bob=7777777 en los dos → SIN FORK.

## #2 — Eliminar `sign_raw` (HECHO, v8.6.28)

El firmante ya no expone `sign_raw` (firmar bytes arbitrarios). En su lugar
`sign_network_handshake(transcript)` EXIGE que el mensaje empiece con el dominio
`P2P_AUTH_V1` (el único uso legítimo de firmar "bytes crudos"); cualquier otra
cosa se rechaza. La interfaz del firmante es 100% TIPADA: `sign_own_vote`,
`sign_peer_vote`, `sign_network_handshake`, `sign_checkpoint`,
`sign_network_key_cert`. "Todo lo no permitido está prohibido".

## #3 — Autenticar el firmante remoto (HECHO, v8.6.26/27)

El socket del `qchain-remote-signer` autentica al cliente por challenge-response
(token pre-compartido, SHA3 prefix-MAC resistente a extensión de longitud) +
channel-binding por-frame (MAC de sesión direccional), sobre UDS same-host o TCP
loopback. El perfil mainnet lo EXIGE cuando `remote_signer` está seteado. Ver
`EC-16` en `LESSONS-LEDGER.md` (una clase nueva: "endpoint/socket privilegiado
sin autenticar; 'acotado' ≠ 'eliminado'").

## #4 — Recovery key offline (HECHO, v8.6.30)

**Problema.** Si las claves de consenso Y operador de un validador se pierden o
comprometen, no había forma de neutralizarlo sin esas claves: el bono queda en
riesgo y la clave de consenso caliente puede seguir firmando (slasheable, pero
nadie puede pararla de raíz). Hace falta una autoridad de recuperación OFFLINE,
independiente de las claves operativas.

**Diseño (comité M-de-N offline, singleton separado — sin migración).** Cada
validador registra por adelantado (con su clave FRÍA de operador, ANTES de
cualquier compromiso) un **comité de recuperación** M-de-N (ej. 3-de-5) de claves
que se guardan OFFLINE. El comité vive en un **singleton nuevo, creado
perezosamente** `VALIDATOR_RECOVERY_REGISTRY_ID = [22u8;32]` — deliberadamente
SEPARADO del registro de validadores, así **no cambia el formato de la entrada de
validador** (cero migración; byte-idéntico hasta el primer uso; brick-safe en la
red v7 viva con sólo actualizar el binario).

**Flujo air-gapped.** Cada firmante de recuperación firma OFFLINE (máquina sin
red):

```
RECOVERY_AUTH_V1 ‖ consensus_address ‖ op_tag(0x01=Revoke) ‖ recovery_nonce_le
```

(dominio `qchain-v7-recovery-auth-v1`, sobre un objeto tipado de largo fijo). Las
M firmas se recolectan y se envían en **UNA sola tx on-chain** por un relayer
**permissionless** (quien difunde no necesita ser firmante). El handler cuenta las
aprobaciones **DISTINTAS y válidas** de firmantes registrados (ignora no-miembros
y firmas malas), exige `≥ threshold`, y recién entonces ejecuta.

**REVOKE = salida dura** (espeja `begin_exit`): el bono se mueve del escrow al pool
de unbonding (`bond_release_quanto = q + max(unbonding, ventana de evidencia)`), y
el estado pasa a **`Revoked`** (terminal — el operador comprometido NO puede
deshacerlo). Un validador `Revoked` queda **excluido del comité activo**
(`active_committee` filtra sólo `Active`) y del reparto de fees; el bono sigue
siendo **slasheable** desde el pool de unbonding (una equivocación probada antes de
la revocación se sigue castigando), y el retiro del bono es **permissionless** a la
`withdrawal_address` fija (nadie puede desviarlo).

**Anti-replay.** El `recovery_nonce` per-validador es **monotónico** (sube en cada
revoke). Una firma para el nonce N no vale para el nonce N+1 → una revocación
usada no se puede reproducir. Misma postura que `VALIDATOR_POP_V1`: el nonce
monotónico dentro de la red es la defensa (no se liga `chain_id`).

**Alcance honesto.** Este incremento cierra **REVOKE**. FREEZE (pausa reversible)
va a **#9** (`EmergencyFreezeValidator`); REEMPLAZAR (rotar la clave de consenso a
una nueva) ya existe como `RotateConsensusKey` autorizada por el operador (#20 /
roadmap #6); los timelocks de la recuperación van a **#5**. Se hizo sólo lo que se
puede cerrar de forma segura y verificable.

**Config / tooling.** Ninguna config nueva (singleton perezoso). CLI:
`v7-set-recovery` (la clave FRÍA de operador fija/reemplaza/limpia el comité —
`--signers` CSV base58, `--threshold` M; se hace ANTES de cualquier compromiso, no
necesita las claves de recuperación), `v7-recovery-sign` (OFFLINE, sin red: firma
una aprobación y la imprime en hex para dársela al relayer), `v7-recover-revoke`
(el relayer envía las M aprobaciones en una tx). RPC read-only:
`/validator_v7_recovery` (lista los comités con firmantes/threshold/nonce). Nuevas
instrucciones v7 `SetRecoveryCommittee`/`RecoverRevoke` y el estado `Revoked`
(discriminantes AÑADIDOS al final → los existentes no se mueven; sólo cutover
coordinado cuando la feature se USA por primera vez, byte-idéntico hasta entonces).

**Verificado.** qchain-execution **246 tests** (+5: validación de bounds/distinción
del comité; SetRecoveryCommittee es operator-only y va al singleton separado;
RecoverRevoke exige quórum de firmantes DISTINTOS registrados; un validador
revocado sale del comité, el bono es recuperable y sigue slasheable; estabilidad
del encoding de instrucciones). clippy limpio; workspace compila. **En vivo (2
validadores v7):** se registró un validador con clave de consenso separada +
operador frío + retiro frío, se fijó un comité 3-de-5, se firmaron 3 aprobaciones
OFFLINE, el relayer las envió → el validador quedó **`Revoked` en AMBOS nodos**, el
**`recovery_nonce` subió 0→1** en ambos, el **root fue byte-idéntico**
(`b76ac7fe…`) → SIN FORK, un **replay** de las aprobaciones del nonce 0 fue
**rechazado** (el nonce quedó en 1, sin cambio de estado), y el bono quedó
escrowado con `bond_release_quanto` agendado (recuperable a la withdrawal fría).

## #5 — Timelocks on-chain de cambios de clave (HECHO, v8.6.31)

**Problema.** Toda instrucción de cambio de clave FRÍA de un validador v7 se
aplicaba INMEDIATAMENTE: `RotateOperator`, `RotateWithdrawal` y (KM#4)
`SetRecoveryCommittee`. Así, si la clave de operador se compromete, el atacante
puede AL INSTANTE redirigir la `withdrawal_address` a la suya (drenar el bono + las
comisiones de fee) o cambiar el operador para dejar afuera al dueño real — sin
ninguna ventana para reaccionar.

**Diseño (propuesta + aplicación tras una ventana, singleton separado).** Cada uno
de esos tres cambios pasa a ser **timelockeado**: la instrucción PROPONE (registra
un cambio pendiente con su `ready_quanto`) y sólo se aplica después de la ventana
vía `ApplyPendingKeyChange` (**permissionless** — el operador ya autorizó al
proponer; el que aplica es un relayer). El operador puede abortar un cambio
legítimo con `CancelPendingKeyChange`. Los pendientes viven en un **singleton nuevo
y perezoso** `VALIDATOR_KEY_TIMELOCK_REGISTRY_ID = [23]` — igual que KM#4 [22], NO
cambia el formato de la entrada de validador (cero migración; byte-idéntico hasta
el primer uso; brick-safe).

**Ventanas (en QUANTOS, la misma unidad determinista que el unbonding/activación).**
Bajo la cadencia estándar (`DEFAULT_ROUNDS_PER_QUANTO`/`DEFAULT_QUANTOS_PER_YEAR` ⇒
~365 quantos/año, 1 quanto ≈ 1 día) mapean a la intención del auditor:

- **operador ≈ 24 h** → `KEY_TIMELOCK_OPERATOR_QUANTOS = 1`
- **withdrawal ≈ 72 h** → `KEY_TIMELOCK_WITHDRAWAL_QUANTOS = 3`
- **recovery ≈ 7 d** → `KEY_TIMELOCK_RECOVERY_QUANTOS = 7`

Las otras dos ventanas del auditor ya estaban satisfechas: la **rotación de
consenso = próxima época** (vía la derivación del comité, ya en #20) y el **retiro
del bono = ~7 d** (la ventana de unbonding + evidencia ya existente).

**Garantías.** Re-proponer el mismo tipo RESETEA el reloj (comportamiento estándar
de timelock). Al aplicar se RE-VALIDA contra el estado comprometido actual (el
validador no puede ser terminal, la dirección nueva no debe colisionar, y un guard
de anti-staleness rechaza un cambio cuyo `proposed_quanto` es anterior a la
`registered_quanto` actual — cierra un replay por re-registro). Un `RecoverRevoke`
(KM#4) PURGA los cambios pendientes del validador revocado — un atacante que propuso
(p.ej.) redirigir el withdrawal se neutraliza dentro de la ventana con la recovery
key, y el cambio pendiente nunca se aplica. Determinista → sin fork.

**Honesto.** Timelockear `SetRecoveryCommittee` implica que hasta el PRIMER set el
validador no tiene comité de recuperación activo por ~7 d — pero el comité se
configura POR ADELANTADO durante operación tranquila (KM#4: "antes de cualquier
compromiso"), no bajo coacción, así que es el tradeoff correcto.

**Cambios.** (1) `qchain-execution` ids: `VALIDATOR_KEY_TIMELOCK_REGISTRY_ID=[23]`;
(2) `qchain-execution` validator_v7: constantes de ventana, tipos `KeyChangeKind`/
`PendingKeyChange`/`PendingKeyChangeEntry`/`KeyTimelockRegistry`,
`read/write_key_timelock_registry` (perezoso, fail-loud si presente-pero-
indecodificable), `RotateOperator`/`RotateWithdrawal`/`SetRecoveryCommittee` ahora
PROPONEN, instrucciones `ApplyPendingKeyChange` (permissionless) + `CancelPendingKeyChange`
(operator), purga en `recover_revoke`; (3) `qchain-node` rpc: ruta read-only
`/validator_v7_pending_keys`; (4) `qchain-cli`: `v7-apply-key-change`,
`v7-cancel-key-change` (los `v7-rotate-operator`/`-withdrawal`/`v7-set-recovery`
ahora proponen).

**Verificado.** qchain-execution **248 tests** (+2: las tres ventanas exactas +
re-propose resetea el reloj; un pendiente se PURGA al revocar). clippy limpio
cli/node/execution. **En vivo (2 validadores v7, rpq=6):** una rotación de
withdrawal PROPUESTA quedó pendiente con `ready_quanto` IDÉNTICO en ambos nodos y
NO se aplicó; aplicar DENTRO de la ventana (recovery, 7q) fue RECHAZADO (registro de
recuperación vacío); aplicar TRAS la ventana cambió la withdrawal con **root
byte-idéntico en ambos nodos** → SIN FORK; un `CancelPendingKeyChange` limpió el
pendiente en ambos nodos con root byte-idéntico.

## #6–#10 — pendientes

Se implementan en orden de prioridad. Notas de diseño resumidas:

- **#6 Rotación en dos fases.** Propuesta (clave vieja) + aceptación con PoP de la
  clave nueva (`QCHAIN_KEY_ROTATION_ACCEPT_V1`), para que una rotación a una clave
  que no se posee sea imposible.
- **#7 El firmante remoto valida política.** Además de la allowlist de dominios,
  el daemon valida chain_id/round/height/nonce, mantiene su propio estado
  anti-equivocación persistente, y aplica rate-limit — deja de ser un oráculo de
  firma "ciego dentro de su allowlist".
- **#8 Keystore V2.** `Argon2id → HKDF-SHA3 → XChaCha20-Poly1305`, derivación HKDF
  jerárquica de sub-claves por rol, y un contador monotónico anti-rollback en el
  archivo.
- **#9 Emergency freeze + expiración.** `EmergencyFreezeValidator` (por la recovery
  key / guardianes) + expiración/rotación obligatoria de claves + audit trail con
  logs encadenados por hash.
- **#10 Pruebas multinodo + adversariales** del ciclo completo (rotación,
  revocación, freeze, recuperación) bajo pérdida de certs y actores bizantinos.
