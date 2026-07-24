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
| 4 | Recovery key offline (revoca/reemplaza/congela) | 4 | pendiente |
| 5 | Timelocks on-chain de cambios de clave | 5 | pendiente |
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

## #4–#10 — pendientes

Se implementan en orden de prioridad. Notas de diseño resumidas:

- **#4 Recovery key offline.** Una clave de recuperación (Shamir 3-de-5, guardada
  offline) que puede REVOCAR/REEMPLAZAR/CONGELAR la clave de consenso u operador
  de un validador sin la clave comprometida. On-chain.
- **#5 Timelocks on-chain.** Todo cambio de clave espera una ventana antes de
  tomar efecto: rotación de consenso = próxima época; operador = 24 h; withdrawal
  = 72 h; recovery = 7 d; retiro/destino del bono = 7 d.
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
