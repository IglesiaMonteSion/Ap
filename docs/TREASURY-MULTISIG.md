# Tesorería y wallet administrativa protegidas por MULTISIG (tarea #222)

> **Problema que cierra.** La firma híbrida Ed25519 + ML-DSA-65 mejora la
> resistencia criptográfica, pero **sigue siendo UNA SOLA autoridad** si ambas
> claves pertenecen a la misma persona. Antes de #222 la tesorería v7 se movía
> con una única `authority` (una sola clave) y el 10% de fee administrativo caía
> en una **constante oculta** (`ADMIN_FEE_WALLET`). Este cambio elimina el punto
> único de control: los fondos administrativos y la liberación de liquidez pasan
> a un **multisig M-de-N con timelock, límites por operación y por periodo,
> eventos públicos auditables, y rotación/recuperación de firmantes** — todo
> configurado en génesis, no en constantes.

Todo vive on-chain en el programa de tesorería v7 (`TREASURY_V7_PROGRAM_ID`,
cuenta `TREASURY_ACCOUNT_ID`). El estado on-chain **ES** el registro de auditoría:
cada propuesta, aprobación y ejecución queda como una transacción firmada y como
estado leíble por cualquiera vía `GET /treasury`.

---

## 1. Modelo de seguridad (los 7 requisitos)

| Requisito del usuario | Cómo se cumple |
|---|---|
| **Multisig real (ej. 3 de 5)** | `TreasuryState { signers: Vec<Pubkey>, threshold: u8 }`. Una operación se ejecuta sólo tras acumular `threshold` aprobaciones **de firmantes distintos** (dedup on-chain, determinista → sin fork). |
| **Timelock antes de liberar / cambiar autoridad** | `timelock_rounds`. Al alcanzar el umbral se graba `threshold_reached_round`; la operación recién es ejecutable en `threshold_reached_round + timelock_rounds` (ventana de revisión real). Aplica a **toda** operación: releases, cambio de firmantes y cambio de política. |
| **Límite máximo por operación** | `max_per_release` (0 = sin límite). Un `Release` por encima del tope se **rechaza en la ejecución**, sin mover fondos. |
| **Límite por periodo** | `max_per_window` sobre una **ventana rodante** de `window_rounds`. Los releases dentro de la ventana se acumulan (`released_in_window`); la ventana se reinicia sola cuando pasa `window_rounds` → un release viejo deja de contar. |
| **Eventos públicos y auditables** | No hay estado oculto: firmantes, umbral, límites, ventana, y **cada operación pendiente con sus aprobaciones** se sirven en claro por `GET /treasury`. Cada Propose/Approve/Execute/Cancel es una tx firmada on-chain. |
| **Direcciones en génesis, no constantes** | Los firmantes, el umbral, los límites y la **wallet administrativa** (`--admin-fee-wallet`) se configuran al crear la red y se **pliegan en el `chain_id`**. Nada de direcciones administrativas hardcodeadas. |
| **Claves frías / HSM** | Cada firmante es una clave independiente. El flujo se puede firmar **air-gapped** con el CLI (una máquina offline firma la tx; otra la difunde) — mismo esquema PQC, sin exponer ninguna clave al nodo. Ver §5. |
| **Recuperación y sustitución de firmantes** | La operación `SetSigners{signers, threshold}` (también sujeta a umbral + timelock) **reemplaza el set completo** — así se rota una clave perdida o comprometida. Al ejecutarse **descarta todas las operaciones pendientes** (una propuesta aprobada bajo el set viejo no puede ejecutarse bajo el nuevo). |

**El pause/ejecución NUNCA confía en una sola clave**, y una liberación grande
se reparte forzosamente entre varias personas + una ventana de revisión + topes.

---

## 2. Máquina de estados on-chain

```
TreasuryState {
  signers: Vec<Pubkey>,          // los N firmantes (máx 16)
  threshold: u8,                 // M (aprobaciones distintas requeridas)
  timelock_rounds: u64,          // demora tras alcanzar el umbral
  max_per_release: u64,          // tope por operación (0 = sin tope)
  max_per_window: u64,           // tope por ventana rodante (0 = sin tope)
  window_rounds: u64,            // largo de la ventana (0 = deshabilitada)
  window_start_round: u64,       // inicio de la ventana rodante vigente
  released_in_window: u64,       // acumulado liberado en la ventana
  next_op_id: u64,               // id incremental de operaciones
  pending: Vec<PendingOp>,       // operaciones en curso (máx 16)
}

PendingOp { id, op, proposed_round, approvals: Vec<Pubkey>, threshold_reached_round }
TreasuryOp = Release{amount,destination} | SetSigners{signers,threshold} | SetPolicy{...}
```

**Instrucción** `TreasuryV7Instruction`:

- `Propose{op}` — un **firmante** abre una operación; la propuesta cuenta como su
  primera aprobación. (payer debe ser firmante.)
- `Approve{op_id}` — otro **firmante** aprueba (dedup: no puede aprobar dos veces).
  Al llegar a `threshold` se graba `threshold_reached_round`.
- `Execute{op_id}` — **PERMISSIONLESS** (cualquiera puede disparar la ejecución de
  una operación ya aprobada y madura). Verifica: umbral alcanzado + timelock
  cumplido + (para Release) tope por-op + tope por-ventana + destino == el
  aprobado. Recién ahí mueve fondos (aritmética chequeada `checked_sub/add`).
- `Cancel{op_id}` — un **firmante** cancela una operación pendiente.

Todo es **determinista** (función del estado y la ronda comprometidos) → todos
los validadores computan lo mismo → sin fork.

---

## 3. Crear una red con tesorería multisig (génesis)

```bash
qchain-genesis-build \
  --manifests-dir manifests --out-dir out --genesis genesis.json \
  --economics-v7 --rounds-per-quanto 172800 \
  --treasury-signer <b58-firmante-1> \
  --treasury-signer <b58-firmante-2> \
  --treasury-signer <b58-firmante-3> \
  --treasury-signer <b58-firmante-4> \
  --treasury-signer <b58-firmante-5> \
  --treasury-threshold 3 \
  --treasury-qch 5000 \
  --treasury-timelock-rounds 5760 \        # p.ej. ~1h a 1 ronda cada 0.5s → ajustar
  --treasury-max-per-release-qch 1000 \
  --treasury-max-per-window-qch 5000 \
  --treasury-window-rounds 172800 \        # ventana ~1 día
  --admin-fee-wallet <b58-tesorería-o-cold-wallet>
```

- `--treasury-threshold 0` = **mayoría** (`floor(N/2)+1`).
- Los límites en **QCH enteros** (0 = sin límite).
- `--admin-fee-wallet` fija el destino del **10% de fee administrativo**
  (genesis-configurado, plegado en el `chain_id`). **Apuntalo a la propia
  tesorería multisig** para que la revenue administrativa también quede protegida
  por el M-de-N. Si se omite, cae a la constante por defecto (byte-idéntico a una
  red pre-#222 → conserva su `chain_id`).
- Todo lo anterior se pliega en el `chain_id` **sólo cuando se configura** → una
  red sin multisig y sin admin-wallet override conserva su `chain_id` exacto.

> **Cambio de semántica → relanzamiento.** Configurar el multisig o el
> admin-wallet cambia el `chain_id` → **NO es un update en caliente**; se decide
> al **crear** la red (mismo procedimiento que cualquier decisión de génesis v7).

### Compatibilidad brick-safe con una red viva

Una red v7 **ya desplegada** con una `authority` única (formato legacy de 32
bytes) **sigue arrancando** tras actualizar el binario: el lector de estado
levanta ese blob de 32 bytes como un multisig **1-de-1** (`TreasuryState::single`).
La red no se brickea; y desde ahí se puede migrar a un M-de-N real con una
operación `SetSigners` **sin relanzar** (la autoridad única propone+ejecuta el
cambio a 3-de-5). Un estado genuinamente corrupto (ni multisig ni legacy de 32B)
**falla ruidoso** (no arranca) — la lección #217/#218: distinguir *ausente*
(tolerar) de *corrupto* (fail-loud) para lo que guarda dinero/autoridad.

---

## 4. Operar la tesorería (CLI)

```bash
# 1) un firmante PROPONE una liberación (cuenta como su aprobación)
qchain treasury-propose-release --rpc <url> --keypair firmante1.json \
  --to <destino> --amount <QCH-units>      # imprime el op-id

# 2) otros firmantes APRUEBAN hasta el umbral
qchain treasury-approve --rpc <url> --keypair firmante2.json --op-id <id>
qchain treasury-approve --rpc <url> --keypair firmante3.json --op-id <id>

# 3) tras el timelock, CUALQUIERA ejecuta
qchain treasury-execute --rpc <url> --keypair firmante1.json --op-id <id> --to <destino>

# ver estado completo (firmantes, límites, ventana, pendientes con aprobaciones)
qchain treasury-status --rpc <url>       # o:  curl <url>/treasury

# ROTAR firmantes (recuperación / sustitución) — sujeto a umbral + timelock
qchain treasury-propose-set-signers --rpc <url> --keypair firmante2.json \
  --signer <nuevo1> --signer <b> --signer <c> --signer <d> --signer <e> --threshold 3
# aprobar + ejecutar igual que un release

# CAMBIAR política (timelock / límites) — sujeto a umbral + timelock
qchain treasury-propose-set-policy --rpc <url> --keypair firmante2.json \
  --timelock-rounds <r> --max-per-release-qch <x> --max-per-window-qch <y> --window-rounds <w>

# cancelar una operación pendiente
qchain treasury-cancel --rpc <url> --keypair firmante2.json --op-id <id>
```

`GET /treasury` devuelve, por operación pendiente: `id`, tipo+detalle, `approvals`,
`approval_count`, `threshold`, `threshold_reached_round`, `executable_round`,
`executable_now` — el registro de auditoría público.

---

## 5. Claves frías / firmante air-gapped (sin HSM dedicado)

No existe hoy hardware wallet (Ledger/Trezor) que hable el esquema híbrido
PQC Ed25519+ML-DSA-65, así que la protección de clave fría es **procedimental**:

1. Cada firmante genera su `keypair.json` en una **máquina offline** (`qchain keygen`).
2. La clave **nunca toca el nodo ni internet**. Sólo su dirección base58 pública
   entra en el génesis (`--treasury-signer`).
3. Para aprobar/proponer, la tx se firma en la máquina offline y el **JSON firmado**
   se difunde desde otra máquina — mismo flujo air-gapped que el resto del CLI.
4. Al ser M-de-N, comprometer una clave no basta: se necesitan `threshold` firmas
   de dispositivos/personas distintos, y hay `timelock` para reaccionar (rotar la
   clave comprometida con `SetSigners` durante la ventana).

El firmante remoto/HSM del consenso (`qchain-remote-signer`, tarea #193) es un
proceso separado para la clave de bloque; la tesorería usa el mismo principio de
clave-fuera-del-proceso vía el flujo air-gapped del CLI.

---

## 6. Verificado en vivo (3-de-5)

Testnet v7 real, tesorería 5000 QCH bajo 3-de-5, timelock 5 rondas, tope 1000
QCH/op, 1500 QCH/ventana de 100 rondas, admin-wallet override:

- `GET /treasury` muestra el 3-de-5 completo con todos los límites.
- Propose(s1)→Approve(s2,s3) → umbral 3 → `executable_round = threshold_reached + 5`.
- **Ejecución tras el timelock**: tesorería 5000→4700, destino +300 QCH, ventana=300.
- **No-firmante (outsider)**: su Approve se ignora on-chain (aprobaciones siguen en 1).
- **Ejecución prematura** (antes de umbral / timelock): rechazada, sin mover fondos.
- **Tope por-op**: un release de 1001 QCH (> 1000) rechazado, tesorería intacta.
- **Tope por-ventana**: la ventana rodante envejece los releases viejos y bloquea
  el que excedería 1500 en la ventana vigente.
- **Admin-fee override**: el 10% administrativo se acredita en la dirección
  configurada (no en la constante).
- **Rotación**: `SetSigners` reemplaza s1→s6, **descarta las operaciones pendientes**,
  el firmante removido (s1) ya no puede proponer y el nuevo (s6) sí.
