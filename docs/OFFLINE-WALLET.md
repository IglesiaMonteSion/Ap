# Wallet offline / air-gapped (roadmap #11)

Para **fondos importantes**, la clave privada NUNCA debe estar en una máquina
conectada a internet. El CLI `qchain` implementa el flujo **air-gapped** de tres
pasos (estilo PSBT de Bitcoin / cold wallet): la máquina online nunca ve la
clave, y la máquina con la clave nunca toca la red.

```
  ONLINE (watch-only)          OFFLINE (air-gapped, con la clave)        ONLINE
  ┌──────────────────┐   USB   ┌───────────────────────────────┐  USB   ┌──────────────┐
  │ transfer-prepare │ ──────► │ tx-sign  (revisar + firmar)   │ ─────► │ tx-broadcast │
  │  (solo dirección)│unsigned │  (CERO red, verificado unshare)│ signed │ (verifica+POST)│
  └──────────────────┘  .json  └───────────────────────────────┘  .json  └──────────────┘
```

## Los tres pasos

### 1. `transfer-prepare` (ONLINE, watch-only — solo la dirección pública)
```bash
qchain transfer-prepare --rpc http://<nodo>:8080 \
  --from <TU_DIRECCIÓN_PÚBLICA> --to <DESTINO> --amount <units> \
  --valid-for-rounds 3600 --out unsigned-tx.json
```
Trae `chain_id` + `nonce` (de la dirección) + la ronda actual (para el TTL) y
escribe `unsigned-tx.json`. **No lee ninguna clave** — corre en la máquina
conectada, que nunca ve el secreto. El archivo lleva sólo campos públicos.

Copiá `unsigned-tx.json` a la máquina OFFLINE (USB, etc.).

### 2. `tx-sign` (OFFLINE, con la clave — CERO red)
```bash
qchain tx-sign --keypair cold-key.json --request unsigned-tx.json --out signed-tx.json
```
Muestra **exactamente** qué se va a firmar (from/to/monto/fee/chain_id/nonce/
expiración) para revisar en la pantalla del equipo air-gapped, exige confirmación
(`type 'yes'`), verifica que la clave **sea el payer** de la solicitud (sólo
podés firmar una tx desde tu propia cuenta), firma y escribe `signed-tx.json`.
**Este comando NO hace ninguna llamada de red** (verificado corriéndolo dentro de
un namespace sin red, `unshare -rn`).

Copiá `signed-tx.json` de vuelta a la máquina ONLINE.

### 3. `tx-broadcast` (ONLINE)
```bash
qchain tx-broadcast --rpc http://<nodo>:8080 --tx signed-tx.json
```
**Re-verifica la firma localmente** antes de enviar (rechaza una tx manipulada
sin siquiera contactar al nodo) y hace `POST /tx`.

## Por qué es seguro

- La clave privada vive SÓLO en la máquina offline. La online nunca la ve
  (`transfer-prepare` sólo necesita la dirección pública; `tx-broadcast` sólo
  maneja la tx ya firmada).
- La firma cubre **todos** los campos (chain_id, nonce, fee_limit, expiración,
  instrucción) — el firmante offline no puede cambiar en silencio lo que se
  revisó, y `tx-broadcast` re-verifica antes de enviar. Un byte cambiado en el
  mensaje O en la firma → rechazado local y por el nodo (`invalid transaction
  signature`).
- El TTL (`--valid-for-rounds`, default 3600) acota la ventana: si el traslado
  de archivos tarda demasiado, el nodo rechaza la tx caducada en vez de dejarla
  válida para siempre.
- `tx-sign` refusa firmar si la clave no es el payer de la solicitud.

## Verificado en vivo (end-to-end)

Contra un nodo real: `transfer-prepare` (sin clave) → `tx-sign` **dentro de
`unshare -rn` (sin red)** rechazando la clave equivocada → `tx-broadcast`
rechazando una tx con mensaje alterado Y con firma alterada → broadcast de la
real → el destino recibió los fondos exactos. Más 3 unit tests
(`air_gapped_tests`) del firmado offline (reconstruye la tx exacta y verifica;
refusa una clave ajena; refusa un formato desconocido).

## Límites honestos

- Es el flujo air-gapped por **archivo/USB**. Un QR de un solo código no alcanza:
  una tx post-cuántica lleva una firma ML-DSA-65 (~3,3 KB) + el bundle de clave
  pública (~2 KB), demasiado para un QR. El transporte real es archivo/USB.
- Un **hardware wallet dedicado** sigue diferido: ningún dispositivo del mercado
  (Ledger/Trezor) habla el esquema híbrido PQC Ed25519+ML-DSA-65, así que no hay
  a quién delegar la firma en hardware. El flujo air-gapped del CLI ES el
  "firmante externo" real hoy (la clave en una máquina dedicada sin red); el
  biométrico WebAuthn-PRF de la wallet web (v3.0.2) ata el CIFRADO de la semilla
  al enclave del teléfono, un eje complementario.
- `transfer-prepare` cubre transferencias (el caso de "fondos importantes"). Los
  pasos `tx-sign`/`tx-broadcast` son genéricos (firman/difunden cualquier
  instrucción preparada), así que extender a staking/gobernanza es agregar más
  comandos `*-prepare`, sin tocar la firma ni el broadcast.
