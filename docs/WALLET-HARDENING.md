# Endurecimiento de la wallet web (v8.1.0)

La wallet no-custodial (`/`) es una **web app**: su código se descarga del
servidor en cada carga y la semilla vive temporalmente en la memoria del
navegador. Este documento describe las defensas aplicadas, y — con honestidad —
lo que **no** resuelven y por qué.

## Modelo de amenaza

1. **JavaScript malicioso servido/inyectado** que roba la semilla al desbloquear.
2. **Replay de una transacción firmada** que quedó atascada/capturada y se
   ejecuta mucho después.

## Qué se hizo

### 1. JS externo + CSP estricta + SRI (contra inyección/XSS)
- Todo el código de la app se sirve como un **archivo externo versionado por
  content-hash** (`/app/app-<sha256[:12]>.js`) en vez de inline.
- La **CSP quita `'unsafe-inline'` del `script-src`**
  (`script-src 'self' 'wasm-unsafe-eval'`): un `<script>` inyectado por un XSS
  ya **no se ejecuta**. `'wasm-unsafe-eval'` queda sólo para instanciar el
  firmante WASM (no es `'unsafe-inline'`).
- El `<script>` lleva **SRI** (`integrity="sha384-…"`). El hash SRI y la URL se
  computan **en Rust** a partir de los mismos bytes embebidos, así el
  `integrity=` del HTML **nunca puede driftear** de lo que se sirve.
- `style-src` conserva `'unsafe-inline'` **a propósito**: la UI usa ~155
  `style=` inline (no hasheables por atributo), y una inyección de CSS **no
  puede exfiltrar la semilla** con `connect-src 'self'` + `img-src` acotado.

### 2. Provenance verificable en la app
- `GET /api/version` expone la versión + **SHA-256 de app.js, del glue WASM y
  del binario WASM** + el SRI de app.js.
- La pantalla **Ajustes → "Seguridad · verificación de la app"** los muestra y
  permite copiarlos.
- `deploy/wallet-asset-manifest.sh` produce un **manifiesto determinista** de
  esos hashes (`crates/qchain-wallet/wallet-assets.manifest.txt`), que
  `deploy/sign-release.sh` incluye bajo la **firma GPG** del release.
- **Reproducibilidad:** el toolchain está pinneado (`rust-toolchain.toml`) y el
  build WASM es determinista → cualquiera puede reconstruir y comparar los
  hashes contra el release firmado. (La reproducibilidad bit-a-bit completa
  necesita además `SOURCE_DATE_EPOCH`; el pin de toolchain + deps ya fija los
  dos inputs principales.)

### 3. TTL obligatorio en TODA transacción (contra replay)
Cada tx firmada por la wallet o el CLI lleva un `valid_until_round` acotado —
**nunca `0`** (que el nodo interpreta como "sin caducidad"):
- **Wallet:** transferencias, staking (v6 y v7), gobernanza (voto/finalizar/
  ejecutar) y contratos. Un helper único (`txValidUntil`, ventana de 300 rondas)
  es **fail-closed**: si no puede leer la ronda actual del nodo, **no firma**.
- **CLI:** transferencias, staking, gobernanza, **tesorería** y **registro de
  validadores** caducan en `DEFAULT_CLI_TTL_ROUNDS` (3600) por defecto,
  ajustable con `--valid-for-rounds`.
El nodo ya rechaza una tx caducada en admisión y en ejecución (desde v6.13.0).

### 4. BigInt en nonces, rondas y montos
Los montos, nonces y el valor de ronda firmado (`valid_until_round`) se manejan
como `BigInt` en el navegador (un `Number` rompería el `u64` de wasm-bindgen y
perdería precisión sobre 2^53). Las rondas usadas sólo para mostrar quedan como
`Number` (no entran en ningún valor firmado).

## Límites honestos (lo que esto NO resuelve)

- **SRI/CSP servidos por el MISMO origen NO defienden contra un servidor
  genuinamente malicioso.** Si el servidor está comprometido, sirve un app.js
  malicioso **y** reescribe el `integrity=` y el `/api/version` para que
  calcen. SRI sólo ayuda cuando el HTML y el script vienen de dominios de
  confianza **distintos** (ej. HTML propio + script de un CDN). Para una wallet
  auto-servida, SRI frena un **XSS/inyección** y una manipulación en tránsito de
  **un** recurso — no a su propio servidor.
- **La defensa real contra un servidor malicioso** es que el usuario **compare
  la huella mostrada en la app contra un release FIRMADO publicado fuera de
  banda** (GitHub release firmado por el maintainer), o que use código que el
  servidor **no re-sirve en cada carga** (extensión de navegador / hardware).
  Por eso existen el hash visible + el manifiesto firmado + el build
  reproducible: **detectabilidad**, no prevención absoluta.

## Hardware wallet / firmante externo — estado real

- **Hardware wallet dedicada (Ledger/Trezor): DIFERIDA, y no por falta de
  ganas.** Qchain firma con un esquema **híbrido post-cuántico**
  (Ed25519 + ML-DSA-65). **Ningún hardware wallet del mercado habla ML-DSA**
  todavía, así que no hay dispositivo al que delegar la firma tal cual. Cuando
  aparezca soporte PQC en hardware (o un secure element programable con
  ML-DSA), se integra.
- **Lo que YA existe como respaldo por hardware:** el **desbloqueo biométrico
  WebAuthn-PRF** (v3.0.2) ata la **clave de cifrado** de la semilla al **enclave
  seguro** del teléfono (Secure Enclave / StrongBox / Keystore). El material de
  esa clave nunca entra al navegador: la semilla **en reposo** queda protegida
  por hardware. (Protege el almacenamiento, no la firma en sí.)
- **Firmante externo disponible HOY para fondos importantes — flujo air-gapped
  con el CLI:** el CLI (`qchain keygen` / `qchain transfer` …) firma con el
  **mismo** esquema, **sin conexión**. Para valor alto:
  1. `qchain keygen` y `qchain transfer` en una **máquina offline** (air-gapped)
     → produce la tx firmada (JSON).
  2. Se copia el JSON a una máquina online y se difunde (`POST /tx` /
     `/api/relay-tx`).
  La clave nunca toca una máquina conectada — el equivalente práctico a un
  firmante externo, sin hardware especial. (El daemon `qchain-remote-signer`
  cumple este rol para la clave de **consenso** de un validador; para fondos de
  usuario, el flujo air-gapped del CLI es el camino recomendado hasta que haya
  hardware wallet PQC.)

## Recomendación

- Uso normal: contraseña fuerte (PBKDF2 600k) + biométrico WebAuthn-PRF +
  respaldo Shamir. Verificá la huella en Ajustes contra el release firmado tras
  cada actualización.
- Fondos importantes: firmá con el CLI en una máquina air-gapped y difundí desde
  otra; o esperá soporte de hardware wallet PQC (diferido).
