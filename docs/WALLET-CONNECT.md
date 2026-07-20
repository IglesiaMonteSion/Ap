# Puente wallet-connect — spec de construcción (listo para ejecutar)

Este documento deja **todas las decisiones tomadas** para que, apenas exista el
dominio estable (ej. `wallet.qchainhq.com` / `scan.qchainhq.com`), el puente
wallet-connect se construya de forma mecánica, sin re-diseñar nada. Habilita:
**desplegar/interactuar con contratos desde QScan firmando con la wallet**.

## Estado de prerequisitos

| Pieza | Estado |
|---|---|
| Túnel nombrado (URL fija) `install-tunnel.sh --hostname` | ✅ hecho (v6.7.3) |
| Runbook del dominio `docs/DOMAIN-SETUP.md` | ✅ hecho (v6.7.3) |
| Sección Contratos read-only en QScan (`/programs`, `/api/programs`, UI) | ✅ hecho (v6.7.2) |
| Firma de contratos en la wallet (`signDeployProgram`/`signCallProgram`) | ✅ hecho (v6.7.4) |
| **Dominio propio estable** (`qchainhq.com`) | ✅ el usuario lo tiene |
| **Puente wallet-connect** (listener postMessage + UI) | ✅ hecho (v6.8.0) |
| UI de deploy/interact en QScan | ✅ hecho (v6.8.0) |
| SDK Rust de contratos | ⏳ para producir el `.wasm` (pendiente) |

> **ETAPA 2 IMPLEMENTADA (v6.8.0)** — el puente funciona de punta a punta. La wallet
> arranca con `--connect-origin https://scan.qchainhq.com`, el indexer (QScan) con
> `--wallet-url https://wallet.qchainhq.com`. QScan abre la wallet en un popup y le
> pide firmas por `postMessage` (origen validado en ambos lados); la wallet muestra
> una aprobación humana y firma; la semilla nunca sale del navegador. Verificado en
> vivo el data path completo (deploy firmado por el código de la wallet → `/programs`
> lo lista → proxies `/api/programs` y `/api/config` correctos).

## Por qué el puente ESPERA al dominio (no es pereza, es seguridad)

Toda la seguridad del puente descansa en **atar la confianza a un origen fijo**
(`event.origin === https://scan.qchainhq.com`). Con la URL random del quick-tunnel
(que cambia al reiniciar) el allowlist de origen es frágil/imposible. Además, el
flujo completo (QScan arma tx → wallet muestra en humano → firma → submit →
converge) hay que **verificarlo en vivo contra el origen real** — no se shippea
código de firma sin esa prueba (disciplina del proyecto). Con el dominio, el
allowlist es un valor de config y la prueba en vivo es directa.

## Transporte elegido: puente `postMessage` (MVP seguro)

Camino B de la charla de diseño (ver la nota en `CLAUDE.md`). La extensión de
navegador (camino A) queda como evolución futura (más segura por aislamiento
total, pero codebase nuevo por navegador). WalletConnect/QR (camino C) para
móvil, follow-up. El `postMessage` es el MVP correcto con un dominio estable.

### Topología
- QScan (`scan.qchainhq.com`, **no confiable**, read-only) abre la wallet
  (`wallet.qchainhq.com`, **límite de confianza**, tiene las claves) en un
  **popup** (`window.open`).
- Se comunican por `window.postMessage`. La clave/semilla NUNCA cruza — QScan
  manda una **intención sin firmar**, la wallet devuelve la **tx firmada** (o la
  submitea ella misma).

### Protocolo de mensajes (JSON, versionado)
Todos los mensajes llevan `{ v: 1, id: <uuid>, type, ... }`. La wallet responde
al `id` del pedido.

**QScan → wallet:**
- `{ type: "connect" }` → la wallet muestra "scan.qchainhq.com quiere conectarse
  — ¿aprobar?" y, si el usuario acepta, responde `{ type: "connected", address }`
  (SOLO la dirección pública, read-only).
- `{ type: "signAndSubmit", tx: { kind: "deployProgram" | "callProgram", ...campos } }`
  → la wallet **decodifica y muestra en HUMANO** ("Desplegar contrato de N KB,
  fee X QCH" / "Llamar contrato Z, args …, fee X QCH") + botón Aprobar/Rechazar.
  Si aprueba: firma con la semilla del navegador (mismo `qchain-wasm` que ya usa
  la wallet), submitea al nodo, y responde `{ type: "submitted", hash }` o
  `{ type: "rejected" }` / `{ type: "error", msg }`.
- `{ type: "disconnect" }`.

**wallet → QScan:** las respuestas de arriba + `{ type: "ready" }` al cargar.

### Los 5 invariantes de seguridad NO NEGOCIABLES (enforced en el código)
1. **La semilla NUNCA sale de la wallet.** QScan solo recibe `address` o `hash`.
2. **La wallet muestra en humano qué se firma** + aprobación explícita **por cada
   acción**. Nada de firma ciega. (Decodifica el tx del lado wallet, no confía en
   un texto que mande QScan.)
3. **Allowlist estricto de origen, validado en CADA `postMessage`**
   (`if (event.origin !== ALLOWED_ORIGIN) return;`) — no solo al conectar.
4. **Conectar = solo lectura de la dirección.** Cada `signAndSubmit` re-pregunta.
5. **Siempre iniciado por el usuario** (click "Conectar" en QScan).

## Cambios de código (cuando se ejecute)

### Wallet (`qchain-wallet`)
- **Config nuevo**: `--connect-origin <https://scan.tudominio.com>` (o env
  `QCHAIN_CONNECT_ORIGIN`) → el allowlist. Sin esto seteado, el listener de
  `postMessage` queda **apagado** (feature off por defecto = hoy byte-idéntico).
- **`wasm_wallet.html`** gana un listener `window.addEventListener("message", …)`
  con el chequeo de origen (invariante 3) + un modal de aprobación humana
  (invariante 2) que reusa `signTransfer`/`signDelegate`/… y para contratos un
  `signDeployProgram`/`signCallProgram` nuevos en `qchain-wasm` (encoding de
  `SystemInstruction::DeployProgram`/dispatch de contrato; **regenerar los
  assets WASM** — lección v3.0.4).
- La wallet solo actúa como "connectee" cuando fue abierta con `window.opener`
  (es un popup) y el origen está en el allowlist.

### QScan (`qchain-indexer`)
- **Config nuevo**: `--wallet-url <https://wallet.tudominio.com>` (o env) → a
  dónde abrir el popup. Sin esto, la sección Contratos sigue **solo-lectura**
  (hoy).
- **`qscan.js`**: botón "Conectar wallet" + formularios de Desplegar (subir
  `.wasm` + entry point) e Interactuar (dirección + args); arman el tx sin
  firmar, abren el popup de la wallet, mandan `signAndSubmit`, reciben el `hash`
  y muestran el resultado enlazando a la tx.

### Nodo
- **Sin cambios.** El deploy/call ya existen (`DeployProgram`, dispatch de
  contrato). El puente solo cambia *quién arma y firma* la tx (la wallet en el
  navegador), no el protocolo.

## Plan de verificación
1. **Enforcement de origen (unit/harness, sin dominio)**: un `postMessage` desde
   un origen NO permitido (localhost:B) es ignorado; desde el permitido
   (localhost:A) dispara el modal. Testeable ya con dos orígenes locales.
2. **Flujo completo EN VIVO (con el dominio)**: desde `scan.tudominio.com`,
   "Conectar" → aprobar en `wallet.tudominio.com` → Desplegar un `.wasm` → la
   wallet muestra "Desplegar contrato de N KB, fee X" → aprobar → firma+submit →
   el contrato aparece en la sección Contratos (que ya lista `/programs`).
3. Regresión: sin `--connect-origin`/`--wallet-url`, wallet y QScan
   byte-idénticos a hoy (feature off por defecto).

## Checklist de puesta en marcha (cuando el usuario dé el dominio)
1. Comprar dominio + Cloudflare + `cloudflared tunnel login` (ver `DOMAIN-SETUP.md`).
2. `install-tunnel.sh --hostname wallet.<dom> --qscan-hostname scan.<dom>` → URLs fijas.
3. Ejecutar este spec: los `signDeployProgram`/`signCallProgram` + listener de la
   wallet + UI de QScan + los dos flags de config.
4. Verificar según el plan de arriba (enforcement local + flujo en vivo).
5. (Después) SDK Rust para producir `.wasm` cómodo.
