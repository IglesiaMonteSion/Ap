# Plan de pruebas OBLIGATORIO pre-lanzamiento

Gate de lanzamiento: tras corregir el código, correr una **testnet real con varios
operadores** durante **varias semanas** sin que se rompa ninguna de las 5
invariantes duras. Este documento mapea CADA escenario requerido a una
herramienta concreta + criterio de pass/fail, y define el protocolo del soak.

## Límite honesto (qué es operativo y qué está automatizado)

- **NO automatizable desde el código:** conseguir 10–20 VPS independientes en
  regiones/proveedores distintos, con operadores distintos, y correrlo semanas.
  Eso es un proceso humano/operativo (misma clase que la auditoría externa +
  bug bounty, tarea #203). Nadie puede "ejecutarlo" en una sesión.
- **SÍ automatizado (lo que este repo entrega):**
  - `deploy/chaos-test.sh` — inyecta las fallas MECÁNICAS en una máquina y
    verifica convergencia sin fork tras cada una (smoke repetible).
  - `deploy/soak-canary.py` — monitor CONTINUO de las 5 invariantes contra
    TODOS los RPC de la red real, durante todo el soak.
  - `deploy/qchain-watchdog.py` — alertas de runtime (fork, RAM/disco, stall,
    fee spike, emisión fuera de rango) por ntfy/Discord/Slack.
  - El **DST** (`cargo test -p qchain-simulation`, 11/11) prueba safety+liveness
    del CONSENSO de forma determinista bajo pérdida de certificados y un
    validador equivocador — la garantía más fuerte, sin depender de suerte.

## Las 5 invariantes que NO deben romperse (criterio de FALLA del gate)

| # | Invariante | Quién la vigila |
|---|---|---|
| 1 | Sin **raíces divergentes** (mismo nº de tx ejecutadas ⟹ mismo Merkle root) | `soak-canary.py` (FORK), `chaos-test.sh`, watchdog |
| 2 | **Supply consistente** (conservación por-nodo + acuerdo cross-node) | `soak-canary.py` (SUPPLY, con `--genesis-supply`) |
| 3 | Sin **pérdida de tx finalizada** (canary tracked; el saldo alcanza lo enviado en todos los nodos) | `soak-canary.py` (TXLOSS) |
| 4 | Sin **crecimiento descontrolado de RAM/disco** | `soak-canary.py` (RAM/DISK), watchdog |
| 5 | Sin **congelamiento tras reinicios** (la ronda avanza) | `soak-canary.py` (FREEZE), watchdog, chaos-test |

`soak-canary.py` sale `!=0` y marca `VERDICT: FAIL` si una invariante DURA
(fork/supply/tx-loss) se rompe → el operador detiene el gate.

## Los 18 escenarios requeridos → cómo probar cada uno

| Escenario | Herramienta / cómo | Criterio de PASS |
|---|---|---|
| **10–20 validadores independientes** | `install-node.sh` en cada VPS (`--modo unirse`), o `qchain-genesis-build` para el set inicial. Ver `DEPLOY.md`. | Los N forman malla, comparten `chain_id`, avanzan en lockstep |
| **Distintas VPS y regiones** | Un VPS por operador en regiones distintas (Oracle/Contabo/etc.). `provision-validator.sh` + NTP. | Convergen pese a la latencia inter-región |
| **Caída y recuperación de nodos** | `chaos-test.sh` (SIGTERM+restart) · en vivo: `systemctl stop/start qchain-validator` | Red sigue con quórum; el nodo re-sincroniza y converge |
| **Cortes de energía** | `chaos-test.sh` (SIGKILL ungraceful+restart) · en vivo: `kill -9` / reiniciar la VPS | Arranca desde disco (flush por-ronda), sin fork, resume |
| **Disco lleno** | En la VPS: `fallocate -l <casi-todo> /data/fill` → observar → borrar. | El nodo maneja ENOSPC sin corromper estado (borra/errorea, no escribe basura); tras liberar, resume |
| **Corrupción de archivos** | El nodo v8.2.0+ **falla-fuerte** (halt) ante un singleton de DINERO corrupto y **tolera** un registro de validadores corrupto (fallback al comité de génesis). Reproducible con el helper de corrupción del store. | Money singleton corrupto → NO arranca (fail-loud); validator registry corrupto → arranca y cae al comité de génesis |
| **Pérdida, retraso y duplicación de paquetes** | `chaos-test.sh --with-netem` (tc netem loss/delay/duplicate en la iface) | Converge bajo pérdida; al limpiar, sigue sin fork |
| **Particiones de red** | `chaos-test.sh --with-partition` (iptables DROP entre nodos) · en vivo: firewall entre regiones | Al sanar la partición, converge (sin dos historias) |
| **Validadores bizantinos** | **DST** escenario `Equivocator` (11/11) + el inyector externo de equivocación (usa una clave de validador para proponer dos vértices en conflicto) | El equivocador es slasheado; la red no forkea |
| **Batches maliciosos** | Cubierto por el **batch-vertex gating** (#175): un batch no referenciado por un vértice válido nunca se ejecuta ni se persiste. + el inyector de data-availability. | Un batch retenido/basura no cuelga ni forkea la red |
| **Transacciones inválidas** | `qchain stress` mezcla + tx con firma/nonce/fee malos; el nodo las rechaza en admisión. Cubierto por tests de `qchain-execution`. | Rechazadas sin afectar el estado; supply intacto |
| **Contratos que agotan gas** | Desplegar un contrato busy-loop (ver `SMART-CONTRACTS.md`) y llamarlo con `fee_limit` ajustado; el fuel se cobra al `fee_limit` firmado (#206). | Trap out-of-fuel, se cobra ≤ fee_limit, cambios descartados |
| **Reinicios en cambios de época** | `chaos-test.sh` (ESCENARIO 3: mata/reinicia en el borde de quanto) | Converge cruzando el borde; sin fork |
| **Entrada y salida de validadores** | Rotación dinámica (fase 3.3) con `validator_rotation:true` en un testnet dedicado: `register-validator` / `unregister-validator`. **DST** cubre rotación+shrink bajo pérdida de certs. | El comité crece/encoge en el borde de época sin fork |
| **Slashing** | `report-equivocation` con evidencia real (el inyector la produce). Tests de `qchain-execution::staking`. | El bono del equivocador se quema; converge |
| **State sync desde cero** | Borrar el `data_dir` de un nodo y reiniciarlo con `state_sync_peers` (#109/#212). | Descarga snapshot verificado (root coincide), resume |
| **Floods prolongados** | `qchain stress --fire-and-forget` / `--sustained-secs` (ver `run-stress.sh`) durante horas. | Sin fork; el fee sube y DECAE; RAM/disco acotados; nada perdido |
| **Invariantes de supply y conservación** | `soak-canary.py --genesis-supply <N>` en vivo + el **DST diferencial económico** (`invariants_v7`, #182). | `balances + burned − emitted == génesis` en todo momento y nodo |

## Cómo correr el soak (protocolo)

### 1. Smoke local de las fallas mecánicas (antes de desplegar)
```bash
cargo build --release -p qchain-node -p qchain-cli
deploy/chaos-test.sh --nodes 4 --rpq 15                     # básico (crash/kill/epoch)
deploy/chaos-test.sh --nodes 4 --with-netem --with-partition  # + red (necesita root: tc/iptables)
```
Debe imprimir `RESULTADO CAOS LOCAL: PASS=N FAIL=0`.

### 2. Testnet real de 10–20 validadores (varias semanas)
- Cada operador levanta su nodo (`install-node.sh`), todos con el MISMO
  `chain_id` (verificado con `qchain-genesis-build`, que lo imprime).
- Endurecer: `network_profile:"mainnet"` (fail-stop #211), auth+cifrado P2P,
  RPC privado, remote-signer, límites systemd (`install-limits.sh`), backups
  (`backup-node.sh`).

### 3. Monitoreo continuo durante todo el soak
```bash
# El coordinador corre el canary contra TODOS los RPC (mejor sobre una réplica
# read-only o por túnel, no exponiendo el RPC del validador):
deploy/soak-canary.py \
  --node v1=http://IP1:8080 --node v2=http://IP2:8080 ...  \
  --qchain-bin ./target/release/qchain \
  --sender-keypair bank.json --canary-recipient <ADDR> \
  --genesis-supply <SUPPLY_TOTAL_DE_GENESIS> \
  --ram-max-mb 3000 --disk-max-mb 20000 --stall-secs 90 \
  --out soak.jsonl
# En paralelo, cada operador corre el watchdog para alertas push:
deploy/qchain-watchdog.py --node self=http://127.0.0.1:8080 ...
```

### 4. Criterio de aprobación del gate
La red corrió **varias semanas** y en `soak.jsonl` **no hay** ni un solo evento
`FORK`, `SUPPLY` (cross-node o conservación), ni `TXLOSS`; los eventos `FREEZE`/
`RAM`/`DISK` (si los hubo) se explican por caos inyectado y se recuperaron. Sólo
entonces se corta el release firmado (`docs/RELEASE-VERIFY.md`).

## Qué ya está PROBADO (no hay que re-descubrirlo, sólo re-confirmar en el soak)

- **Consenso safety+liveness bajo pérdida de certs + equivocador:** DST 11/11.
- **Crash/kill/epoch-boundary restart + convergencia:** `chaos-test.sh` PASS=5/5
  local (baseline, SIGTERM+restart, SIGKILL+restart, reinicio en borde de época
  — todos convergen sin fork ni pérdida, verificado en esta entrega).
- **State sync desde cero, slashing, batch withholding, fuel-a-fee_limit,
  fail-loud de singletons de dinero:** verificados en vivo en incrementos previos
  (ver `CLAUDE.md`).

Lo que el soak multi-VPS agrega y NINGÚN test local puede: **semanas de tiempo de
reloj, latencia inter-región real, y operadores independientes** — exactamente lo
que este plan instrumenta.
