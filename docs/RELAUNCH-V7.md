# Relanzamiento v7 coordinado

Esta guía es el **runbook operativo** para pasar una red de la economía **v6** a la
**v7** (staking shares+índice, emisión por cuanto, split de fee **45% validadores
/ 45% quema / 10% admin**, bono de validador de **500 QCH**, métrica de
participación §21.2).

> **Lo más importante primero:** v7 NO es una actualización en caliente. Es un
> **hard fork con génesis NUEVO**. `economics_v7` (y `rounds_per_quanto`) se
> pliegan en el `chain_id`, así que una red v7 es una red **separada** de la v6 —
> una transacción firmada para v6 la rechaza v7 y viceversa (replay-safe). No hay
> migración automática de estado: **el ledger v6 se abandona** y v7 arranca desde
> un génesis que vos definís. Si querés que los saldos de los usuarios sobrevivan,
> hay que **snapshotearlos y encodearlos como asignaciones del génesis v7** (ver
> el Paso 2). Todo esto ya está verificado en vivo de punta a punta.

Como es un cambio de génesis que reinicia la red desde cero, **coordiná con todos
los validadores antes de empezar**: hay una ventana en que la red v6 se apaga y la
v7 todavía no arrancó.

---

## Qué cambia (y qué NO)

| | v6 (hoy) | v7 (después del relanzamiento) |
|---|---|---|
| `chain_id` | el actual | **distinto** (v7 se pliega) |
| Génesis / state root | el actual | **nuevo** (no migra) |
| Staking | delegar a un validador, comisión por-bloque | **pool global shares+índice**, sin elegir validador, rinde por el índice |
| Emisión | ninguna (solo redistribuye fee) | **emisión por cuanto** (APY objetivo) |
| Split de fee | 50% quema / 50% validadores | **45% validadores / 45% quema / 10% admin** |
| Ser validador | estar en el `validators` del génesis | bono de **500 QCH** (`v7-bond-register`) o sembrado como fundador en génesis |
| Un validador CAÍDO | seguía cobrando | **pierde fees** (participación §21.2), sin slashear |
| Wire / firma / consenso | — | **sin cambios** (v7 usa el mismo protocolo; solo cambian el génesis + las reglas económicas) |

La wallet detecta la red v7 sola (por `economics_v7` en `/status`) y muestra el
panel v7 (sin selector de validador, "Hacer staking" al pool global).

---

## Decisiones a tomar ANTES

1. **`rounds_per_quanto`** — la unidad de tiempo económico de v7 (cuántas rondas
   dura un cuanto: emisión, cierre de participación, reparto de fees). Default
   `172800` (~2 días a 1s/ronda). Se pliega en el `chain_id`, así que **TODOS los
   nodos deben usar el mismo valor**. Para un testnet chico conviene un valor
   chico (p.ej. `8`–`100`) para cruzar cuantos rápido.
2. **¿Se conservan los saldos v6?** — Sí (carry-over, Paso 2) o no (génesis
   limpio con las asignaciones que definas a mano). Los **fundadores** (el set
   `validators`) se siembran automáticamente con su bono de 500 QCH acuñado en
   el escrow — no hace falta asignarles nada aparte.
3. **El set de validadores fundadores** — quiénes arrancan en el comité (con su
   bono sembrado, Active desde el cuanto 0). Cualquiera que quiera sumarse
   después compra su bono de 500 QCH y hace `v7-bond-register`.

---

## Paso 0 — preparar los binarios

En cada máquina, dentro del repo, con la versión v7 (≥ 6.3.23):

```bash
git pull
docker build -t qchain:latest .    # o: cargo build --release --workspace
```

Confirmá que el binario es v7:

```bash
qchain-genesis-build --help | grep economics-v7   # debe existir el flag
```

---

## Paso 1 — cada validador genera su clave y su manifiesto

Igual que un despliegue normal (ver `DEPLOY.md`). Cada validador, en SU máquina:

```bash
qchain keygen --out keypair.json          # su clave privada — NUNCA la comparte
qchain bundle --keypair keypair.json      # su bundle público (pegalo en el manifiesto)
```

Y arma su manifiesto `mN.json` (sin ninguna clave privada):

```json
{ "pubkey_bundle": { ... salida de `qchain bundle` ... },
  "listen_addr": "IP_PUBLICA:9000",
  "rpc_addr":    "IP_PUBLICA:8080",
  "stake": 1000000,
  "name": "Nombre del validador" }
```

Todos los manifiestos se juntan en un directorio (`./m/`) en la máquina del
coordinador.

---

## Paso 2 (opcional) — conservar los saldos v6 (carry-over)

Si querés que los holders mantengan su QCH en v7, **congelá la red v6 primero**
(dejá de mandar transacciones / bajá el faucet) para que el estado sea estable, y
snapshoteá los saldos de las wallets de usuario a un archivo de asignaciones del
génesis v7:

```bash
# 1) mirá el punto exacto que vas a congelar (ronda + root + nº de cuentas)
deploy/v6-snapshot-to-v7-genesis.sh --rpc http://127.0.0.1:8080 --meta

# 2) generá las asignaciones v7 desde el estado v6
deploy/v6-snapshot-to-v7-genesis.sh --rpc http://127.0.0.1:8080 --out v7-genesis.json
```

Esto escribe `v7-genesis.json` con **solo las wallets de usuario** (owned por el
System Program, saldo > 0), ordenadas por dirección — determinista. Los singletons
de programa v6 (pool de staking, params, fee-state, registro…) se **descartan a
propósito**: v7 siembra los suyos (§15).

> **Determinismo:** como todos los nodos v6 convergen al mismo estado, el snapshot
> de cualquier nodo en la MISMA ronda da el mismo archivo. Congelá la red y que
> TODOS los coordinadores usen la misma ronda, o el `chain_id` v7 diferirá.

Si NO querés carry-over, armá un `v7-genesis.json` a mano con las asignaciones que
quieras (o `[]` para un génesis sin asignaciones — los fundadores igual reciben su
bono).

---

## Paso 3 — el coordinador arma el génesis v7

```bash
qchain-genesis-build \
  --manifests-dir ./m \
  --genesis v7-genesis.json \
  --out-dir ./out \
  --economics-v7 \
  --rounds-per-quanto <N> \
  --round-interval-ms 1000
```

La herramienta escribe un `nodeN.json` por validador **e imprime el `chain_id`**:

```
chain_id: fba40ca485ae798c216c0b761a9c56afbd218eb25d90faabbe7866b7b644d3f1
economics: v7 ENABLED (rounds_per_quanto=8) — a hard-forked network, distinct from any v6 chain.
EVERY validator of this network must build from the same manifests + genesis + flags and see this SAME chain_id, or the network will fork.
```

**Anotá ese `chain_id`.** Es la identidad de la red v7. Todos los que armen el
génesis (o lo verifiquen) tienen que ver EXACTAMENTE el mismo valor — si dos
coordinadores ven `chain_id` distinto, construyeron redes distintas que
**forkearían**. (Causas típicas de diferencia: manifiestos distintos, `genesis`
distinto, o un `rounds_per_quanto` distinto.)

---

## Paso 4 — arrancar la red v7 (coordinado)

Cada validador, en SU máquina, con SU `nodeN.json` + `keypair.json` + un
**`data_dir` VACÍO** (v7 es un génesis nuevo — NO reutilizar el `data/` de v6):

```bash
# IMPORTANTE: mover/borrar el data_dir viejo de v6 primero
mv data data-v6-backup      # o borralo si ya respaldaste

qchain-node --config nodeN.json
```

Con systemd (producción):

```bash
# copiar nodeN.json -> /opt/qchain/config.json, keypair.json -> /opt/qchain/keypair.json
sudo rm -rf /opt/qchain/data           # génesis nuevo
sudo systemctl restart qchain-validator
```

El nodo loguea `economics: v7 ENABLED … rounds_per_quanto=N` al arrancar.

---

## Paso 5 — verificar (checklist post-arranque)

En cada nodo:

```bash
# 1) el chain_id coincide con el que imprimió genesis-build
curl -s http://127.0.0.1:8080/chain_id

# 2) v7 está activo y las rondas avanzan
curl -s http://127.0.0.1:8080/status | grep -o '"economics_v7":[a-z]*'
#    (repetí y confirmá que next_round sube)

# 3) los fundadores están sembrados Active y elegibles desde el cuanto 0
qchain v7-validators --rpc http://127.0.0.1:8080
#    -> state=Active activation_q=0 eligible=true participation=10000bps

# 4) (si hubo carry-over) un saldo conocido está presente
curl -s http://127.0.0.1:8080/account/<direccion>

# 5) el reparto de fees paga a los fundadores por igual (tras algo de tráfico)
#    -> los balances de los validadores crecen idénticos; los roots de /root
#       coinciden entre todos los nodos (sin fork)
```

**Verificado en vivo (n=4, este relanzamiento):** con los 4 fundadores arriba el
reparto 1/N pagó a los 4 exactamente igual y los 4 roots fueron idénticos; al
matar uno, tras la ventana de lag su `participation_bps → 0` y `eligible → false`,
su balance quedó congelado mientras los otros siguieron cobrando 1/3, con los 3
roots supervivientes idénticos (sin fork). El carry-over conservó los saldos v6
byte-idénticos en el génesis v7, con un `chain_id` distinto del v6.

---

## Seguridad y rollback

- **La red v6 queda intacta** hasta que la apagues. Si algo sale mal en el Paso 4,
  podés volver a arrancar los nodos v6 con su `data-v6-backup` — la v6 no se tocó
  (su `chain_id` no cambia; v7 es una red aparte).
- **No mezclar binarios/flags:** todos los nodos de la red v7 corren la misma
  versión y el mismo `rounds_per_quanto`. Un mismatch forkea.
- **El bono de los fundadores** se acuña en el escrow en génesis (invariante §13:
  escrow == Σ bonos). Un fundador que quiera salir usa `v7-begin-exit` y recupera
  los 500 con `v7-withdraw-bond` tras la ventana de unbonding.

---

## Referencia rápida de comandos v7 (post-relanzamiento)

```bash
qchain v7-validators        --rpc <url>                                   # ver el registro v7
qchain v7-bond-register     --rpc <url> --keypair k.json --moniker <n> --p2p-address <ip:puerto>
qchain v7-begin-exit        --rpc <url> --keypair k.json
qchain v7-withdraw-bond     --rpc <url> --keypair k.json
```

Staking de usuario: desde la **wallet web** (detecta v7 y muestra el panel del pool
global) o firmando `StakingV7Instruction` (ver `qchain-wasm`).
