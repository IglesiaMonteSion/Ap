# Desplegar un testnet público real

Esta guía cubre cómo pasar de "corre en mi máquina" a un testnet real con
validadores en máquinas distintas (idealmente regiones distintas), más un
faucet y una página de estado básica para que gente externa lo pruebe.

**Antes de empezar, léase esto:** esto sigue siendo un testnet, no una red
con valor económico real. No hay auditoría externa todavía (ver
`ARCHITECTURE.md`/`CLAUDE.md`). No pongas nada de valor real detrás de
esto, y dejalo claro a cualquiera que invites a participar.

## Checklist rápido multi-región (una vez que haya VPS reales)

Para cada validador, en su propia región:

1. VPS Debian/Ubuntu fresca → `sudo ./deploy/provision-validator.sh qchain:latest`
2. Ese participante corre `qchain keygen`/`qchain bundle` **en su propia
   máquina** (nunca comparte `keypair.json`) → manda el bundle al coordinador
3. Coordinador junta todos los bundles → `qchain-genesis-build` → un
   `nodeN.json` por validador, sin haber visto ninguna clave privada
4. Cada participante recibe *solo* su propio `nodeN.json` → lo renombra
   `config.json`, lo pone en `/opt/qchain` junto a su `keypair.json`
5. `sudo systemctl enable --now qchain-validator` en cada máquina
6. Confirmar convergencia: `qchain balance`/`qchain registry` contra el
   puerto RPC de *varias* regiones debe dar el mismo resultado

El resto de este documento cubre cada paso en detalle, más el faucet y
la página de estado.

## Qué hay en este repo para esto

- `Dockerfile` — imagen única con los cuatro binarios: `qchain-node`
  (validador), `qchain-genesis-build` (herramienta de coordinación),
  `qchain` (wallet CLI), `qchain-faucet`.
- `deploy/compose/` — smoke test local de la imagen con Docker Compose (3
  validadores + faucet en un solo host, IPs estáticas). **No es la
  topología real multi-región** — sirve para probar que la imagen
  funciona antes de gastar en servidores reales.
- `deploy/provision-validator.sh` — deja una VPS Debian/Ubuntu fresca
  lista para correr un validador real: instala Docker si falta, abre los
  puertos de `listen_addr`/`rpc_addr` en `ufw` (si está disponible),
  activa NTP, e instala el servicio `systemd` de abajo. Pensado para
  correrse una vez por máquina, en cualquier región — no asume nada del
  resto de la red.
- `deploy/systemd/qchain-validator.service` y
  `deploy/systemd/qchain-faucet.service` — unidades `systemd` reales
  (`Restart=on-failure`) para que el validador/faucet sobrevivan un
  crash o un reinicio de la máquina sin intervención manual, en vez de
  depender de `docker run -d` corriendo a mano en una sesión de shell.
- Página de estado en `GET /` de cualquier validador (ver más abajo).

## Paso 0 — smoke test local (recomendado antes de gastar en servidores)

```
cargo build --release --workspace
cd deploy/compose
./setup-local-demo.sh
docker compose up --build
```

Esto genera 3 validadores + un wallet de faucet, arma la config
compartida, y levanta todo en un solo host vía Docker (red bridge propia
con IPs fijas, ya que las direcciones de peer tienen que ser IP:puerto
literal, no nombres DNS de Docker). Confirma que la imagen compila y que
los tres nodos convergen antes de tocar infraestructura real.

## Paso 1 — cada validador genera su propia clave (nunca la comparte)

Cada participante, en su propia máquina:

```
docker run --rm -v $PWD:/out <imagen> qchain keygen --out /out/keypair.json
docker run --rm -v $PWD:/out <imagen> qchain bundle --keypair /out/keypair.json
```

El segundo comando imprime el "bundle" público (JSON) — **esto es lo
único que se comparte con el coordinador**. `keypair.json` nunca sale de
la máquina del validador.

Cada participante arma su propio manifest (sin clave privada):

```json
{
  "pubkey_bundle": { ...el JSON que imprimió "qchain bundle"... },
  "listen_addr": "203.0.113.10:9000",
  "rpc_addr": "0.0.0.0:8080",
  "stake": 1000000
}
```

`listen_addr` tiene que ser la IP pública real de esa máquina (o la IP que
sus pares puedan marcar) — es la dirección que el resto de la red usa
para conectarse a este validador, no un nombre de host.

## Paso 2 — el coordinador arma la configuración compartida

El coordinador junta un manifest por validador en un directorio y corre:

```
qchain-genesis-build \
  --manifests-dir ./manifests \
  --genesis ./genesis.json \
  --out-dir ./configs \
  --round-interval-ms 1000
```

`genesis.json` es opcional — una lista `[{ "address": "...", "balance": N }]`
para precargar, por ejemplo, el wallet del faucet. `round_interval_ms`
más alto que el default (500ms) deja margen real de latencia entre
regiones — 1000ms es un punto de partida razonable, ajustable.

Esto imprime qué `nodeN.json` corresponde a qué validador (por dirección),
y el coordinador le manda a cada participante *solo* su propio
`nodeN.json` — nunca ve ni necesita ninguna clave privada.

## Paso 3 — cada validador corre su nodo

Cada participante coloca su `nodeN.json` (renombrado `config.json`) junto
a su propio `keypair.json`, en un directorio con un subdirectorio `data/`
vacío para persistencia real en disco, y corre:

```
docker run -d --name qchain-validator \
  --network host \
  -v $PWD:/qchain -w /qchain \
  <imagen> qchain-node --config config.json
```

`--network host` es lo más simple para un VPS real: el nodo se bindea
directo a la IP pública de la máquina, la misma que ya declaró en su
manifest — sin mapeo de puertos ni NAT de por medio. Abrir los puertos
`listen_addr` y `rpc_addr` en el firewall de esa máquina (típicamente
9000 y 8080).

### Alternativa recomendada para producción real: `systemd`

`docker run -d` funciona, pero no sobrevive un reinicio de la máquina ni
se reinicia solo si el proceso muere - hay que reingresar a mano. Para
un validador real, sobre todo en una región distinta a la que estás
mirando en el momento, usar en cambio:

```
sudo ./deploy/provision-validator.sh qchain:latest   # una vez, en la VPS nueva
# copiar config.json + keypair.json a /opt/qchain en esa VPS
sudo systemctl enable --now qchain-validator
journalctl -u qchain-validator -f                    # confirmar que arrancó bien
```

`provision-validator.sh` instala Docker si falta, abre `listen_addr`/
`rpc_addr` en `ufw` (si está disponible - si el proveedor usa un
security group en su lugar, configurarlo ahí en cambio), activa NTP
(los timestamps de log de validadores en regiones distintas solo se
pueden correlacionar si los relojes están sincronizados), e instala
`deploy/systemd/qchain-validator.service` (`Restart=on-failure`, arranca
solo en el boot de la máquina). El mismo patrón aplica al faucet vía
`deploy/systemd/qchain-faucet.service`.

## Faucet

Quien vaya a operar el faucet corre, en cualquier máquina con acceso al
RPC de al menos un validador:

```
docker run -d --name qchain-faucet \
  -v $PWD:/qchain -w /qchain -p 9090:9090 \
  <imagen> qchain-faucet \
    --rpc http://<ip-de-un-validador>:8080 \
    --keypair /qchain/faucet-keypair.json \
    --listen 0.0.0.0:9090 \
    --amount 10000000 \
    --cooldown-secs 60
```

El wallet del faucet necesita balance real — se lo asigna vía el
`genesis.json` del paso 2. Uso:

```
curl -X POST http://<faucet>:9090/faucet \
  -H 'content-type: application/json' \
  -d '{"address":"<tu dirección>"}'
```

El monto es fijo por el operador (`--amount`), nunca lo pide quien
llama — así nadie puede vaciar el faucet en un solo pedido. Rate-limit
por dirección vía `--cooldown-secs` (en memoria, no persiste un
reinicio del faucet — aceptable para un testnet).

## Página de estado (Qscan)

Visitar `http://<ip-de-un-validador>:8080/` en un navegador muestra el
estado de ese nodo (ronda actual, certificados, raíz de estado), una
lista real de las transferencias más recientes que *ese* validador
ejecutó (con detalle completo — balances antes/después, pruebas Merkle
— al hacer clic en una fila), y permite buscar el balance de una
dirección. Los mismos datos están disponibles como JSON real vía RPC:

```
GET /transfers?limit=20&offset=0   # lista, más reciente primero
GET /transfers/<hash-hex>          # detalle completo de una transferencia
```

**Sigue sin ser un explorador de red completo** — cada validador solo
conoce las transferencias que *él mismo* ejecutó (no hay un indexador
centralizado agregando los datos de todos los nodos), el log es un
`Vec` en memoria sin persistencia ni límite (mismo `TransferReceipt`
que ya usaba `/stark_proof`, no una tabla nueva), y solo cubre
transacciones `Transfer` de una sola instrucción (staking/gobernanza no
generan un recibo). Para eso — o para consultar contra un nodo
específico por CLI — usar `qchain-cli`.

## Seguridad real, no cosmética

- El RPC (`/tx`, `/account/:addr`, etc.) no tiene autenticación —
  cualquiera que lo alcance puede enviar transacciones (pagan su propio
  fee) y leer balances. Aceptable para un testnet público; no exponer así
  si alguna vez hay valor real detrás.
- El transporte P2P (`qchain-network`) abre una conexión TCP nueva por
  mensaje — una simplificación de fase 1 documentada (ver
  `ARCHITECTURE.md`); bajo tráfico de ataque real esto puede agotar file
  descriptors (ver el hallazgo real documentado en
  `project-lessons-learned`). No es una preocupación nueva de este
  despliegue, pero un testnet *público* es la primera vez que tráfico
  hostil real es plausible, no solo hipotético.
- El faucet es un wallet caliente con clave privada en el disco de quien
  lo opera — tratalo como cualquier hot wallet, no como un archivo
  cualquiera.
