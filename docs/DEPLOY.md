# Desplegar un testnet público real

Esta guía cubre cómo pasar de "corre en mi máquina" a un testnet real con
validadores en máquinas distintas (idealmente regiones distintas), más un
faucet y una página de estado básica para que gente externa lo pruebe.

**Antes de empezar, léase esto:** esto sigue siendo un testnet, no una red
con valor económico real. No hay auditoría externa todavía (ver
`ARCHITECTURE.md`/`CLAUDE.md`). No pongas nada de valor real detrás de
esto, y dejalo claro a cualquiera que invites a participar.

## El camino fácil: `deploy/install-node.sh`

Si no tenés experiencia técnica (o simplemente querés algo rápido), no
hace falta seguir el checklist manual de abajo. Necesitás tres cosas: una
VPS Debian/Ubuntu fresca, este repositorio en la máquina, y correr un
comando. Desde cero:

```
# 1. traé el repo a la máquina (o subilo por SFTP si es privado)
git clone <url-del-repo> qchain && cd qchain
# 2. corré el instalador
sudo ./deploy/install-node.sh
```

El script pregunta una sola cosa — si querés **crear tu propia red de
prueba** (un solo nodo, vos sos el único validador, con una wallet de
prueba ya cargada de fondos para probar transferencias al toque) o
**unirte a una red que ya existe** (te va a pedir tu bundle público para
mandárselo a quien coordina esa red, y esperar el `config.json` que te
devuelvan) — y hace todo lo demás solo: instala Docker si falta (y
verifica que su servicio esté corriendo), genera tu clave, arma la
configuración (validando que el `config.json` resultante sea JSON
correcto antes de seguir), abre los puertos, restringe los permisos de
tu clave privada (`chmod 600`), e instala el nodo como servicio
(`systemctl`, se reinicia solo si se cae, y el script confirma que quedó
activo). Al final te imprime la URL de la página de estado, cómo ver los
logs, y un recordatorio de que el RPC no tiene autenticación.

**No hace falta conseguir la imagen Docker por tu cuenta.** Como todavía
no hay un registro público publicado, el instalador **construye la imagen
desde el código de este mismo repo** la primera vez (un `docker build`
automático — tarda varios minutos y baja las dependencias de compilación,
después queda cacheado). Solo necesitás Docker con acceso a internet, que
el propio script instala si falta. Si en el futuro publicás la imagen en
un registro, `--image <registro/qchain:tag>` la baja en vez de compilar; y
`--no-build` desactiva la compilación (solo intenta `docker pull` o cargar
un `qchain-image.tar` que dejes junto al repo). En todos los casos el
script verifica que la imagen realmente tenga los binarios de qchain antes
de avanzar.

Al final, si elegís instalar la **wallet web**, también te ofrece exponerla
por **HTTPS con un túnel de Cloudflare** (sin abrir puertos en el firewall de
la nube) — así un nodo público completo (validador + wallet + HTTPS) queda en
**un solo comando**. Un nodo público en solitario, de punta a punta, sin
interacción (`--con-tunel` implica la wallet, y `--yes` le genera una
contraseña fuerte y te la muestra):

```
sudo ./deploy/install-node.sh --modo solo --nombre "Mi validador" \
    --con-tunel --yes
```

O de forma interactiva (te pregunta la contraseña de la wallet y si querés el
túnel): `sudo ./deploy/install-node.sh --modo solo`.

Es seguro volver a correrlo: si ya generó tu clave o tu `config.json`,
nunca los pisa (ni siquiera si un paso anterior falló a mitad de camino)
— solo te pregunta si querés reinstalar el servicio. Para bajar el nodo
sin perder nada: `sudo ./deploy/install-node.sh --uninstall`.

También se puede correr sin preguntas, para instalación automatizada:

```
sudo ./deploy/install-node.sh --modo solo --yes
sudo ./deploy/install-node.sh --modo unirse --config /ruta/a/config.json --yes
```

Ver todas las opciones (puertos custom, imagen custom, carpeta de
instalación custom) con `sudo ./deploy/install-node.sh --help`.

## Red de 2 validadores (principal + secundario) en un paso: `deploy/setup-2validators.sh`

Para armar una red NUEVA de dos VPS sin hacer el ida y vuelta de bundles/configs
a mano, hay un solo script que corre en la **VPS principal** (la que lleva la
mayoría del stake, así puede avanzar sola si la secundaria se cae):

```
# 1) En la VPS SECUNDARIA (Oracle): sacá su bundle (un comando)
sudo docker run --rm -v /opt/qchain:/qchain -w /qchain qchain:latest \
    qchain bundle --keypair keypair.json > bundle-secundario.json
#    → copiá el contenido a la VPS principal (scp, o pegalo en un archivo)

# 2) En la VPS PRINCIPAL (nueva), dentro del repo:
sudo ./deploy/setup-2validators.sh \
    --ip-principal  <IP_PUBLICA_DE_ESTA_VPS> \
    --ip-secundario <IP_PUBLICA_DE_LA_ORACLE> \
    --bundle-secundario bundle-secundario.json
#    → instala el principal (Docker + imagen + firewall + systemd) y te imprime
#      UN comando listo para pegar en la secundaria.

# 3) En la SECUNDARIA: pegá el comando que imprimió el paso 2 (escribe su config,
#    borra el estado viejo y la reinicia en la red nueva).

# 4) Abrí el puerto P2P (9000 por defecto) en el FIREWALL DE LA NUBE de AMBAS
#    VPS (Security List / NSG en Oracle Cloud, grupo de seguridad en la otra).
```

Reparto de stake por defecto: principal 3.000.000 / secundario 1.000.000 (75/25 →
el principal tiene >2/3 y avanza solo si la secundaria se cae). Cambialo con
`--stake-principal`/`--stake-secundario`. **Aclaración honesta:** con >2/3 en un
solo nodo ganás redundancia, no tolerancia bizantina — para tolerar la caída de
cualquiera de las dos sin depender de cuál, el salto real es a 4 validadores con
stake parejo. `--dry-run` genera los configs sin instalar nada; `--help` lista
todas las opciones.

El resto de esta guía documenta el camino manual, paso a paso, para
quien quiera más control (multi-validador coordinado, ajustar
`round_interval_ms`, etc.) o entender qué hace el instalador por dentro.

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
solo en el boot de la máquina). El script en sí solo cubre el validador
— si el faucet va a correr en la misma VPS (el caso más común), la
unidad `deploy/systemd/qchain-faucet.service` usa el mismo patrón
(`--network host`, `Restart=on-failure`), pero hay que instalarla y
abrir su puerto a mano, ver más abajo.

### Recuperar un validador muy atrasado (state-sync)

Un validador que estuvo caído mucho tiempo (más de ~1.024 rondas, la
ventana de retención del DAG) no puede reincorporarse pidiendo
certificados uno por uno: sus pares ya podaron esa historia vieja. La
recuperación es state-sync, igual que en Cosmos: se borra el estado local
y se arranca de nuevo apuntando a pares sanos, que sirven un snapshot
verificado del estado de cuentas.

En el `config.json` del validador a recuperar, agregar los RPC de dos o
tres pares sanos:

```
"state_sync_peers": [
  "http://<ip-par-1>:8080",
  "http://<ip-par-2>:8080",
  "http://<ip-par-3>:8080"
]
```

Luego, en la VPS de ese validador:

```
sudo systemctl stop qchain-validator
sudo rm -rf /opt/qchain/data        # borrar SOLO el estado local, nunca keypair.json
sudo systemctl start qchain-validator
journalctl -u qchain-validator -f   # buscar "state-synced N accounts at round R"
```

El nodo descarga el snapshot, **reconstruye el árbol de Merkle y exige
que la raíz coincida** con la reclamada (rechaza un snapshot manipulado),
y si dos pares reportan raíces distintas para la misma ronda, aborta en
vez de sincronizar desde una vista bifurcada. Para una verificación aún
más fuerte, un operador puede fijar un ancla obtenida por fuera:
`"state_sync_trusted_root": "<hex>", "state_sync_trusted_round": <n>` —
solo acepta el snapshot si coincide exacto. Sin `state_sync_peers` el
arranque es el de siempre (un nodo con `data_dir` existente resume normal;
uno fresco siembra génesis y arranca desde la ronda 0).

## Actualizar un nodo (versiones y avisos de actualización)

Cada nodo corre una **versión** (`MAJOR.MINOR.PATCH`, arranca en `1.0.0`,
tomada del `Cargo.toml` del workspace). La versión se puede consultar en
`GET /version` y aparece en `GET /status` y en la página de estado.

**Aviso automático de actualización, sin servidor central:** cada validador
anuncia su versión a sus pares cada 30s. Si un validador escucha a otro
validador (real, del conjunto) corriendo una versión **más nueva**, levanta
la bandera `update_available` — visible en `/version`, `/status`, la página
de estado (banner ⬆️) y un `WARN` en los logs. Así, a medida que algunos
validadores actualizan, los que quedan viejos se enteran solos de que hay
una versión nueva. Es solo un aviso (nunca afecta el consenso ni actúa
automáticamente) y solo lo levanta un par que de verdad está en el conjunto
de validadores.

**Para actualizar un nodo** (desde el repo, en la VPS del nodo):

```
git pull                        # traé el código nuevo
sudo ./deploy/update-node.sh    # reconstruye la imagen y reinicia el nodo
```

`update-node.sh` muestra la versión actual vs. la del repo, reconstruye
`qchain:latest` desde el código, y reinicia el servicio systemd. **Tu clave,
`config.json` y `data/` no se tocan** — el nodo resume su estado exacto desde
`data_dir` (balances, nonces, DAG, todo). Es seguro correrlo aunque no haya
cambios. Para cortar una versión nueva (cuando hagas mejoras): subí `version`
en el `Cargo.toml` raíz, actualizá `version.json`, commiteá, y cada operador
corre `update-node.sh`.

**Actualización rápida de solo la wallet** (cambios de interfaz — lo más
frecuente): `sudo ./deploy/update-wallet.sh` reconstruye la imagen (rápido
con la cache) y reinicia **solo** `qchain-wallet`, sin reiniciar el
validador. Usá `update-node.sh` cuando cambie el nodo/consenso.

**Cómo elegir el número de versión:**
- **Cambio chico** (fix puntual, ajuste de UI, tooling, mejora menor): subí el
  último dígito. Ej: `1.9.0 → 1.9.1 → 1.9.2`.
- **Cambio grande** (fase nueva, feature mayor, cambio de protocolo/consenso o
  criptografía, algo que rompe compatibilidad): subí la versión mayor. Ej:
  `1.9 → 2.0`.
- Regla de dedo: si toca el formato de wire, el consenso o la cripto → grande;
  si es aditivo/correctivo y un nodo viejo sigue conviviendo → chico.

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

Para correrlo como servicio real (`Restart=on-failure`) en la misma VPS
que un validador, copiar `faucet-keypair.json` a `/opt/qchain-faucet/`,
instalar la unidad, y abrir su puerto (`provision-validator.sh` no lo
hace por vos, ya que no siempre corre en el mismo host que el validador):

```
sudo cp deploy/systemd/qchain-faucet.service /etc/systemd/system/
sudo ufw allow 9090/tcp comment 'qchain faucet'   # si usás ufw
sudo systemctl daemon-reload
sudo systemctl enable --now qchain-faucet
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

## Wallet web (`qchain-wallet`) — crear wallets y transferir desde el navegador

Una interfaz simple (botones, no CLI) para que una persona común pueda
crear wallets, ver balances en QCH y enviar transferencias. Reusa el
*mismo* código de firma post-cuántica que el nodo (`qchain-crypto` /
`qchain-core`), así que las transacciones que firma son byte-compatibles
— el navegador es solo la UI.

### Dos wallets, dos puertas

El servidor sirve **dos** wallets en el mismo puerto:

| Ruta | Tipo | Contraseña | Dónde vive la clave |
|---|---|---|---|
| `/` (y `/wasm`) | **No-custodial** (por defecto) | **No pide** | En tu navegador (cifrada con tu contraseña vía WebCrypto) |
| `/custodial` | Custodial (legado) | **Sí, obligatoria si se expone** | En el servidor |

La puerta principal `/` es la **no-custodial**: un desconocido que abre la
wallet desde cualquier navegador **no ve login** — la clave se genera y se
cifra en su propio navegador, el servidor nunca la ve. La custodial (claves
en el servidor) quedó en `/custodial` y sigue exigiendo contraseña, porque
quien la alcance podría gastar esas claves.

**La no-custodial (`/`) necesita HTTPS** (o localhost): los navegadores solo
habilitan WebCrypto en un contexto seguro. Sobre `http://` plano muestra un
aviso y no funciona. Ver **"HTTPS sin comprar dominio"** más abajo.

### El camino fácil: `deploy/install-wallet.sh`

Un solo comando deja la wallet web funcionando, protegida con contraseña,
abierta al navegador y arrancando sola si la máquina se reinicia:

```
sudo ./deploy/install-wallet.sh
```

Te pregunta la contraseña (o te genera una fuerte y te la muestra), abre
el puerto en el firewall del sistema, y la instala como servicio systemd
(`qchain-wallet`). Al terminar te da la URL (`http://<tu-ip>:8090/`) y
cómo entrar (usuario: cualquiera; contraseña: la que definiste). Si
instalaste el nodo en modo "solo", la wallet de prueba con fondos aparece
automáticamente en el navegador como **"banco"**, lista para repartir
monedas de prueba a las wallets que crees.

`install-node.sh` también te *ofrece* instalarla al final. Cambiar la
contraseña después: `sudo ./deploy/install-wallet.sh --password 'nueva' --yes`.
Bajarla sin perder wallets: `sudo ./deploy/install-wallet.sh --uninstall`.

**Recordá el firewall de la nube:** el instalador abre el puerto en el
sistema, pero si tu proveedor tiene un firewall aparte (Security List de
Oracle Cloud, Security Group de AWS), tenés que abrir el `8090/TCP` ahí
también desde su consola web.

### HTTPS sin comprar dominio: `deploy/install-https.sh`

Para que la wallet no-custodial (`/`) funcione desde internet hace falta
HTTPS. Un solo comando lo resuelve **sin comprar dominio**:

```
sudo ./deploy/install-https.sh
```

Detecta tu IP pública, arma un dominio gratis con **sslip.io**
(`129-80-59-17.sslip.io` → tu IP, sin configurar nada), instala **Caddy**
como proxy y saca un certificado real de **Let's Encrypt** automáticamente.
Al terminar entrás por `https://129-80-59-17.sslip.io/` — sin contraseña,
con la clave cifrada en tu navegador.

Si **sí** tenés dominio propio, apuntá su registro A a tu IP y corré
`sudo ./deploy/install-https.sh --dominio wallet.tudominio.com`.

**Falta un paso en la consola de la nube:** Let's Encrypt valida por el
puerto **80** y el navegador entra por el **443**. Abrí ambos (TCP) en la
Security List / firewall de tu proveedor (en Oracle: Networking → VCN →
Security Lists → Ingress Rules). Sin eso el certificado no se emite.

### HTTPS sin abrir puertos: `deploy/install-tunnel.sh` (túnel de Cloudflare)

Si el firewall de la nube es un problema (Oracle Cloud, típicamente) y no
podés/querés abrir 80/443, un túnel de Cloudflare te da HTTPS **sin abrir
ningún puerto de entrada**: hace una conexión *saliente* desde tu VPS a
Cloudflare, y Cloudflare te da una URL pública HTTPS que reenvía por esa
conexión hasta tu wallet local.

```
sudo ./deploy/install-tunnel.sh
```

Instala `cloudflared` (binario oficial, detecta amd64/arm64 — Oracle free
tier suele ser ARM), lo deja como servicio systemd, y te imprime la URL
(`https://algo.trycloudflare.com/`). Ver la URL después:
`sudo ./deploy/install-tunnel.sh --url`. Quitarlo:
`sudo ./deploy/install-tunnel.sh --uninstall`.

**Límite:** es un "quick tunnel" gratis y sin cuenta — la URL **cambia**
cada vez que el túnel reinicia (reboot/crash). Para una URL **fija** hace
falta una cuenta gratis de Cloudflare + un dominio propio (túnel con
nombre): se crea con `cloudflared tunnel login`, `cloudflared tunnel create
qchain`, y una regla DNS al hostname que elijas — Cloudflare documenta el
flujo. El quick tunnel alcanza para probar/usar la wallet desde el celular.

### A mano (si preferís no usar el instalador)

**Local (lo más seguro), por túnel SSH desde tu equipo:**

```
# en la VPS del nodo (escucha solo en localhost, sin contraseña):
docker run --rm --network host -v /opt/qchain/wallets:/wallets \
  qchain:latest qchain-wallet --rpc http://127.0.0.1:8080 --wallets-dir /wallets

# en tu equipo, abrí un túnel y entrá a http://127.0.0.1:8090
ssh -L 8090:127.0.0.1:8090 usuario@<ip-de-la-vps>
```

**Expuesta a internet (requiere contraseña, sin excepción):** el wallet
guarda **claves privadas** — quien alcance el puerto puede gastar las
wallets. Por eso, si la exponés (`--bind 0.0.0.0`), el binario **se niega
a arrancar sin una contraseña**. Pasala por variable de entorno para que
no quede en el historial de comandos:

```
docker run --rm --network host -v /opt/qchain/wallets:/wallets \
  -e QCHAIN_WALLET_PASSWORD='una-clave-fuerte' \
  qchain:latest qchain-wallet --rpc http://127.0.0.1:8080 \
  --wallets-dir /wallets --bind 0.0.0.0 --port 8090
```

Después abrí el puerto 8090 en el firewall (los dos niveles en Oracle
Cloud):

```
# nivel SO:
sudo iptables -I INPUT 1 -p tcp --dport 8090 -j ACCEPT
# nivel nube: agregar una Ingress Rule para el puerto 8090/TCP en la
#             Security List de la subred (consola de OCI)
```

El navegador va a pedir usuario/contraseña (el usuario es cualquiera, la
contraseña es la que pusiste). Queda accesible en `http://<ip>:8090`.

**Límite honesto:** sobre HTTP plano la contraseña viaja solo en base64
(HTTP Basic), no cifrada — para uso con valor real poné un proxy con
HTTPS/TLS adelante. Para un testnet sin valor real, la contraseña + el
firewall alcanzan.

## Seguridad real, no cosmética

- El RPC (`/tx`, `/account/:addr`, etc.) no tiene autenticación —
  cualquiera que lo alcance puede enviar transacciones (pagan su propio
  fee) y leer balances. Aceptable para un testnet público; no exponer así
  si alguna vez hay valor real detrás.
- El transporte P2P (`qchain-network`) ya no abre una conexión TCP nueva
  por mensaje — cierra una conexión persistente por peer (ver
  `ARCHITECTURE.md` §1), lo cual además cierra en la práctica el riesgo
  de agotamiento de file descriptors bajo tráfico real que la versión
  anterior tenía documentado.
- El faucet es un wallet caliente con clave privada en el disco de quien
  lo opera — tratalo como cualquier hot wallet, no como un archivo
  cualquiera.
