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

> **¿URL fija con tu dominio?** El quick-tunnel da una URL random que cambia al
> reiniciar. Para una URL **fija** con tu dominio (ej. `wallet.qchain.com`) —
> prerequisito del puente wallet-connect — seguí [`DOMAIN-SETUP.md`](DOMAIN-SETUP.md):
> `sudo ./deploy/install-tunnel.sh --hostname wallet.qchain.com`.

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

### Sumar un nodo SECUNDARIO a una red que ya existe (en un comando)

En la VPS nueva, traé el repo y corré:

```
sudo ./deploy/install-node.sh --modo unirse \
     --red-config config-de-la-red.json \
     --sync-peer http://<ip-de-un-nodo-vivo>:8080
```

- `--red-config` es el `config.json` **público** que te pasa **cualquier** nodo
  que ya esté corriendo (tiene `validators`+`genesis`, **no** tiene ninguna clave
  privada). El instalador lo adapta solo: le pone **tu** clave, **tus** puertos y
  el `state_sync_peers`, dejando `validators`/`genesis`/rotación **igual** (eso es
  la identidad de la red, el `chain_id`). No hace falta que nadie te devuelva un
  config a medida ni compartir ninguna clave privada.
- `--sync-peer` es el RPC de un nodo vivo desde el que ponerse al día (state-sync).

Tu nodo arranca, **se sincroniza solo** y ya es parte de la red (sigue la cadena y
sirve RPC). Qué pasa después depende de la red:

- **Si la red tiene rotación dinámica ON** (`validator_rotation: true`): el
  instalador te imprime los **dos comandos exactos** para volverte VALIDADOR en
  caliente — bloquear tu self-stake (`stake-delegate` a tu propia dirección,
  ≥ 10.000.000 unidades = 0,01 QCH) y `register-validator` con tu IP pública. En el
  próximo borde de época entrás al comité **sin que ningún otro nodo reinicie**.
- **Si la red tiene rotación OFF** (el default): tu nodo corre como **seguidor**
  (sincroniza, sirve RPC/balances, no propone) — útil como réplica de lectura.
  Para que sea validador con rotación off, el operador debe incluir tu bundle en
  el génesis y hacer un redeploy coordinado (ver la sección de rotación más abajo).

## Endurecimiento / hardening (aislamiento de servicios y RPC privado)

> **Antes de ir a VALOR REAL**, seguí la checklist operativa completa en
> [`PRE-LAUNCH.md`](PRE-LAUNCH.md): auditoría automática (`deploy/prelaunch-check.sh`),
> RPC privado, bajar el dashboard, clave de tesorería en frío, endurecer SSH
> (`deploy/harden-ssh.sh`), backups+monitoreo, y auth/cifrado P2P al sumar nodos.

El instalador aplica varias defensas por defecto — no hay que configurar nada,
pero conviene entender el modelo para no aflojarlo por accidente.

**Almacenamiento ATÓMICO (motor `redb`, el default de mainnet).** El estado de
la cadena se guarda con **redb** (ACID, pure-Rust). Cada ronda comprometida se
persiste en **UNA sola transacción atómica y fsync-durable** que incluye TODO
junto: los saldos y nonces del pagador y el receptor, los fees/quema/pools, el
staking y la tesorería, los parámetros económicos, y el **checkpoint de la ronda
ejecutada** (la raíz Merkle se deriva del estado, así que es siempre consistente
por construcción). Es **todo o nada**: un corte de energía ve la ronda entera o
ninguna parte — el estado y la ronda **nunca** pueden quedar desfasados (medio
estado guardado). Si una escritura o el flush fallan, **el nodo se DETIENE**
(halt), nunca continúa con una advertencia sobre estado a medio escribir; systemd
lo reinicia y retoma desde la última ronda commiteada atómicamente.

- Es el valor por defecto (`storage_engine: "redb"`): no hay que configurar nada.
- Una red existente sobre el motor viejo (`sled`) **migra sola a redb al reiniciar
  con esta versión** (verificado: el set de cuentas migrado debe ser idéntico; los
  archivos sled quedan de respaldo). Es una elección NODE-LOCAL: no cambia el
  state root / consenso / `chain_id`, no es un hard fork, e interopera con nodos en
  cualquier motor.
- **No usar `sled` como motor de producción**: sled 0.34 NO commitea el estado y
  la ronda en una sola transacción (queda un checkpoint en archivo aparte, dos
  operaciones no atómicas) y retiene multi-GB bajo ráfagas. Queda sólo por
  compatibilidad/dev (`storage_engine: "sled"`).

**Endurecimiento del P2P (SIEMPRE activo, defaults generosos).** El transporte
P2P aplica en la capa de conexión, por defecto y sin configurar nada, defensas de
DoS que el tráfico honesto de validadores nunca dispara (son cotas amplias):

- **Límite global de conexiones** entrantes + **límite por IP** de origen.
- **Una conexión válida por identidad de validador** (con auth): una reconexión
  fresca reemplaza a la conexión vieja/colgada de esa misma identidad.
- **Timeouts** de cabecera (idle), de cuerpo (defensa slowloris: si un peer
  anuncia un mensaje grande y no lo entrega, se corta) y de mensaje completo.
- **Tamaño máximo POR TIPO de mensaje** (un "Vote" de 16 MB se rechaza aunque
  entre bajo el tope global).
- **Cuota de ancho de banda por peer** (ventana móvil, con histéresis).
- **Baneo temporal** de un peer abusivo (por IP y/o identidad).
- **Batches: no se persisten a disco sin relacionarlos primero con un vértice
  válido** — un batch gossipeado que ningún vértice referencia se cachea sólo en
  RAM (acotado por un cap por-validador-y-ronda), y se persiste recién cuando un
  vértice válido lo referencia. Cierra el flood de RAM+disco sin romper el resync.

**MAINNET: auth + cifrado P2P OBLIGATORIOS.** Poné `"mainnet": true` en el
`config.json` de TODOS los nodos para exigir, al arrancar, tanto
`authenticated_transport` (handshake ML-DSA) como `encrypted_transport`
(ML-KEM-768 + ChaCha20-Poly1305). Si `mainnet` está activo y falta cualquiera de
los dos, **el nodo se DETIENE con un error claro** en vez de correr una mainnet
con transporte sin autenticar/en claro. Es una elección node-LOCAL (no cambia el
`chain_id`), pero como auth+cifrado son wire-breaking, TODOS los nodos deben
tenerlos activos juntos (cutover coordinado):

```json
{
  "mainnet": true,
  "authenticated_transport": true,
  "encrypted_transport": true
}
```

En un **testnet** (`mainnet` ausente/`false`, el default) no se impone nada — la
red del usuario sigue exactamente como está.

### Perfil de red obligatorio: `"network_profile": "mainnet"` (tarea #211)

`mainnet: true` sólo exige auth+cifrado. Para la **POSTURA COMPLETA de
producción**, poné `"network_profile": "mainnet"` en el `config.json` de TODOS
los nodos: el nodo **SE NIEGA A ARRANCAR** si falta CUALQUIERA de las
protecciones duras, y **acumula TODAS las faltas en un solo error** (las
arreglás en una pasada, no una por una). Exige:

| Protección | Campo del config |
|---|---|
| Estado persistente | `data_dir` seteado |
| Almacenamiento transaccional | `storage_engine: "redb"` (commit atómico estado+ronda+economía) |
| Transporte P2P autenticado | `authenticated_transport: true` |
| Transporte cifrado | `encrypted_transport: true` |
| Firmante remoto (clave fuera del proceso) | `remote_signer: "host:port"` o `"unix:/ruta.sock"` **+** `remote_signer_auth_token_path` (token de auth del cliente, obligatorio en mainnet) |
| RPC del validador en red privada | `rpc_addr` loopback/RFC1918 (nunca ruteable) |
| Trust anchor de state-sync | `require_state_sync_trust_anchor: true` (+ `state_sync_trusted_root`/`_round` si hay `state_sync_peers`) |
| Límites de RPC explícitos | `rpc_rate_limit_per_10s`, `simulate_rate_limit_per_10s`, `tx_rate_limit_per_10s` (> 0) |
| Parámetros económicos explícitos | `economics_v7: true` + `quanto_rate_fp` BAKED + `rounds_per_quanto` |
| Configuración idéntica entre nodos | el nodo loguea el **network fingerprint** al arrancar — comparalo entre TODOS los nodos |
| TLS en wallet/servicios públicos | la wallet exige `--behind-trusted-proxy` bajo su propio `--network-profile mainnet` (TLS en el proxy) |

Los **límites de P2P** (conexión global/por-IP, timeouts, cuotas de ancho de
banda, ban temporal, batch-vertex gating) son **SIEMPRE activos por
construcción** — no necesitan config. Ejemplo mínimo de un `config.json`
mainnet (además de `validators`/`genesis`/`keypair_path`/`listen_addr`):

```json
{
  "network_profile": "mainnet",
  "data_dir": "data",
  "storage_engine": "redb",
  "authenticated_transport": true,
  "encrypted_transport": true,
  "remote_signer": "127.0.0.1:9200",
  "rpc_addr": "127.0.0.1:8080",
  "require_state_sync_trust_anchor": true,
  "rpc_rate_limit_per_10s": 64,
  "simulate_rate_limit_per_10s": 8,
  "tx_rate_limit_per_10s": 16,
  "economics_v7": true,
  "quanto_rate_fp": 310537755655371,
  "rounds_per_quanto": 86400,
  "state_checkpoints": true,
  "state_sync_min_confirmations": 2,
  "state_sync_trusted_root": "<hex root pinned out of band>",
  "state_sync_trusted_round": 123456
}
```

### State-sync seguro: checkpoint firmado por quórum + verificación conjunta (tarea #212)

Un snapshot ya no se acepta sólo porque coincide con la raíz que el propio par
declara (weak-subjectivity). El nodo que se sincroniza AUTENTICA la
`(ronda, raíz)` de dos formas, y en **mainnet exige el ancla**:

- **Checkpoint firmado por quórum** — con `state_checkpoints: true`, cada
  validador self-firma su `(chain_id, ronda, raíz)` en `/snapshot/meta`. El nodo
  que se sincroniza **UNE** las firmas de todos los peers que confirman el MISMO
  `(chain_id, ronda, raíz)` y sólo acepta si los firmantes distintos alcanzan el
  **quórum de stake** del comité (verificado contra el comité de SU config, nunca
  el que declara un par). Así la confirmación multi-peer ES la agregación del
  quórum, sin subsistema de gossip.
- **Trust anchor** — `state_sync_trusted_root` + `state_sync_trusted_round`
  pinneados por un canal independiente. En **mainnet es OBLIGATORIO**: un snapshot
  sin ancla se rechaza.

Se verifican **CONJUNTAMENTE**: `chain_id` (un par de otra red se descarta),
`validator_set_fingerprint` (comité), ronda y raíz. Y se exige la confirmación de
**varios peers** (`state_sync_min_confirmations`, mínimo **2** en mainnet).

**Requisitos del operador:** poné `state_checkpoints: true` en TODOS los
validadores; el nodo que se recupera lista suficientes **RPC de validadores** en
`state_sync_peers` para que sus checkpoints self-firmados unan a un quórum
(típicamente hace falta que los validadores ARRIBA alcancen el quórum por sí
solos → `n ≥ 4` con stake parejo; con menos, o con demasiados nodos caídos, el
**trust anchor** es el autenticador — por eso es obligatorio en mainnet). Un
relay/réplica read-only (sin clave de validador) no aporta firma; sí aportan los
validadores.

**Fingerprint de red (config idéntica).** Al arrancar en perfil mainnet el nodo
loguea `network fingerprint: <hex>`. Es el hash de los campos que TODOS los nodos
DEBEN compartir (chain_id + auth/cifrado + rotación + perfil). **Comparalo entre
todos los nodos**: si difiere, un nodo está mal configurado (y forkearía o
fallaría el handshake). `qchain-genesis-build --network-profile mainnet` **bakea
el perfil** en cada config generado (el operador completa después los campos
per-nodo: `remote_signer`, `data_dir`, límites).

Podés arrancar un genesis mainnet con el flag: `qchain-genesis-build …
--network-profile mainnet --economics-v7 --quanto-rate-fp <n> --rounds-per-quanto <n>`.

**Wallet mainnet (TLS obligatorio).** La wallet exige TLS: corré
`qchain-wallet --network-profile mainnet --behind-trusted-proxy` (o
`QCHAIN_WALLET_NETWORK_PROFILE=mainnet`). Si no está detrás de un reverse-proxy
que termine TLS (túnel de Cloudflare / nginx / Caddy con HTTPS), **la wallet se
DETIENE** — un servicio público de mainnet nunca se sirve en HTTP en claro.

**RPC privado por defecto.** El JSON-RPC del nodo (`rpc_addr`) bindea a
`127.0.0.1`, así que **solo es accesible desde la propia máquina** (o por un
túnel SSH). El instalador **no abre su puerto en el firewall** cuando detecta
que es local. El RPC no tiene autenticación (como el RPC de cualquier nodo:
Ethereum, Solana, etc.), así que exponerlo en internet dejaría que cualquiera
envíe transacciones y consulte estado sin límite — por eso queda privado.
Lo que SÍ se expone al público es:

- el **puerto P2P** (`listen_addr`, 9000 por defecto) — necesario para que los
  validadores se hablen entre sí; y
- el **explorador QScan** (solo-lectura, seguro de exponer) y la **wallet web**
  (por túnel HTTPS), que son servicios aparte con su propio puerto.

Si de verdad necesitás el RPC accesible desde afuera (un exchange, un
indexador remoto), corré el instalador con `--rpc-public` (bindea a `0.0.0.0` y
abre el puerto), o en una instalación existente editá `rpc_addr` en
`config.json` a `0.0.0.0:<puerto>`, abrí el puerto en el firewall y reiniciá.
Lo recomendado sigue siendo **no** exponerlo: para acceso remoto puntual usá un
túnel SSH (`ssh -L 8080:127.0.0.1:8080 usuario@vps`).

**Rate limit del RPC público (dos capas).**

- **`POST /simulate` — OBLIGATORIO cuando el RPC es alcanzable por clientes
  remotos.** Es el endpoint más caro sin autenticar (corre un verify de firma
  post-cuántica y puede compilar y ejecutar WASM, con un pool chico de simulaciones
  concurrentes). Cuando `rpc_addr` NO es loopback —**o** es loopback pero está
  detrás de un proxy de confianza (`rpc_behind_trusted_proxy: true`, ver abajo)— el
  nodo **fuerza** un rate limit dedicado a `/simulate` — por IP (default 8/10 s,
  nunca por debajo del piso 5, **ventana deslizante sin baneo** para no bloquear a
  todos los que comparten una IP) **y** por txid (ventana, sin baneo — evita el
  replay distribuido de una misma tx firmada sin que un flooder pueda banear el
  txid de una víctima) — y **nunca** acepta `None`/`0` en ese caso; responde `429`
  de inmediato al superar el límite. Ajustable con `simulate_rate_limit_per_10s` en
  el `config.json` (recomendado 5–10). En un loopback genuinamente privado queda
  opt-in. La coalescencia por txid+ronda+state_root (singleflight) y el tope de
  ejecuciones WASM concurrentes están siempre activos.
- **`POST /tx` — OBLIGATORIO cuando el RPC es alcanzable por clientes remotos (task
  #210).** `/tx` recibe una transacción FIRMADA y corre un verify post-cuántico por
  llamada — la segunda superficie más cara. Con la MISMA política que `/simulate`, el
  nodo fuerza en `/tx` un rate limit **por IP** (default 16/10 s, piso 8, ventana sin
  baneo) **y por txid** (ventana, sin baneo — mata el reenvío distribuido de una
  misma tx firmada), rechaza con `429` **antes de parsear/verificar la firma**, y
  nunca acepta `None`/`0` en un bind público. Ajustable con `tx_rate_limit_per_10s`.
  Además, SIEMPRE activos (sin importar el bind, y compartidos con la ruta de gossip
  P2P): un **tope de verificaciones de firma concurrentes** (a lo sumo 8 verifies de
  admisión a la vez, así un flood de tx firmadas distintas no clava todos los cores)
  y una **cuota de admisión GLOBAL + por-pagador** (un techo absoluto de tx/ventana
  que el nodo admite, y por clave, así un botnet de IPs/pagadores distintos tampoco
  puede inflar el trabajo). El cap de tamaño de tx (#192) y el chequeo de solvencia
  del pagador ya eran previos.
- **Resto de endpoints — opt-in.** El rate limit GENERAL por IP (`rpc_rate_limit_per_10s`,
  read/submit) sigue siendo opcional; **activalo** si exponés el RPC público (o
  poné un proxy con su propio rate limit). Sin él, el nodo avisa fuerte al arrancar.

> **Detrás de un reverse-proxy (el túnel de Cloudflare `cloudflared`, o nginx/Caddy
> local):** si dejás el `rpc_addr` en loopback y publicás vía un proxy en el MISMO
> host, poné **`"rpc_behind_trusted_proxy": true`** en el `config.json`. Con eso:
> (1) el `/simulate` obligatorio se activa aunque el bind sea loopback (si no, un
> RPC tunelizado quedaría SIN esa protección), y (2) el rate limit por IP lee el
> cliente real del header **`X-Forwarded-For`** — pero **sólo** cuando el peer TCP
> directo es loopback (el proxy local), así un cliente que pega un bind público
> DIRECTO nunca puede falsificarlo. Usa el último hop del header (el que agregó tu
> proxy de confianza), así una `X-Forwarded-For` inyectada por el cliente queda a
> la izquierda y se ignora — asume **un** proxy de confianza (el caso documentado
> cloudflared / nginx local). **No lo pongas** en un bind público directo ni si tu
> proxy no está en el mismo host. Alternativamente, dejá que el proxy haga su
> propio rate limit — pero el `/simulate` obligatorio del nodo es la red de
> seguridad que no depende de configurar bien el proxy.

**El borde público real es la WALLET, no el nodo.** Los usuarios no llaman al RPC
del nodo directo: van `usuario → Cloudflare/nginx → wallet web → nodo`. Por eso la
wallet (`qchain-wallet`) rate-limita ELLA MISMA sus proxies `POST /api/simulate` **y
`POST /api/relay-tx`** (el reenvío de una tx firmada al `/tx` del nodo, task #210)
por la IP REAL del cliente y se la reenvía SANEADA al nodo, para que el segundo rate
limit del nodo también mida clientes reales en vez de agrupar a todos bajo
`127.0.0.1` (la IP con que la wallet, en el mismo host, habla con el nodo). Se
activa con **`--behind-trusted-proxy`** en la wallet (o `QCHAIN_WALLET_BEHIND_PROXY=1`):
la wallet lee la IP del cliente de `CF-Connecting-IP` / `X-Forwarded-For` **sólo
cuando el peer TCP directo es loopback** (el túnel/nginx local), la usa para su
propia ventana de 10 s por IP (default 8, piso 5, `--simulate-rate-limit-per-10s`),
responde `429` antes de reenviar, y FALLA CERRADO (429) si no puede identificar al
cliente (nunca agrupa a todos bajo el proxy). El nodo, del otro lado, va con
`rpc_behind_trusted_proxy:true` + `simulate_rate_limit_per_10s:8` para leer esa IP
reenviada. **El instalador lo configura solo** cuando instalás con `--con-tunel`
(nodo: los dos campos en `config.json`; wallet: `--behind-proxy` en el servicio) —
no hace falta editar nada a mano. Un `singleflight` por txid+ronda+state_root y el
tope de 4 simulaciones WASM concurrentes siguen siempre activos en el nodo.

**Producción: separá el RPC público (simulación + admisión de tx) del validador de
consenso.** Un `/simulate` público **y** un `/tx` público son superficie de ataque
(CPU: verify PQC + WASM en simulación, verify PQC por tx en admisión — task #210).
Lo ideal para mainnet es **no** exponer ninguno de los dos desde el mismo proceso
que produce bloques: correr uno o más nodos de **sólo-lectura/relay** (misma red,
mismo `chain_id`, **sin** clave de validador) detrás del proxy público — reciben
`/simulate` y `/tx`, verifican la firma, y GOSSIPean la tx admitida al validador por
P2P — y mantener el nodo validador en loopback/privado. Así ni una tormenta de
simulaciones ni un flood de tx firmadas compiten por CPU con el consenso; el
validador sólo ve tx ya verificadas llegando por el canal P2P (a su vez acotado por
el mismo tope de verify concurrente + la cuota de admisión global/por-pagador, que
están SIEMPRE activos en todo nodo).

### Réplica read-only de simulación en un comando (`deploy/install-sim-replica.sh`)

Automatiza esa separación. Una **réplica** es un nodo en modo seguidor (sincroniza
el estado y sigue la cadena, pero **no** valida ni propone) con el RPC **público**
y el rate limit de `/simulate` **forzado**. Si se cae o la saturan, el consenso
**no** se ve afectado. Corré esto en una VPS **distinta** a la del validador:

```sh
# el config PÚBLICO de la red lo da cualquier nodo que ya corra (validators+
# genesis, SIN claves); --sync-peer es el RPC de un nodo vivo para ponerse al día.
sudo ./deploy/install-sim-replica.sh \
    --config config-publico-de-la-red.json \
    --sync-peer http://<ip-de-un-nodo-vivo>:8080 \
    --behind-proxy          # si le ponés Cloudflare/nginx adelante (recomendado)

sudo ./deploy/install-sim-replica.sh --uninstall     # baja el servicio (no toca datos)
```

Es un envoltorio fino sobre `install-node.sh --modo unirse --rpc-public`: reusa
toda la maquinaria probada (Docker, identidad P2P, adaptación del config,
firewall, systemd) y sólo agrega el endurecimiento del endpoint de simulación
(`simulate_rate_limit_per_10s`, `rpc_behind_trusted_proxy` con `--behind-proxy`).
Escalás corriéndolo en varias VPS y balanceando `/simulate` entre ellas
(round-robin en tu nginx/Cloudflare). **Nunca** le pongas claves de valor: es una
ventana de lectura/simulación, sin autenticación por diseño.

**Aislamiento de claves entre servicios.** Cada servicio ve solo el directorio
que necesita, montado por volumen en su contenedor:

- el **validador** monta `/opt/qchain` (su `keypair.json` — la clave que firma
  bloques);
- la **wallet** monta solo `/opt/qchain/wallets` (nunca ve la clave del
  validador);
- el **indexador/QScan** monta solo `qscan-data` (es solo-lectura, no tiene
  ninguna clave);
- el **faucet** monta solo `/opt/qchain-faucet` (su propia clave caliente).

Ningún servicio expuesto a internet (QScan, wallet, faucet) tiene acceso a la
clave del validador.

**Firmante remoto / HSM de la clave de validador (`remote_signer`, tarea #193).**
Por defecto la clave que firma bloques vive DENTRO del proceso del nodo (el
`keypair.json` que lee al arrancar) — cómodo, pero es la superficie más expuesta
a internet (RPC, P2P, dashboard). Podés sacar esa clave a un **proceso separado**
(o un HSM), estilo `tmkms` de Cosmos, para que comprometer el nodo **no filtre la
clave**. El nodo le pide firmas por un socket local y nunca ve el material de
clave.

Cómo activarlo (OPT-IN; por defecto sigue todo en-proceso, byte-idéntico):

1. **Mové** el `keypair.json` del validador de `/opt/qchain` a `/opt/qchain-signer`
   (para que el nodo ya no lo tenga).
2. **Generá el token de auth del cliente** (#4.2 — un secreto compartido entre el
   nodo y el firmante):
   `head -c 32 /dev/urandom | base64 > /opt/qchain-signer/signer.token && chmod 600 /opt/qchain-signer/signer.token`
   (el mismo archivo lo verá el nodo — copialo a donde el nodo lo lea, p.ej.
   `/opt/qchain/signer.token`, 0600).
3. **Arrancá el firmante** (bindea loopback — sólo el nodo del mismo host lo
   alcanza — y EXIGE el token): `sudo systemctl enable --now qchain-remote-signer`
   (unidad `deploy/systemd/qchain-remote-signer.service`), o a mano:
   `qchain-remote-signer --keypair /opt/qchain-signer/keypair.json --listen 127.0.0.1:9200 --guard-file /opt/qchain-signer/guard.bin --auth-token-file /opt/qchain-signer/signer.token`
   (o `--listen unix:/run/qchain/signer.sock` para un socket Unix con aislamiento
   de permisos del SO).
4. **Poné** `"remote_signer": "127.0.0.1:9200"` **y** `"remote_signer_auth_token_path":
   "/opt/qchain/signer.token"` en el `config.json` del nodo y reiniciá el validador.
   En el arranque el nodo loguea
   `consensus signer: REMOTE ... [client auth: TOKEN]`.

Es una migración **sin cambio de identidad**: el firmante sostiene la MISMA clave,
así que el validador es el mismo (misma dirección, mismo registro on-chain, mismo
`chain_id`) — no hay re-registro ni génesis nuevo. El firmante trae una **guardia
anti-doble-firma persistida** (`guard.bin`): se niega a firmar dos vértices
PROPIOS distintos para la misma ronda, aun si el proceso del nodo estuviera
comprometido — la propiedad de seguridad central de un firmante de validador.
**Autenticación del cliente del socket (#4.2, auditoría v8.6.13 — CERRADO):** con
el token, cada conexión debe probar que lo conoce por **challenge-response** (el
servidor manda un nonce fresco; el cliente responde con
`SHA3-256(dominio ‖ token ‖ nonce)`, verificado en tiempo constante) ANTES de que
el daemon firme nada — un proceso local que no conoce el token es **rechazado**.
Con un socket **Unix**, además, sólo un proceso del MISMO usuario puede abrirlo
(dir `0700`, socket `0600`). El perfil **mainnet del nodo EXIGE** tanto un endpoint
loopback/UDS como el token (fail-stop). `--allow-non-loopback` sigue existiendo
para una dirección TCP pública (sólo sobre un enlace privado + firewall + el
token). Esto saca la clave del proceso del nodo (incremento A de #193) y cierra el
"cualquier proceso local puede pedir firmas sin autenticarse" (#4.2).

**Separación de roles de clave — dirección FRÍA de retiro (`withdrawal_address`,
tarea #193-B, incremento B).** La clave de consenso (online, en el nodo o en el
firmante remoto) firma bloques, pero por defecto TAMBIÉN es la dirección donde se
acreditan las comisiones de fee que gana el validador — así que una fuga de esa
hot key deja gastar las ganancias. Con una dirección de retiro configurada, esas
comisiones se acreditan a una dirección **cuya clave FRÍA guardás offline**: la
clave de consenso puede firmar/equivocar (slasheable) pero NO puede gastar los
fondos. **Cómo:** agregá `"withdrawal_address": "<base58>"` a la entrada de tu
validador en `validators` (o pasá `--withdrawal-address <dir>` a
`install-node.sh` en modo solo, o el campo homónimo del manifiesto de
`qchain-genesis-build`). Refuerzo del firmante remoto: rechaza firmar cualquier
mensaje del dominio de transacción (`qchain-tx-sig-v1`), así la clave de consenso
NO puede autorizar una transferencia de valor aunque el proceso del nodo esté
comprometido. **Es una decisión de génesis** (cambia DÓNDE se acredita el fee →
se pliega en el `chain_id` sólo cuando está seteada): elegila al crear la red;
una red sin ella conserva su `chain_id` exacto y las ganancias van a la dirección
de consenso (comportamiento previo). Determinista → todos los nodos acreditan la
misma dirección, sin fork.

**Endurecimiento del contenedor.** Los cuatro servicios systemd corren con
`--security-opt no-new-privileges` (un proceso dentro del contenedor no puede
ganar privilegios vía setuid) y `--cap-drop ALL` (se le quitan todas las
capabilities de Linux — el nodo no necesita ninguna). Si editás una unidad a
mano, no quites estas dos líneas.

**Pin de descargas.** El túnel (`install-tunnel.sh`) baja `cloudflared` de una
versión FIJA (no del tag mutable `latest`), imprime el SHA-256 del binario
descargado, y con `--cf-sha256 <hex>` lo EXIGE (aborta si no coincide). El
instalador del nodo baja el script oficial de Docker a un archivo y recién ahí
lo corre (en vez de un `curl | sh` a ciegas), y respeta `QCHAIN_DOCKER_VERSION`
para fijar la versión de Docker.

**Límites de recursos + rotación de logs (`deploy/install-limits.sh`).** Cada
unidad systemd trae ya sus **límites de recursos**: los flags de docker
`--memory` / `--pids-limit` / `--ulimit nofile` (los que acotan el CONTENEDOR de
verdad — RAM, hilos y file descriptors, cerrando por config las clases de
runaway que el código ya acota: el blowup de RAM del flood, el de 300k tareas, y
el agotamiento de fd tipo slowloris) más los `MemoryMax` / `TasksMax` /
`LimitNOFILE` a nivel de la unidad (defensa-en-profundidad). Valores por defecto
generosos (validador 3G / 8192 hilos / 65536 fd; wallet/faucet/indexer más
chicos) — un despliegue grande los sube editando la unidad. En una instalación
FRESCA los toma solos; para un box YA desplegado corré
`sudo ./deploy/install-limits.sh` (aplica los caps a las unidades existentes vía
drop-in, sin reescribir su `ExecStart`; `--restart` para tomarlos ya, o se
aplican en el próximo restart). Ese mismo script instala el **límite de tamaño
del journal** (los servicios corren como `docker run` bajo systemd → su stdout
va al journal; sin cota puede llenar el disco → se acota a 500M vía un drop-in de
`journald`) y el **logrotate** de los `*.log` de archivo (install.log, backups,
monitoreo). `--uninstall` revierte todo. `install-node.sh` lo corre solo al final.

**Attestation de la imagen (`deploy/attest-image.sh`).** Como no hay registro
remoto (la imagen `qchain:latest` se construye en cada host desde el
`Dockerfile`), la attestation es local pero real: `record` graba en
`image-attestation.json` la **id (digest) de la imagen desplegada + el commit
git + el hash del Dockerfile + la fecha**; `verify` confirma que la imagen local
y **cada contenedor qchain en ejecución** usan exactamente esa id (exit ≠ 0 si
alguno corre otra imagen — p.ej. quedó una vieja tras un rebuild sin restart, o
alguien la cambió), pensado para un cron de monitoreo o un gate de CI. Avisa si
grabaste con el repo sucio (`git_dirty`) — esa imagen no es reproducible desde el
commit solo (la firma/reproducibilidad de artefactos es su propia tarea, #198).

**Cadena de suministro (tarea #198).** Varias piezas que hacen auditable de dónde
salió el binario:

- **Toolchain pinneado + `Cargo.lock` + `--locked`** → build reproducible. El
  `rust-toolchain.toml` fija la versión EXACTA del compilador (1.94.1) que rustup
  instala en cualquier máquina/Docker/CI, y el `Dockerfile` usa `rust:1.94-bookworm`
  + `cargo build --locked` (deps pinneadas al `Cargo.lock` committeado).
- **SBOM** (`deploy/gen-sbom.sh`) → inventario CycloneDX de TODA dependencia
  transitiva con versión y checksum SHA-256, derivado sólo del `Cargo.lock`
  (determinista, sin red). CI lo genera y lo sube como artefacto; a mano:
  `deploy/gen-sbom.sh -o sbom.cdx.json`.
- **CI de seguridad** (`.github/workflows/ci.yml`): build `--locked` + `clippy -D
  warnings` + toda la suite (incl. DST 9/9 y ataques WASM) + **`cargo audit`**
  (RustSec) + el SBOM.
- **CODEOWNERS** (`.github/CODEOWNERS`): un cambio a consenso/cripto/ejecución/CI/
  deploy exige la revisión del maintainer (necesita branch protection con "Require
  review from Code Owners"). Reemplazá `@owner` por tu handle real de GitHub.
- **Firmas GPG** (`deploy/sign-release.sh`): firma un manifiesto (hashes del
  `Cargo.lock` + `Dockerfile` + SBOM + **provenance** + los binarios) y, opcional,
  la tag. **Requiere tu clave GPG** (la firma es humana). Activá también
  `git config --global commit.gpgsign true`.
- **Provenance verificable** (`deploy/gen-provenance.sh` → `provenance.json`): UN
  archivo determinista que RELACIONA `commit → version → binarios → imagen de
  despliegue → wasm de la wallet`. Un verificador corre
  `deploy/verify-provenance.sh --provenance provenance.json` para confirmar, sin
  confiar en el servidor, que todo salió del commit firmado.
- **CI de release** (`.github/workflows/release.yml`): al pushear una tag `vX.Y.Z`
  re-corre el gate completo (build+clippy+tests+audit) SOBRE ESE commit y sólo
  entonces produce+firma los artefactos → **CI verde sobre el mismo commit antes
  del release**. Los jobs pesados (fuzz/sanitizers/reproducible) corren nightly.

Ver **`docs/RELEASE-VERIFY.md`** para el flujo completo (cortar un release firmado,
verificar la cadena, y activar protección de rama + revisión obligatoria — que son
settings del repo en GitHub, no código).

**Pendiente honesto:** la reproducibilidad **bit-for-bit** entre máquinas distintas
necesita un entorno de build hermético (el `SOURCE_DATE_EPOCH` + toolchain pinneado
+ el job `reproducible` cubren el mismo-entorno); firmar la IMAGEN en un registro
(cosign) es un follow-up cuando se publique a uno; y la auditoría externa + bug
bounty (tarea #203) es un proceso humano con terceros.

## Respaldos automáticos (`deploy/backup-node.sh`)

Lo ÚNICO irreemplazable de un validador es su `keypair.json` (la clave que firma
bloques): si la perdés, tu validador deja de existir. El estado (`data/`) es
re-sincronizable de los pares, y el `config.json` es público. Así que el respaldo
se enfoca en las CLAVES + el config, siempre **cifrado** (AES-256, PBKDF2).

```
# definir una contraseña de cifrado UNA vez (guardala FUERA de la VPS)
echo 'UNA-CONTRASEÑA-FUERTE' | sudo tee /opt/qchain/backup.pass >/dev/null
sudo chmod 600 /opt/qchain/backup.pass

# un respaldo ahora
sudo ./deploy/backup-node.sh

# respaldo diario automático (timer systemd, ~03:30)
sudo ./deploy/backup-node.sh --install

# copiar cada respaldo FUERA de la máquina (durabilidad real si la VPS muere)
sudo ./deploy/backup-node.sh --install --remote usuario@otro-host:/backups

# restaurar
sudo ./deploy/backup-node.sh --restore /opt/qchain-backups/qchain-backup-XXX.tar.gz.enc --into /tmp/rec
```

El respaldo NUNCA se escribe en texto plano (sin contraseña, se niega a correr).
Rota los últimos 14 por defecto (`--keep N`). **Sin la contraseña no hay forma de
descifrar el respaldo — guardala en un lugar seguro y separado de la VPS.**

## Monitoreo externo con aviso (`deploy/monitor-node.sh`)

Como el RPC ahora es privado (127.0.0.1), el chequeo corre EN la máquina y
EMPUJA un aviso hacia afuera (a tu teléfono/chat) si el nodo se cae o el consenso
se congela. Detecta dos cosas: (1) el RPC no responde (nodo caído), y (2) las
rondas no avanzan por más de `--stall-secs` (consenso congelado). Avisa una sola
vez por transición (no spamea) y avisa también cuando se recupera.

```
# elegí un canal: ntfy (lo más simple para el celular), Discord, Slack o webhook
sudo ./deploy/monitor-node.sh --ntfy https://ntfy.sh/mi-canal-secreto --test     # probar el aviso
sudo ./deploy/monitor-node.sh --ntfy https://ntfy.sh/mi-canal-secreto --install  # chequeo cada 2 min
```

Con ntfy: instalá la app ntfy en el teléfono y suscribite al mismo canal — los
avisos llegan como notificación push, sin cuenta ni servidor propio. También:
`--discord <webhook>`, `--slack <webhook>`, o `--webhook <url>` (POST JSON
`{"text": "..."}`). Quitar el monitor: `sudo ./deploy/monitor-node.sh --uninstall`.

## Vigilante de runtime con IA (`deploy/qchain-watchdog.py`)

El escalón siguiente a `monitor-node.sh`: un servicio **read-only** de dos capas
que corre **fuera** del validador y vigila un nodo vivo (tarea #183, Fase B — ver
`docs/AI-RUNTIME-WATCHDOG.md`). **Capa 1** (heurísticas deterministas, SIN IA,
siempre corriendo) sondea `/status`, `/economics`, `/resources` y opcional
cross-check de `/root` entre nodos, y dispara señales con umbrales fijos (consenso
congelado, fee disparado, mempool creciendo, RAM/disco, **fork** si dos nodos
reportan roots distintos a la misma ronda, ...). **Capa 2** (Claude como analista,
sólo si hay `ANTHROPIC_API_KEY`) correlaciona señales débiles en un veredicto con
acción **humana** recomendada — advisory, nunca actúa.

```sh
./deploy/qchain-watchdog.py --selftest                     # autotest offline (sin red)
sudo ./deploy/qchain-watchdog.py --install --rpc http://<ip>:8080 \
    --ntfy https://ntfy.sh/mi-canal --cross-check http://<ip-otro-nodo>:8080
# Capa 2 (opcional): la API key va en el entorno del servicio, NUNCA en el repo:
sudo sh -c 'echo "ANTHROPIC_API_KEY=sk-ant-..." > /etc/qchain-watchdog.env'
sudo chmod 600 /etc/qchain-watchdog.env && sudo systemctl restart qchain-watchdog
```

Modelo de seguridad: read-only, sin llaves de la cadena, sin poder de acción
destructiva (peor caso = "mandó una alerta falsa"); **inerte** sin la API key (la
Capa 1 corre igual). Corrélo en una caja **aparte** del validador.

## Explorador QScan (`deploy/install-indexer.sh`)

QScan es el explorador de bloques de la red, estilo Etherscan — un servicio
**aparte** del validador. Un validador guarda solo lo que necesita para
validar (estado + DAG reciente + sus claves) y sirve una ventana rodante de
las últimas transacciones; **QScan** (`qchain-indexer`) sigue al nodo por RPC
y construye su **propio índice durable y completo** más el sitio web:
inicio con últimos bloques/transacciones, búsqueda (por dirección, hash de tx
o número de ronda), páginas de bloque, de transacción (con balances
antes/después), de dirección (historial completo), de validadores y de
holders (rich list). Es exactamente cómo Ethereum separa un validador de
Etherscan.

**Es de SOLO LECTURA** — no toca claves ni el consenso —, así que exponerlo
en público es seguro (a diferencia del RPC o la wallet). Se puede correr en
la misma VPS que el nodo o en otra máquina apuntando `--rpc-port`/`--node` al
RPC del nodo.

Instalarlo como servicio systemd (un comando, en la VPS, dentro del repo):

```
sudo ./deploy/install-indexer.sh --yes
# explorador en http://<ip>:9200  (seguí al nodo local en RPC :8080)
```

Opciones: `--port` (puerto del explorador, 9200), `--rpc-port` (RPC del nodo a
seguir, 8080), `--poll-ms` (sondeo, 1000). Bajarlo sin borrar el índice:
`sudo ./deploy/install-indexer.sh --uninstall`. `deploy/update.sh` lo reinicia
solo contra la imagen recién construida si está instalado.

**Correrlo a mano** (sin systemd, p. ej. para probar local):

```
qchain-indexer --node http://127.0.0.1:8080 --bind 0.0.0.0:9200 \
    --data ./qscan-data --poll-ms 1000
```

El índice es durable (sled) y sobrevive reinicios; si arranca con el índice
vacío, se rellena solo desde la ventana del nodo. Para exponerlo por HTTPS,
un túnel de Cloudflare apuntando al puerto del explorador funciona igual que
para la wallet (ver `deploy/install-tunnel.sh`). Límite honesto: QScan indexa
transferencias de una instrucción y actividad de staking (lo que el nodo
expone en `/transfers` y `/staking_activity`); su vista de holders/economía es
la foto point-in-time del nodo que sigue.

### Red con árbol comprimido (`--comprimido`, ~6× throughput)

Para crear una red NUEVA con el **árbol de estado comprimido** (mayor
throughput de apply y menos RAM/disco bajo carga), agregá `--comprimido` al
crear la red en modo solo:

```
sudo ./deploy/install-node.sh --modo solo --comprimido --con-tunel --yes
```

**Es un hard fork, decidido en el génesis:** cambia la raíz de estado y se
pliega en el `chain_id`, así que **solo se puede elegir al CREAR la red** — no
se puede convertir una cadena ya corriendo, y TODOS los nodos de esa red deben
usar el mismo valor (si no, divergen). Para pasar una red existente a
comprimido, arrancá una red nueva con `--comprimido` (el estado viejo no se
migra automáticamente; es una cadena distinta). El beneficio se nota bajo carga
alta; a tráfico bajo la diferencia es chica.

### Red con economía v7 (`--economics-v7`)

Para crear una red NUEVA con la **economía v7** (staking shares+índice, emisión
por cuanto, split de fee **45% validadores / 45% quema / 10% admin**, bono de
validador de **500 QCH**), agregá `--economics-v7` al crear la red en modo solo:

```
sudo ./deploy/install-node.sh --modo solo --economics-v7 --con-tunel --yes
```

Opcionalmente `--rounds-per-quanto <n>` fija cuántas rondas dura un cuanto (la
unidad de tiempo económico de v7; por defecto 172800). En un testnet conviene
bajarlo para ver la emisión/reparto cruzar borders rápido.

**Es un hard fork, decidido en el génesis:** `economics_v7` se pliega en el
`chain_id`, así que una red v7 es una red **separada** de una v6 (una tx firmada
para v6 la rechaza v7, y viceversa) — solo se elige al CREAR la red, y TODOS los
nodos deben usar el mismo valor (si no, divergen). Una red creada **sin** el flag
queda byte-idéntica a v6. Se combina con `--comprimido` (ambos son decisiones de
génesis). Tras crear la red, un validador se registra con
`qchain v7-bond-register --moniker <nombre> --p2p-address <ip:puerto>` (bloquea
500 QCH y entra al comité de reparto de fees al cuanto siguiente); sale con
`qchain v7-begin-exit` y recupera el bono con `qchain v7-withdraw-bond` tras la
ventana de unbonding.

**¿Pasar una red v6 que YA existe a v7?** Eso es un **relanzamiento coordinado**
(génesis nuevo, `chain_id` distinto, con opción de conservar los saldos v6). El
runbook completo paso a paso — incluyendo el carry-over de saldos con
`deploy/v6-snapshot-to-v7-genesis.sh` y el cross-check del `chain_id` que ahora
imprime `qchain-genesis-build` — está en **[`RELAUNCH-V7.md`](RELAUNCH-V7.md)**.

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
- `deploy/backup-node.sh` — respaldo CIFRADO (AES-256) de las claves + config,
  con rotación, copia remota opcional (scp) y timer diario. Ver "Respaldos
  automáticos" arriba.
- `deploy/monitor-node.sh` — monitoreo de salud (RPC vivo + rondas avanzando)
  con aviso EXTERNO (ntfy/Discord/Slack/webhook) y timer cada 2 min. Ver
  "Monitoreo externo con aviso" arriba.
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

**Ancla OBLIGATORIA para producción/mainnet (tarea #194).** Por defecto el
state-sync corre en *weak subjectivity* (confía en la raíz que reporta el par,
suavizado por el cross-check + la consistencia interna). Para una red con valor
real, poné **`"require_state_sync_trust_anchor": true`** en el `config.json`: con
eso el nodo **se niega a sincronizar** salvo que estén fijados los DOS campos del
ancla (`state_sync_trusted_root` + `state_sync_trusted_round`) y el snapshot
coincida exacto — nunca confía en la raíz de un par, solo en un valor que vos
obtuviste por fuera (p.ej. de un nodo tuyo ya sano). Es una **política node-LOCAL**
(NO se pliega en el `chain_id`) y solo afecta el camino de state-sync, así que un
nodo con `data_dir` propio nunca la toca. Falla temprano (antes de tocar la red)
con un mensaje claro si falta el ancla.

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

**Para actualizar un nodo** — ahora es UN SOLO COMANDO (desde el repo, en la
VPS del nodo):

```
sudo ./deploy/update-node.sh    # git pull + rebuild + restart + health-check
```

El script hace todo solo, en orden: **(1)** `git pull` del repo (como el dueño
del repo, no como root, para evitar el error de "dubious ownership" de git);
**(2)** si el commit no cambió desde la última actualización, **no reconstruye**
(salvo `--force`); **(3)** etiqueta la imagen actual como `qchain:previous`
(punto de **rollback** real); **(4)** reconstruye `qchain:latest`; **(5)**
reinicia el servicio systemd; **(6)** hace un **health-check de verdad** — no
solo que systemd diga "active", sino que el RPC responda **y que la ronda de
consenso avance** (detecta un nodo congelado). Si no queda sano, con
`--rollback` vuelve solo a la imagen anterior; sin la bandera te deja el
comando exacto de rollback. **Tu clave, `config.json` y `data/` nunca se
tocan** — el nodo resume su estado exacto desde `data_dir`.

Banderas: `--no-pull` (no hacer git pull), `--force` (reconstruir aunque no
haya cambios), `--rollback` (volver solo a la versión anterior si el nodo no
queda sano), `--yes` (sin preguntar).

**Actualizar nodo Y wallet de una vez:** `sudo ./deploy/update.sh` — hace el
flujo completo de arriba y además reinicia la wallet contra la misma imagen,
**reconstruyendo una sola vez** (no dos).

**Actualización rápida de solo la wallet** (cambios de interfaz — lo más
frecuente): `sudo ./deploy/update-wallet.sh` (también hace git pull +
skip-si-no-cambió + health-check HTTP) reconstruye la imagen y reinicia
**solo** `qchain-wallet`, sin reiniciar el validador.

Para cortar una versión nueva (cuando hagas mejoras): subí `version` en el
`Cargo.toml` raíz, actualizá `version.json`, commiteá, y cada operador corre
`update-node.sh`.

## Gobernanza endurecida y pausa de emergencia (multisig) — task #213

Desde v8.0.0 la gobernanza económica (base_fee, dust, gas, comisión, emisión) es
tier **`Economic`**: exige **supermayoría 2/3**, **30% de participación mínima**,
y una **ventana de revisión (timelock) real de ~120 rondas** antes de ejecutar —
ya no se aplica al instante con poca participación. Además, **el poder de voto se
congela al crear la propuesta** (snapshot del `total_staked`), y **cada parámetro
sólo puede moverse un máximo por propuesta** (≤2× para base_fee/dust/gas, ≤2000 bps
comisión, ≤500 bps emisión) — un cambio grande se reparte en varias propuestas.

**Pausa de emergencia por multisig (opcional, decisión de génesis).** Un conjunto
de *guardianes* con umbral M‑de‑N puede **pausar la ejecución de cualquier cambio
de gobernanza** mientras investiga — un freno de emergencia. La pausa **sólo
voltea una bandera y bloquea `execute-proposal`; nunca toca un balance**, así que
es estructuralmente incapaz de confiscar o mover fondos.

Se configura **al crear la red** (se pliega en el `chain_id`, así que una red ya
lanzada la activa relanzando con génesis nuevo; los otros 6 endurecimientos toman
efecto con sólo actualizar el binario):

```bash
# al armar la config compartida:
qchain-genesis-build ... \
  --guardian <PUBKEY_GUARDIAN_1_base58> \
  --guardian <PUBKEY_GUARDIAN_2_base58> \
  --guardian <PUBKEY_GUARDIAN_3_base58> \
  --guardian-threshold 2          # 2 de 3 aprobaciones para pausar/despausar
```

o directo en el `config.json` de TODOS los nodos (el mismo set en todos, o
computan un `chain_id` distinto y se rechazan entre sí):

```json
  "governance_guardians": ["<b58_1>", "<b58_2>", "<b58_3>"],
  "governance_guardian_threshold": 2
```

Pausar/despausar (cada guardián firma con su clave; al alcanzar el umbral, se
voltea la bandera):

```bash
qchain emergency-pause   --rpc http://127.0.0.1:8080 --keypair guardian1.json
qchain emergency-pause   --rpc http://127.0.0.1:8080 --keypair guardian2.json   # umbral alcanzado → pausado
# ... investigar ...
qchain emergency-unpause --rpc http://127.0.0.1:8080 --keypair guardian1.json
qchain emergency-unpause --rpc http://127.0.0.1:8080 --keypair guardian2.json   # → despausado
```

Sin `governance_guardians` configurados (el default), la pausa queda **inerte**
(nadie puede pausar) y la red conserva su `chain_id` exacto.

## Ajustar el TPS: `round_interval_ms`

El techo de TPS de qchain está **medido** (no estimado): un `apply_transaction`
hace ~712 tx/s en un solo hilo, dominado (~82%) por las actualizaciones del árbol
de Merkle de estado (256 hashes por escritura de cuenta) — NO por la verificación
de firma PQC (~10%) ni por la captura del recibo STARK (~8%). Un nodo solo drena
~300 tx/s (apply + lock + consenso + persistencia).

En una red **multi-nodo geodistribuida** el límite real suele ser la **latencia
de consenso** (propagación de certificados + verificación de votos entre nodos),
no el `apply`. Ahí el knob más efectivo y seguro es **bajar `round_interval_ms`**
(ms entre rondas de consenso; por defecto 500 = 2 rondas/s). Bajarlo a **250**
(4 rondas/s) sube el techo de rondas/s. Es un cambio **node-local, sin fork ni
riesgo de consenso**: el gate de quórum de `propose_round` lo protege — un tick
demasiado rápido no-opea hasta que la ronda previa certifica, así que el intervalo
es un *piso*, no un driver rígido, y el techo real lo pone la CPU/red.

**Reglas:**
- **TODOS los nodos de una red deben usar el mismo valor** (para una cadencia
  consistente; `round_interval_ms` está excluido del `chain_id`, así que no
  forkea, pero conviene uniformarlo).
- **Salvedad de emisión:** las recompensas de staking se emiten **por ronda**
  (`ROUNDS_PER_YEAR` asume 500 ms). Rondas más rápidas → más emisión por año de
  reloj. Si bajás el intervalo a la mitad (500→250), la emisión real por año se
  duplica; para mantener ~12% real, bajá el APR por gobernanza a la mitad:
  `qchain propose-set-emission-apr --value 600 ...` (6%). Sin staking activo
  (`total_staked == 0`) la emisión es 0 y esto no aplica.

**Instalación nueva:** `sudo ./deploy/install-node.sh --round-interval 250 ...`

**Red ya desplegada (tu caso):** editá `round_interval_ms` en el `config.json` de
CADA nodo y reiniciá:
```bash
# en cada VPS, con el mismo valor en todos:
sudo python3 - <<'PY'
import json; p="/opt/qchain/config.json"; d=json.load(open(p)); d["round_interval_ms"]=250; json.dump(d,open(p,"w"),indent=2)
PY
sudo systemctl restart qchain-validator
```
Después mirá el TPS real en el panel del validador (`GET /`, la tarjeta "tx/s" es
una medición real de ejecutadas/segundo) antes y después para ver la mejora en tu
hardware. Si el nodo se satura de CPU (load average alto, rondas que no avanzan),
subí el intervalo de nuevo — el punto óptimo depende de tu hardware y del nº de
validadores.

**El gran salto de TPS** (reducir ese 82% del árbol de Merkle) requeriría
reemplazar el árbol disperso de 256 de profundidad por uno path-comprimido estilo
Jellyfish (Aptos/Diem, O(log n) hashes por escritura) — un rediseño mayor que toca
el state root (consenso) y el binding STARK, con verificación DST completa. Queda
como trabajo futuro de mayor alcance.

### Agregar un validador nuevo (incluso de alguien que no conocés)

El registro de validadores es **on-chain y permissionless** — no hace falta
que un coordinador recolecte a mano el bundle/dirección/stake de cada uno:

1. **El nuevo validador se registra a sí mismo** (necesita QCH; pedilo al
   faucet): bloquea self-stake y publica su bundle + dirección P2P on-chain.
   ```
   qchain stake-delegate --rpc <nodo> --keypair suya.json --validator <su propia dirección> --amount 10000000
   qchain register-validator --rpc <nodo> --keypair suya.json --stake-account <la que imprimió> --address <su_ip:puerto>
   ```
2. **Un coordinador regenera la lista de validadores** desde el registro
   on-chain, con un comando, y la pega en la config:
   ```
   qchain gen-validators --rpc <nodo>     # imprime el array `validators` listo para la config
   ```
   Pegá ese array en el campo `validators` de la config de **cada** nodo
   (todos deben usar el **mismo** array, o los nodos no se ponen de acuerdo
   sobre el conjunto), commiteá, y cada operador corre `sudo ./deploy/update.sh`.

Esto elimina el recolectar-a-mano y el editar genesis. Sigue habiendo un
redeploy coordinado (un `update.sh` por operador). **Nota honesta:** la
rotación **automática** del conjunto sin redeploy (que un validador entre solo
al consenso en cuanto se registra) es un cambio de protocolo de consenso más
profundo (BFT reconfiguration), documentado como trabajo siguiente — el camino
de arriba es el seguro y ya disponible.

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
