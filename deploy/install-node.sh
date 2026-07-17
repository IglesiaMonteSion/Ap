#!/usr/bin/env bash
# Instalador simplificado de un nodo qchain - pensado para alguien SIN
# conocimientos tecnicos: un solo comando (`sudo ./install-node.sh`) que
# hace todo lo que docs/DEPLOY.md documenta a mano (generar clave, armar
# config.json, abrir puertos, instalar el servicio systemd) con preguntas
# minimas y valores por defecto sensatos. No reemplaza el flujo manual de
# docs/DEPLOY.md (sigue existiendo para despliegues multi-region reales
# con mas control) - es la puerta de entrada rapida para la primera vez.
#
# Uso interactivo (recomendado la primera vez):
#   sudo ./install-node.sh
#
# Uso no interactivo / automatizado (mismo resultado, sin preguntas):
#   sudo ./install-node.sh --modo solo --yes
#   sudo ./install-node.sh --modo unirse --config /ruta/a/config.json --yes
#
# Para bajar el nodo sin tocar tu clave ni el estado de la cadena:
#   sudo ./install-node.sh --uninstall
#
# Ver todas las opciones: sudo ./install-node.sh --help
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="qchain:latest"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
MODO=""
ASUMIR_SI=0
UNINSTALL=0
NO_BUILD=0
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_ORIGEN=""
LISTEN_PORT_ARG=""
RPC_PORT_ARG=""
# Milisegundos entre rondas de consenso. 500 (2 rondas/s) es el default seguro.
# Bajarlo (p.ej. 250) sube el techo de TPS en una red multi-nodo limitada por
# latencia de consenso - es config node-local, sin fork (un tick demasiado
# rápido no-opea hasta que la ronda previa certifica). TODOS los nodos de una
# red deberían usar el mismo valor. Salvedad: la emisión de staking es nominal
# por-ronda, así que rondas más rápidas inflan más rápido por año de reloj -
# retuneá el APR por gobernanza (propose-set-emission-apr) si cambiás esto.
RONDA_MS="${RONDA_MS:-500}"
FONDO_WALLET_PRUEBA="1000000000000"
CON_WALLET=0
CON_TUNEL=0
# Arrancar la red con el arbol de estado COMPRIMIDO (hard fork, ~6x throughput).
# Solo aplica al CREAR una red nueva (modo "solo") - todos los nodos de una red
# deben usar el mismo valor (se pliega en el chain_id). Off por defecto.
COMPRIMIDO=0

decir()  { printf '\n==> %s\n' "$1"; }
error()  { printf '\nERROR: %s\n' "$1" >&2; exit 1; }
log()    { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$QCHAIN_HOME/install.log" 2>/dev/null || true; }

trap 'error "algo falló en la línea $LINENO del instalador - no se pisó ninguna clave ni configuración existente. Podés volver a correr el script: si ya tenías keypair.json/config.json, se reutilizan tal cual."' ERR

uso() {
  cat <<'EOF'
Uso: sudo ./install-node.sh [opciones]

Opciones:
  --modo solo|unirse     Elige el modo sin preguntar interactivamente.
                         "solo": crea tu propia red de prueba de un nodo.
                         "unirse": te unís a una red que ya existe.
  --config <archivo>     (con --modo unirse) copia este config.json en vez
                         de esperar a que lo pongas vos manualmente.
  --image <nombre>       Imagen Docker a usar (por defecto qchain:latest).
  --home <ruta>          Carpeta de instalación (por defecto /opt/qchain,
                         también configurable con la variable QCHAIN_HOME).
  --listen-port <puerto> Puerto P2P a usar en modo "solo" (por defecto 9000).
  --rpc-port <puerto>    Puerto RPC a usar en modo "solo" (por defecto 8080).
  --nombre <texto>       (modo "solo") nombre visible del validador, para que
                         las wallets lo muestren al elegir dónde hacer staking.
  --round-interval <ms>  (modo "solo") ms entre rondas de consenso (por defecto
                         500). Bajarlo (p.ej. 250) sube el techo de TPS en una
                         red multi-nodo. TODOS los nodos deben usar el mismo
                         valor. Ojo: la emisión de staking es por-ronda (retuneá
                         el APR por gobernanza si cambiás esto).
  --comprimido           (modo "solo") crear la red con el ÁRBOL COMPRIMIDO
                         (hard fork, ~6x throughput bajo carga, menos RAM/disco).
                         Solo al CREAR la red; todos los nodos deben usarlo. No se
                         puede convertir una cadena ya corriendo (cambia la raíz).
  --con-wallet           Instalar también la wallet web sin preguntar (con --yes
                         te genera y muestra una contraseña fuerte).
  --con-tunel            Instalar también el túnel de Cloudflare (HTTPS público)
                         sin preguntar. Implica --con-wallet (el túnel expone la
                         wallet). Deja un nodo público (validador + wallet +
                         HTTPS) en UN solo comando.
  --yes, -y              No pedir confirmaciones (para instalación automatizada).
  --no-build             No construir la imagen desde el código aunque falte;
                         solo intentar 'docker pull' / cargar un tar. Útil si
                         ya publicaste la imagen en un registro.
  --uninstall            Para y desinstala el servicio systemd. NO borra tu
                         clave, config.json, ni la carpeta data/.
  --help, -h             Muestra esta ayuda.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --modo) MODO="${2:-}"; shift 2 ;;
    --config) CONFIG_ORIGEN="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --listen-port) LISTEN_PORT_ARG="${2:-}"; shift 2 ;;
    --rpc-port) RPC_PORT_ARG="${2:-}"; shift 2 ;;
    --nombre) NOMBRE_VALIDADOR="${2:-}"; shift 2 ;;
    --round-interval) RONDA_MS="${2:-}"; shift 2 ;;
    --comprimido|--compressed) COMPRIMIDO=1; shift ;;
    --con-wallet) CON_WALLET=1; shift ;;
    --con-tunel) CON_TUNEL=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --help|-h) uso; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

# El túnel expone la wallet, así que pedirlo implica instalar la wallet.
[ "$CON_TUNEL" -eq 1 ] && CON_WALLET=1

if [ "$(id -u)" -ne 0 ]; then
  error "corre este script como root (sudo ./install-node.sh)"
fi

mkdir -p "$QCHAIN_HOME"
log "instalador iniciado (modo=$MODO, uninstall=$UNINSTALL, imagen=$IMAGE)"

# ---------------------------------------------------------------------------
# Desinstalación: para el servicio, no toca clave/config/datos
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  decir "Desinstalando el servicio de $QCHAIN_HOME"
  if [ "$ASUMIR_SI" -ne 1 ]; then
    read -rp "Esto para y desinstala el servicio systemd (tu clave, config.json y data/ NO se tocan). ¿Continuar? [s/N] " resp
    case "$resp" in s|S|si|Si|SI) ;; *) echo "Cancelado."; exit 0 ;; esac
  fi
  systemctl disable --now qchain-validator 2>/dev/null || true
  rm -f /etc/systemd/system/qchain-validator.service
  systemctl daemon-reload
  log "servicio desinstalado"
  echo "Servicio detenido y desinstalado. Tus archivos siguen en $QCHAIN_HOME."
  echo "Para volver a instalarlo: sudo ./install-node.sh"
  exit 0
fi

# ---------------------------------------------------------------------------
# Paso 0: Docker
# ---------------------------------------------------------------------------
decir "Verificando Docker"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker no esta instalado. Instalando..."
  # Usa el script oficial de Docker (get.docker.com), que detecta la
  # distribución solo (Debian, Ubuntu, Oracle Linux/RHEL, Fedora, etc.) y
  # configura el repositorio correcto para cada una. La versión anterior
  # asumía Debian a mano y fallaba en Ubuntu/otras distros (que es lo más
  # común en una VPS de la nube) al no existir ese repo para su release.
  # Nos aseguramos primero de tener curl/ca-certificates con el gestor de
  # paquetes que haya.
  if ! command -v curl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates
    elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates
    else error "no encontré curl ni un gestor de paquetes conocido (apt/dnf/yum) para instalarlo. Instalá Docker a mano y volvé a correr el script."
    fi
  fi
  if ! curl -fsSL https://get.docker.com | sh; then
    error "no se pudo instalar Docker automáticamente. Instalalo a mano (https://docs.docker.com/engine/install/) y volvé a correr este script - al detectar que Docker ya está, se saltea este paso."
  fi
  systemctl enable --now docker 2>/dev/null || true
else
  echo "Docker ya esta instalado."
fi

if ! docker info >/dev/null 2>&1; then
  error "Docker está instalado pero su servicio no está corriendo. Probá: sudo systemctl start docker"
fi

# Obtener la imagen. Como todavía no hay un registro público publicado, el
# camino real y autocontenido para alguien sin conocimientos técnicos es
# CONSTRUIRLA desde el código que este mismo repo trae: un solo comando, sin
# tener que conseguir un tar misterioso de ningún lado. Solo hace falta este
# repo en la máquina y Docker con acceso a internet (para bajar las
# dependencias de compilación la primera vez). Orden de preferencia:
#   - imagen custom pedida con --image  -> se intenta 'docker pull' primero
#     (asumimos que nombraste un registro a propósito)
#   - imagen por defecto (qchain:latest) -> se construye desde el Dockerfile
#   - fallbacks para ambos: pull, o cargar 'qchain-image.tar' del repo
obtener_imagen() {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then return 0; fi

  local es_custom=0
  [ "$IMAGE" != "qchain:latest" ] && es_custom=1

  # Imagen custom: intentar bajarla de su registro primero.
  if [ "$es_custom" -eq 1 ]; then
    echo "Intentando 'docker pull $IMAGE'..."
    if docker pull "$IMAGE" >/dev/null 2>&1; then return 0; fi
  fi

  # Construir desde el código (el camino normal hoy).
  if [ "$NO_BUILD" -ne 1 ] && [ -f "$REPO_ROOT/Dockerfile" ]; then
    decir "Construyendo la imagen de qchain desde el código"
    echo "Esto compila todo desde cero y puede tardar VARIOS MINUTOS la primera"
    echo "vez (después queda cacheado). Origen: $REPO_ROOT"
    if DOCKER_BUILDKIT=1 docker build -t qchain:latest "$REPO_ROOT"; then
      IMAGE="qchain:latest"
      return 0
    fi
    echo "La construcción falló (ver el detalle arriba)."
  fi

  # Fallbacks: registro por defecto, o un tar que alguien te pasó.
  if [ "$es_custom" -eq 0 ]; then
    echo "Intentando 'docker pull $IMAGE'..."
    if docker pull "$IMAGE" >/dev/null 2>&1; then return 0; fi
  fi
  if [ -f "$REPO_ROOT/qchain-image.tar" ]; then
    decir "Cargando la imagen desde $REPO_ROOT/qchain-image.tar"
    if docker load -i "$REPO_ROOT/qchain-image.tar"; then return 0; fi
  fi

  error "no pude construir ni obtener la imagen de qchain.
  - Si estás en el repo: instalá Docker con acceso a internet y volvé a correr
    (la construcción baja dependencias de compilación la primera vez).
  - Si te pasaron un archivo 'qchain-image.tar': ponelo junto a este repo
    (en $REPO_ROOT) y volvé a correr.
  Detalle en docs/DEPLOY.md."
}
obtener_imagen
if [ "$IMAGE" != "qchain:latest" ]; then
  docker tag "$IMAGE" qchain:latest
fi

decir "Verificando que la imagen tenga los binarios de qchain"
for bin in qchain qchain-node qchain-genesis-build; do
  if ! docker run --rm qchain:latest "$bin" --help >/dev/null 2>&1; then
    error "la imagen '$IMAGE' no responde a '$bin --help' - no parece ser una imagen válida de qchain. Revisá docs/DEPLOY.md."
  fi
done
echo "Imagen verificada correctamente."

qrun() { docker run --rm -v "$QCHAIN_HOME":/qchain -w /qchain qchain:latest "$@"; }

# ---------------------------------------------------------------------------
# Reinstalacion: si ya hay una instalacion, no la pisamos por accidente
# ---------------------------------------------------------------------------
SALTAR_CONFIGURACION=0
if [ -f "$QCHAIN_HOME/config.json" ] && [ -f "$QCHAIN_HOME/keypair.json" ]; then
  decir "Ya existe una instalacion en $QCHAIN_HOME"
  if [ "$ASUMIR_SI" -ne 1 ]; then
    echo "Esto reinstalaria el SERVICIO (systemd) pero no toca tu clave, tu"
    echo "config.json, ni la carpeta data/ (tu dinero y el estado de la red"
    echo "no se pierden)."
    read -rp "¿Continuar y (re)instalar el servicio con lo que ya hay? [s/N] " resp
    case "$resp" in
      s|S|si|Si|SI) ;;
      *) echo "Cancelado. No se cambio nada."; exit 0 ;;
    esac
  fi
  SALTAR_CONFIGURACION=1
fi

if [ "$SALTAR_CONFIGURACION" -eq 0 ]; then
  if [ -z "$MODO" ]; then
    decir "¿Que querés hacer?"
    echo "  1) Crear mi propia red de prueba (recomendado si es tu primera vez)"
    echo "     -> Un solo nodo, vos sos el unico validador, con una wallet"
    echo "        de prueba ya cargada de fondos para que puedas probar"
    echo "        transferencias de inmediato."
    echo "  2) Unirme a una red que ya existe (alguien te va a dar un"
    echo "     archivo config.json, o vos ya lo tenes)"
    while true; do
      read -rp "Elegi 1 o 2: " eleccion
      case "$eleccion" in
        1) MODO="solo"; break ;;
        2) MODO="unirse"; break ;;
        *) echo "No entendí, escribí 1 o 2." ;;
      esac
    done
  fi

  case "$MODO" in
    solo)
      LISTEN_ADDR="0.0.0.0:${LISTEN_PORT_ARG:-9000}"
      RPC_ADDR="0.0.0.0:${RPC_PORT_ARG:-8080}"
      STAKE="1000000000"

      if [ ! -f "$QCHAIN_HOME/keypair.json" ]; then
        decir "Generando tu clave de validador"
        qrun qchain keygen --out keypair.json
      else
        echo "Ya existe una clave de validador en $QCHAIN_HOME/keypair.json, se reutiliza."
      fi
      MI_DIRECCION="$(qrun qchain address --keypair keypair.json)"
      echo "Tu direccion de validador: $MI_DIRECCION"

      if [ ! -f "$QCHAIN_HOME/wallet.json" ]; then
        decir "Generando una wallet de prueba con fondos"
        qrun qchain keygen --out wallet.json
      else
        echo "Ya existe una wallet de prueba en $QCHAIN_HOME/wallet.json, se reutiliza."
      fi
      WALLET_DIRECCION="$(qrun qchain address --keypair wallet.json)"
      echo "Wallet de prueba: $WALLET_DIRECCION"

      BUNDLE_JSON="$(qrun qchain bundle --keypair keypair.json)"

      # Nombre (moniker) opcional del validador, para que las wallets lo
      # muestren en una lista al elegir dónde hacer staking, en vez de una
      # dirección cruda. Interactivo si no se pasó --nombre y no es --yes.
      if [ -z "${NOMBRE_VALIDADOR:-}" ] && [ "${ASUMIR_SI:-0}" -ne 1 ]; then
        read -rp "Nombre para tu validador (opcional, Enter para omitir): " NOMBRE_VALIDADOR || true
      fi

      mkdir -p "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out"
      if [ -n "${NOMBRE_VALIDADOR:-}" ]; then
        # Escapar comillas/backslashes para un JSON válido.
        NOMBRE_JSON="$(printf '%s' "$NOMBRE_VALIDADOR" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        cat > "$QCHAIN_HOME/manifests/validador1.json" <<EOF
{"pubkey_bundle": $BUNDLE_JSON, "listen_addr": "$LISTEN_ADDR", "rpc_addr": "$RPC_ADDR", "stake": $STAKE, "name": "$NOMBRE_JSON"}
EOF
      else
        cat > "$QCHAIN_HOME/manifests/validador1.json" <<EOF
{"pubkey_bundle": $BUNDLE_JSON, "listen_addr": "$LISTEN_ADDR", "rpc_addr": "$RPC_ADDR", "stake": $STAKE}
EOF
      fi
      cat > "$QCHAIN_HOME/genesis.json" <<EOF
[{"address": "$WALLET_DIRECCION", "balance": $FONDO_WALLET_PRUEBA}]
EOF

      decir "Armando la configuracion de la red (config.json)"
      GB_COMPRIMIDO=""
      if [ "$COMPRIMIDO" = "1" ]; then
        GB_COMPRIMIDO="--compressed-state-tree"
        decir "  -> arbol de estado COMPRIMIDO (hard fork, ~6x throughput bajo carga)"
      fi
      qrun qchain-genesis-build --manifests-dir manifests --genesis genesis.json --out-dir out --round-interval-ms "$RONDA_MS" $GB_COMPRIMIDO
      cp "$QCHAIN_HOME/out/node1.json" "$QCHAIN_HOME/config.json"
      rm -rf "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out" "$QCHAIN_HOME/genesis.json"
      mkdir -p "$QCHAIN_HOME/data"
      log "modo solo: red creada, validador $MI_DIRECCION, wallet de prueba $WALLET_DIRECCION"
      ;;
    unirse)
      if [ ! -f "$QCHAIN_HOME/keypair.json" ]; then
        decir "Generando tu clave de validador"
        qrun qchain keygen --out keypair.json
      else
        echo "Ya existe una clave en $QCHAIN_HOME/keypair.json, se reutiliza."
      fi
      MI_DIRECCION="$(qrun qchain address --keypair keypair.json)"
      BUNDLE_JSON="$(qrun qchain bundle --keypair keypair.json)"

      if [ -n "$CONFIG_ORIGEN" ]; then
        [ -f "$CONFIG_ORIGEN" ] || error "no encontré el archivo $CONFIG_ORIGEN"
        cp "$CONFIG_ORIGEN" "$QCHAIN_HOME/config.json"
      fi

      if [ ! -f "$QCHAIN_HOME/config.json" ]; then
        decir "Necesitas un archivo config.json de quien coordina la red"
        echo "Enviale a esa persona:"
        echo "  - tu direccion de IP publica"
        echo "  - este bundle (clave publica, no es secreta):"
        echo "$BUNDLE_JSON"
        echo
        echo "Cuando te devuelvan tu config.json, copialo a $QCHAIN_HOME/config.json"
        echo "(o volvé a correr: sudo ./install-node.sh --modo unirse --config <archivo>)"
        echo "y volve a correr este script."
        log "modo unirse: esperando config.json del coordinador (validador $MI_DIRECCION)"
        exit 0
      fi
      mkdir -p "$QCHAIN_HOME/data"
      log "modo unirse: config.json presente, validador $MI_DIRECCION"
      ;;
    *)
      error "modo inválido: '$MODO' (usá 'solo' o 'unirse')"
      ;;
  esac
fi

if command -v python3 >/dev/null 2>&1; then
  python3 -c "import json; json.load(open('$QCHAIN_HOME/config.json'))" >/dev/null 2>&1 \
    || error "$QCHAIN_HOME/config.json no es JSON válido - revisá cómo se generó/copió antes de continuar."
fi

chmod 600 "$QCHAIN_HOME/keypair.json" "$QCHAIN_HOME/config.json" 2>/dev/null || true
[ -f "$QCHAIN_HOME/wallet.json" ] && chmod 600 "$QCHAIN_HOME/wallet.json"

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
decir "Abriendo puertos"
LISTEN_PORT="$(grep -oP '"listen_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" | head -1 || true)"
RPC_PORT="$(grep -oP '"rpc_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" | head -1 || true)"
LISTEN_PORT="${LISTEN_PORT:-9000}"
RPC_PORT="${RPC_PORT:-8080}"
if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH || true
  ufw allow "${LISTEN_PORT}/tcp" comment 'qchain p2p' || true
  ufw allow "${RPC_PORT}/tcp" comment 'qchain rpc' || true
  ufw --force enable || true
else
  echo "ufw no esta disponible - si tu proveedor usa un firewall aparte (ej. grupo de seguridad de la nube), abri los puertos $LISTEN_PORT y $RPC_PORT manualmente."
fi

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-ntp true || true
fi

# ---------------------------------------------------------------------------
# Servicio systemd
# ---------------------------------------------------------------------------
decir "Instalando el servicio (arranca solo, y se reinicia solo si se cae)"
cp "$SCRIPT_DIR/systemd/qchain-validator.service" /etc/systemd/system/qchain-validator.service
sed -i "s#WorkingDirectory=/opt/qchain#WorkingDirectory=$QCHAIN_HOME#" /etc/systemd/system/qchain-validator.service
systemctl daemon-reload
systemctl enable --now qchain-validator

decir "Comprobando que el nodo arrancó bien"
NODO_OK=0
for _ in $(seq 1 10); do
  sleep 1
  if systemctl is-active --quiet qchain-validator; then NODO_OK=1; break; fi
done
if [ "$NODO_OK" -ne 1 ]; then
  echo "El servicio no llegó a quedar activo en 10 segundos. Mirá el detalle con:"
  echo "  journalctl -u qchain-validator -e --no-pager"
else
  echo "El servicio está activo."
fi

log "instalación finalizada, servicio activo=$NODO_OK"

decir "Listo"
IP_PUBLICA="$(curl -fsSL --max-time 3 https://ifconfig.me 2>/dev/null || echo '<tu-ip>')"
cat <<EOF

Tu nodo esta corriendo.

  Estado de la red (pagina web):  http://$IP_PUBLICA:$RPC_PORT/
  Ver que esta haciendo el nodo:  journalctl -u qchain-validator -f
  Parar el nodo:                  systemctl stop qchain-validator
  Volver a prenderlo:              systemctl start qchain-validator
  Desinstalar el servicio:        sudo ./install-node.sh --uninstall

Tus archivos importantes estan en $QCHAIN_HOME (permisos restringidos a root):
  keypair.json   -> tu clave de validador (NO la compartas ni la borres)
  config.json    -> la configuracion de la red
  data/          -> el estado de la cadena (balances, etc), sobrevive reinicios
  install.log    -> registro de esta instalación, útil para soporte
EOF
if [ -f "$QCHAIN_HOME/wallet.json" ]; then
cat <<EOF

Ademas te creamos una wallet de prueba ya con fondos:
  wallet.json    -> tu billetera de prueba (NO la compartas ni la borres)

Para probarla (reemplaza <direccion-destino> por cualquier direccion):
  docker run --rm -v $QCHAIN_HOME:/qchain -w /qchain qchain:latest \\
    qchain transfer --rpc http://127.0.0.1:$RPC_PORT --keypair wallet.json --to <direccion-destino> --amount 1000000
EOF
fi

echo
echo "Recordatorio de seguridad: el RPC ($RPC_PORT) no tiene autenticación -"
echo "cualquiera que llegue a él puede consultar balances y enviar transacciones"
echo "propias firmadas (no puede robar fondos ajenos, pero sí ver la actividad"
echo "y saturarlo). Esto sigue siendo un testnet - no pongas valor real detrás."

# ---------------------------------------------------------------------------
# Oferta: instalar también la wallet web (crear wallets y transferir desde el
# navegador, con botones en vez de la CLI). Es opcional y reutiliza la misma
# imagen que acabamos de preparar - por eso lo ofrecemos acá, ya con todo listo.
# ---------------------------------------------------------------------------
INSTALAR_WALLET="$CON_WALLET"
if [ "$INSTALAR_WALLET" -ne 1 ] && [ "$ASUMIR_SI" -ne 1 ]; then
  decir "¿Querés abrir también la wallet web?"
  echo "Es una página para crear wallets, ver balances y transferir desde el"
  echo "navegador (sin usar comandos). Queda protegida con una contraseña."
  read -rp "Instalar la wallet web ahora? [s/N] " resp
  case "$resp" in s|S|si|Si|SI) INSTALAR_WALLET=1 ;; esac
fi
if [ "$INSTALAR_WALLET" -eq 1 ]; then
  WALLET_ARGS=(--rpc-port "$RPC_PORT" --home "$QCHAIN_HOME")
  # Sin interacción (--yes): que la wallet genere y muestre una contraseña
  # fuerte, en vez de quedarse esperando que la tipeen.
  [ "$ASUMIR_SI" -eq 1 ] && WALLET_ARGS+=(--generar-password --yes)
  QCHAIN_HOME="$QCHAIN_HOME" "$SCRIPT_DIR/install-wallet.sh" "${WALLET_ARGS[@]}" \
    || echo "La wallet no se pudo instalar ahora, pero tu nodo sigue funcionando. Podés instalarla después con: sudo ./install-wallet.sh"
else
  echo
  echo "Tip: para manejar tus fondos desde el navegador (crear wallets y"
  echo "transferir con botones), instalá la wallet web cuando quieras:"
  echo "  sudo ./install-wallet.sh"
fi

# ---------------------------------------------------------------------------
# Oferta: exponer la wallet por HTTPS con un túnel de Cloudflare. Solo tiene
# sentido si la wallet quedó instalada (el túnel apunta al puerto de la wallet).
# Deja todo el despliegue de un nodo público en UN solo comando.
# ---------------------------------------------------------------------------
if [ "$INSTALAR_WALLET" -eq 1 ]; then
  INSTALAR_TUNEL="$CON_TUNEL"
  if [ "$INSTALAR_TUNEL" -ne 1 ] && [ "$ASUMIR_SI" -ne 1 ]; then
    decir "¿Querés abrir la wallet por HTTPS desde internet (túnel de Cloudflare)?"
    echo "Te da una URL https://...trycloudflare.com para entrar desde el celular,"
    echo "SIN abrir puertos en el firewall de la nube. (La URL cambia si el túnel"
    echo "reinicia; para una fija hace falta un dominio propio - ver install-tunnel.sh.)"
    read -rp "Instalar el túnel HTTPS ahora? [s/N] " resp
    case "$resp" in s|S|si|Si|SI) INSTALAR_TUNEL=1 ;; esac
  fi
  if [ "$INSTALAR_TUNEL" -eq 1 ]; then
    "$SCRIPT_DIR/install-tunnel.sh" \
      || echo "El túnel no se pudo instalar ahora, pero la wallet sigue funcionando en la red local. Podés instalarlo después con: sudo ./install-tunnel.sh"
  fi
elif [ "$CON_TUNEL" -eq 1 ]; then
  echo
  echo "Nota: pediste --con-tunel pero la wallet no se instaló (el túnel expone la"
  echo "wallet). Instalá la wallet y el túnel con: sudo ./install-wallet.sh && sudo ./install-tunnel.sh"
fi
