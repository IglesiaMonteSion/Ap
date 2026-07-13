#!/usr/bin/env bash
# Instalador de la wallet web de qchain - pensado para alguien SIN
# conocimientos tecnicos. Un solo comando deja la wallet web funcionando,
# protegida con contraseña, abierta al navegador y arrancando sola si la
# maquina se reinicia. Reemplaza el "docker run" largo a mano (donde la
# contraseña se prestaba a confusion) por una sola pregunta.
#
# Uso interactivo (recomendado):
#   sudo ./install-wallet.sh
#     -> te pregunta la contraseña (o te genera una fuerte), abre el puerto,
#        instala el servicio y te muestra la URL + como entrar.
#
# Uso no interactivo:
#   sudo ./install-wallet.sh --password 'TuClaveFuerte' --yes
#   sudo ./install-wallet.sh --generar-password --yes   # te genera una y la muestra
#
# Cambiar la contraseña despues:
#   sudo ./install-wallet.sh --password 'NuevaClave' --yes
#
# Bajar la wallet (no borra tus wallets):
#   sudo ./install-wallet.sh --uninstall
#
# Ver todas las opciones: sudo ./install-wallet.sh --help
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="qchain:latest"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
PASSWORD=""
GENERAR_PASSWORD=0
ASUMIR_SI=0
UNINSTALL=0
NO_BUILD=0
RPC_PORT="8080"
WALLET_PORT="8090"

decir()  { printf '\n==> %s\n' "$1"; }
error()  { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

trap 'error "algo falló en la línea $LINENO del instalador de la wallet - no se borró ninguna wallet ni contraseña existente. Podés volver a correrlo."' ERR

uso() {
  cat <<'EOF'
Uso: sudo ./install-wallet.sh [opciones]

Opciones:
  --password <clave>     La contraseña para entrar a la wallet. Si no la pasás
                         (y no usás --generar-password), el script te la pregunta.
  --generar-password     Genera una contraseña fuerte al azar y te la muestra.
  --port <puerto>        Puerto de la wallet web (por defecto 8090).
  --rpc-port <puerto>    Puerto RPC del nodo al que hablarle (por defecto 8080).
  --image <nombre>       Imagen Docker a usar (por defecto qchain:latest).
  --home <ruta>          Carpeta de qchain (por defecto /opt/qchain).
  --no-build             No construir la imagen desde el código aunque falte.
  --yes, -y              No pedir confirmaciones (para instalación automatizada).
  --uninstall            Para y desinstala la wallet. NO borra tus wallets.
  --help, -h             Muestra esta ayuda.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --generar-password) GENERAR_PASSWORD=1; shift ;;
    --port) WALLET_PORT="${2:-}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --help|-h) uso; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./install-wallet.sh)"
mkdir -p "$QCHAIN_HOME"

# ---------------------------------------------------------------------------
# Desinstalación: para el servicio, no toca las wallets ni la contraseña
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  decir "Desinstalando la wallet web"
  if [ "$ASUMIR_SI" -ne 1 ]; then
    read -rp "Esto para y desinstala el servicio de la wallet (tus wallets en $QCHAIN_HOME/wallets NO se tocan). ¿Continuar? [s/N] " resp
    case "$resp" in s|S|si|Si|SI) ;; *) echo "Cancelado."; exit 0 ;; esac
  fi
  systemctl disable --now qchain-wallet 2>/dev/null || true
  rm -f /etc/systemd/system/qchain-wallet.service
  systemctl daemon-reload
  echo "Wallet detenida y desinstalada. Tus wallets siguen en $QCHAIN_HOME/wallets."
  echo "Para volver a instalarla: sudo ./install-wallet.sh"
  exit 0
fi

# ---------------------------------------------------------------------------
# Docker + imagen (mismo criterio que install-node.sh: construir desde el
# código si hace falta, para que sea autocontenido)
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || error "Docker no está instalado. Corré primero deploy/install-node.sh (instala Docker) o instalalo a mano."
docker info >/dev/null 2>&1 || error "Docker está instalado pero su servicio no corre. Probá: sudo systemctl start docker"

obtener_imagen() {
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then return 0; fi
  local es_custom=0
  [ "$IMAGE" != "qchain:latest" ] && es_custom=1
  if [ "$es_custom" -eq 1 ]; then
    echo "Intentando 'docker pull $IMAGE'..."
    if docker pull "$IMAGE" >/dev/null 2>&1; then return 0; fi
  fi
  if [ "$NO_BUILD" -ne 1 ] && [ -f "$REPO_ROOT/Dockerfile" ]; then
    decir "Construyendo la imagen de qchain desde el código (puede tardar varios minutos la primera vez)"
    if docker build -t qchain:latest "$REPO_ROOT"; then IMAGE="qchain:latest"; return 0; fi
  fi
  if [ "$es_custom" -eq 0 ]; then
    if docker pull "$IMAGE" >/dev/null 2>&1; then return 0; fi
  fi
  if [ -f "$REPO_ROOT/qchain-image.tar" ]; then
    if docker load -i "$REPO_ROOT/qchain-image.tar"; then return 0; fi
  fi
  error "no pude construir ni obtener la imagen de qchain. Corré deploy/install-node.sh primero, o revisá docs/DEPLOY.md."
}
decir "Preparando la imagen de qchain"
obtener_imagen
[ "$IMAGE" != "qchain:latest" ] && docker tag "$IMAGE" qchain:latest
docker run --rm qchain:latest qchain-wallet --help >/dev/null 2>&1 \
  || error "la imagen no tiene el binario qchain-wallet - reconstruila (deploy/install-node.sh) o revisá docs/DEPLOY.md."

# ---------------------------------------------------------------------------
# Contraseña
# ---------------------------------------------------------------------------
generar_clave() {
  # base64 de 18 bytes al azar (~24 caracteres). /dev/urandom siempre está.
  head -c 18 /dev/urandom | base64 | tr -d '\n/+=' | cut -c1-24
}

CLAVE_GENERADA=0
if [ "$GENERAR_PASSWORD" -eq 1 ]; then
  PASSWORD="$(generar_clave)"; CLAVE_GENERADA=1
fi

if [ -z "$PASSWORD" ]; then
  if [ "$ASUMIR_SI" -eq 1 ]; then
    # No interactivo y sin clave dada: generamos una para no exponer sin protección.
    PASSWORD="$(generar_clave)"; CLAVE_GENERADA=1
  else
    decir "Contraseña de la wallet"
    echo "La wallet guarda claves privadas y va a estar abierta a internet,"
    echo "así que necesita una contraseña. Podés:"
    echo "  - escribir la tuya (que no sea obvia), o"
    echo "  - dejarla vacía y apretar Enter para que te genere una fuerte."
    read -rsp "Contraseña (Enter = generar una): " PASSWORD; echo
    if [ -z "$PASSWORD" ]; then
      PASSWORD="$(generar_clave)"; CLAVE_GENERADA=1
    else
      read -rsp "Repetí la contraseña: " PASSWORD2; echo
      [ "$PASSWORD" = "$PASSWORD2" ] || error "las contraseñas no coinciden - volvé a correr el script."
    fi
  fi
fi
[ -n "$PASSWORD" ] || error "no se definió ninguna contraseña."

# Guardarla en un archivo de entorno root-only (no queda en el comando ni en
# `docker inspect`). systemd la carga desde acá y la pasa por nombre.
umask 077
printf 'QCHAIN_WALLET_PASSWORD=%s\n' "$PASSWORD" > "$QCHAIN_HOME/wallet.env"
chmod 600 "$QCHAIN_HOME/wallet.env"
mkdir -p "$QCHAIN_HOME/wallets"

# Si el nodo se instaló en modo "solo", install-node.sh dejó una wallet de
# prueba YA CON FONDOS del génesis en $QCHAIN_HOME/wallet.json. La copiamos a
# la carpeta de la wallet web (como "banco") si todavía no está, para que
# aparezca en el navegador con saldo y puedas repartir monedas de prueba a las
# wallets que crees, sin usar la CLI. Solo copia si existe y no está ya.
if [ -f "$QCHAIN_HOME/wallet.json" ] && [ ! -f "$QCHAIN_HOME/wallets/banco.json" ]; then
  cp "$QCHAIN_HOME/wallet.json" "$QCHAIN_HOME/wallets/banco.json"
  chmod 600 "$QCHAIN_HOME/wallets/banco.json"
  echo "Encontré tu wallet de prueba con fondos - la vas a ver en el navegador como 'banco'."
fi

# ---------------------------------------------------------------------------
# Firewall del SO (el firewall de la nube -Security List de OCI, etc.- se abre
# aparte en la consola del proveedor; se lo recordamos al final)
# ---------------------------------------------------------------------------
decir "Abriendo el puerto $WALLET_PORT en el firewall del sistema"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${WALLET_PORT}/tcp" comment 'qchain wallet' || true
elif command -v iptables >/dev/null 2>&1; then
  # Insertar solo si no está ya (idempotente).
  if ! iptables -C INPUT -p tcp --dport "$WALLET_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp --dport "$WALLET_PORT" -j ACCEPT || true
  fi
  # Persistir si el paquete está disponible, para que sobreviva un reinicio.
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
fi

# ---------------------------------------------------------------------------
# Servicio systemd
# ---------------------------------------------------------------------------
decir "Instalando la wallet como servicio (arranca sola, se reinicia sola)"
cp "$SCRIPT_DIR/systemd/qchain-wallet.service" /etc/systemd/system/qchain-wallet.service
sed -i "s#WorkingDirectory=/opt/qchain#WorkingDirectory=$QCHAIN_HOME#" /etc/systemd/system/qchain-wallet.service
sed -i "s#EnvironmentFile=/opt/qchain/wallet.env#EnvironmentFile=$QCHAIN_HOME/wallet.env#" /etc/systemd/system/qchain-wallet.service
sed -i "s#-v /opt/qchain/wallets:/wallets#-v $QCHAIN_HOME/wallets:/wallets#" /etc/systemd/system/qchain-wallet.service
sed -i "s#--rpc http://127.0.0.1:8080#--rpc http://127.0.0.1:$RPC_PORT#" /etc/systemd/system/qchain-wallet.service
sed -i "s#--port 8090#--port $WALLET_PORT#" /etc/systemd/system/qchain-wallet.service
systemctl daemon-reload
systemctl enable --now qchain-wallet

decir "Comprobando que la wallet arrancó bien"
WALLET_OK=0
for _ in $(seq 1 12); do
  sleep 1
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$WALLET_PORT/"; then WALLET_OK=1; break; fi
done
if [ "$WALLET_OK" -ne 1 ]; then
  echo "La wallet no respondió local en 12 segundos. Mirá el detalle con:"
  echo "  journalctl -u qchain-wallet -e --no-pager"
fi

# ---------------------------------------------------------------------------
# Resumen final
# ---------------------------------------------------------------------------
IP_PUBLICA="$(curl -fsSL --max-time 3 https://ifconfig.me 2>/dev/null || echo '<tu-ip>')"
decir "Listo"
cat <<EOF

Tu wallet web esta corriendo.

  Abrila en:    http://$IP_PUBLICA:$WALLET_PORT/
  Usuario:      cualquiera (no se valida - poné 'admin' o lo que quieras)
  Contraseña:   $( [ "$CLAVE_GENERADA" -eq 1 ] && echo "$PASSWORD  <-- ANOTALA, es la que se generó" || echo "la que elegiste" )

Adentro podés crear wallets, ver balances y transferir, todo con botones.

Comandos utiles:
  Ver que hace la wallet:   journalctl -u qchain-wallet -f
  Cambiar la contraseña:    sudo ./install-wallet.sh --password 'NuevaClave' --yes
  Parar / arrancar:         systemctl stop|start qchain-wallet
  Desinstalar:              sudo ./install-wallet.sh --uninstall

EOF

if [ "$IP_PUBLICA" != "<tu-ip>" ]; then
cat <<EOF
IMPORTANTE - firewall de la nube:
  Abriste el puerto $WALLET_PORT en el firewall del sistema, pero si tu
  proveedor tiene un firewall aparte (ej. Security List de Oracle Cloud, o
  Security Group de AWS), tenés que abrir el puerto $WALLET_PORT/TCP ahí
  tambien desde su consola web, o no vas a poder entrar desde el navegador.

EOF
fi

cat <<EOF
Seguridad honesta: sobre HTTP la contraseña viaja sin cifrar (solo en base64).
Para un testnet sin valor real alcanza; para valor real, poné un proxy con
HTTPS/TLS delante. Y recordá: quien tenga esta contraseña puede gastar TODAS
las wallets que esta interfaz maneja - tratala como la llave de tu dinero.
EOF
