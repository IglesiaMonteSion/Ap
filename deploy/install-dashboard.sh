#!/usr/bin/env bash
# install-dashboard.sh — expone el DASHBOARD del validador (GET / del nodo) por
# HTTPS desde cualquier parte, PROTEGIDO POR CONTRASEÑA, usando un proxy Caddy
# (basic auth) + un túnel de Cloudflare propio.
#
# POR QUÉ el proxy con contraseña (y no exponer el puerto pelado): el dashboard
# vive en el MISMO puerto que el JSON-RPC del nodo (8080), y el RPC NO tiene
# autenticación. Exponer 8080 tal cual dejaría que cualquiera mande transacciones
# y sature el nodo. Este script pone un proxy Caddy adelante que EXIGE usuario +
# contraseña para CUALQUIER ruta (dashboard y RPC), así la contraseña es la
# puerta: sin ella no se llega ni al dashboard ni al RPC. Cloudflare pone el
# HTTPS (la contraseña nunca viaja en claro).
#
# Uso (en la VPS, como root):
#   sudo ./deploy/install-dashboard.sh --generar-password    # genera y muestra una clave
#   sudo ./deploy/install-dashboard.sh --password 'TuClave'  # usás tu propia clave
#   sudo ./deploy/install-dashboard.sh --url                 # imprimir la URL actual
#   sudo ./deploy/install-dashboard.sh --uninstall           # BAJARLO (cuando vayas a real)
#
# LÍMITE HONESTO: es un "quick tunnel" gratis; la URL (https://algo.trycloudflare.com)
# CAMBIA cada vez que el túnel reinicia. Para una URL fija hace falta un dominio
# propio. La basic auth va sobre HTTPS (seguro), pero si la clave se filtra, quien
# la tenga llega al RPC (puede consultar/mandar tx propias, NO robar fondos ajenos).
set -Eeuo pipefail

USER_NAME="admin"
PASSWORD=""
GENERAR_PASSWORD=0
DASH_PORT="8091"          # puerto local donde escucha el proxy Caddy
NODE_RPC_PORT="8080"      # puerto RPC del nodo (dashboard incluido) al que hace proxy
CADDY_IMAGE="caddy:2.8.4" # pin reproducible
CF_VERSION="${CF_VERSION:-2024.12.2}"
MODE="install"
ASUMIR_SI=0

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO. Revisá el mensaje de arriba."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --generar-password) GENERAR_PASSWORD=1; shift ;;
    --dashboard-port) DASH_PORT="${2:-}"; shift 2 ;;
    --node-rpc-port) NODE_RPC_PORT="${2:-}"; shift 2 ;;
    --cf-version) CF_VERSION="${2:-}"; shift 2 ;;
    --url) MODE="url"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,26p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo."

CADDY_SERVICE=/etc/systemd/system/qchain-dashboard.service
TUNNEL_SERVICE=/etc/systemd/system/qchain-dashboard-tunnel.service
CADDY_DIR=/opt/qchain-dashboard

# ---------------------------------------------------------------------------
# --url : imprimir la URL pública actual del dashboard
# ---------------------------------------------------------------------------
if [ "$MODE" = "url" ]; then
  URL="$(journalctl -u qchain-dashboard-tunnel --no-pager 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)"
  if [ -n "$URL" ]; then echo "URL actual del dashboard:  $URL"; else echo "Todavía no hay URL (¿arrancando?). Probá: journalctl -u qchain-dashboard-tunnel -e"; fi
  exit 0
fi

# ---------------------------------------------------------------------------
# --uninstall : bajar el dashboard público (para cuando vayas a real)
# ---------------------------------------------------------------------------
if [ "$MODE" = "uninstall" ]; then
  systemctl disable --now qchain-dashboard-tunnel 2>/dev/null || true
  systemctl disable --now qchain-dashboard 2>/dev/null || true
  docker rm -f qchain-dashboard 2>/dev/null || true
  rm -f "$TUNNEL_SERVICE" "$CADDY_SERVICE"
  rm -rf "$CADDY_DIR"
  systemctl daemon-reload
  echo "Dashboard público QUITADO. El nodo (RPC privado 127.0.0.1:$NODE_RPC_PORT) sigue intacto."
  echo "Ya NO se puede entrar al dashboard desde internet."
  exit 0
fi

command -v docker >/dev/null 2>&1 || error "Docker no está instalado."

# ---------------------------------------------------------------------------
# Resolver la contraseña
# ---------------------------------------------------------------------------
CLAVE_GENERADA=0
if [ "$GENERAR_PASSWORD" -eq 1 ] || { [ -z "$PASSWORD" ] && [ "$ASUMIR_SI" -eq 1 ]; }; then
  PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
  CLAVE_GENERADA=1
fi
if [ -z "$PASSWORD" ]; then
  read -rsp "Contraseña para ver el dashboard (Enter = generar una): " PASSWORD; echo
  if [ -z "$PASSWORD" ]; then
    PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"; CLAVE_GENERADA=1
  fi
fi
[ -n "$PASSWORD" ] || error "no se definió ninguna contraseña."

# ---------------------------------------------------------------------------
# Caddy: hash de la contraseña (bcrypt) + Caddyfile con basic auth + reverse proxy
# ---------------------------------------------------------------------------
echo "==> Preparando el proxy con contraseña (Caddy)"
docker image inspect "$CADDY_IMAGE" >/dev/null 2>&1 || docker pull "$CADDY_IMAGE" >/dev/null
HASH="$(docker run --rm "$CADDY_IMAGE" caddy hash-password --plaintext "$PASSWORD")"
[ -n "$HASH" ] || error "no pude generar el hash de la contraseña."

mkdir -p "$CADDY_DIR"
# El Caddyfile: basic auth para TODA ruta, luego proxy al nodo. El heredoc va
# CITADO ('EOF') para que bash no toque los '$' del hash bcrypt.
cat > "$CADDY_DIR/Caddyfile" <<EOF
:${DASH_PORT} {
	basic_auth {
		${USER_NAME} ${HASH}
	}
	reverse_proxy 127.0.0.1:${NODE_RPC_PORT}
}
EOF
chmod 600 "$CADDY_DIR/Caddyfile"

# Servicio del proxy (Caddy en un contenedor con red del host, para alcanzar el
# RPC local; NO abrimos su puerto en el firewall — sólo el túnel lo alcanza).
cat > "$CADDY_SERVICE" <<EOF
[Unit]
Description=qchain dashboard auth proxy (Caddy)
After=network-online.target qchain-validator.service
Wants=network-online.target

[Service]
ExecStartPre=-/usr/bin/docker rm -f qchain-dashboard
ExecStart=/usr/bin/docker run --rm --name qchain-dashboard --network host -v ${CADDY_DIR}/Caddyfile:/etc/caddy/Caddyfile:ro ${CADDY_IMAGE}
ExecStop=/usr/bin/docker rm -f qchain-dashboard
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# cloudflared (si falta) — mismo pin que install-tunnel.sh
# ---------------------------------------------------------------------------
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "==> Instalando cloudflared"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) CF_ARCH="amd64" ;;
    aarch64|arm64) CF_ARCH="arm64" ;;
    armv7l) CF_ARCH="arm" ;;
    *) error "arquitectura no soportada: $ARCH" ;;
  esac
  URL="https://github.com/cloudflare/cloudflared/releases/download/${CF_VERSION}/cloudflared-linux-${CF_ARCH}"
  TMP_CF="$(mktemp)"
  curl -fsSL "$URL" -o "$TMP_CF" || error "no pude descargar cloudflared."
  install -m 0755 "$TMP_CF" /usr/local/bin/cloudflared
  rm -f "$TMP_CF"
  /usr/local/bin/cloudflared --version >/dev/null 2>&1 || error "cloudflared descargado no ejecuta."
fi

# Túnel propio del dashboard (separado del de la wallet).
cat > "$TUNNEL_SERVICE" <<EOF
[Unit]
Description=qchain dashboard Cloudflare tunnel
After=network-online.target qchain-dashboard.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate --url http://localhost:${DASH_PORT}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "==> Arrancando el proxy + el túnel"
systemctl daemon-reload
systemctl enable --now qchain-dashboard
systemctl enable --now qchain-dashboard-tunnel

# Esperar la URL
echo "Esperando la URL pública de Cloudflare (hasta ~30s)..."
URL=""
for _ in $(seq 1 30); do
  sleep 1
  URL="$(journalctl -u qchain-dashboard-tunnel --no-pager 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)"
  [ -n "$URL" ] && break
done

echo
echo "==========================================================================="
echo "  Dashboard del validador, protegido por contraseña:"
echo
[ -n "$URL" ] && echo "      $URL/" || echo "      (URL todavía no visible — mirala con: sudo ./deploy/install-dashboard.sh --url)"
echo
echo "  Usuario:     $USER_NAME"
if [ "$CLAVE_GENERADA" -eq 1 ]; then
  echo "  Contraseña:  $PASSWORD    <-- GUARDALA (no se vuelve a mostrar)"
else
  echo "  Contraseña:  (la que definiste)"
fi
echo
echo "  Abrí esa URL en cualquier navegador: te pide usuario/contraseña y recién"
echo "  ahí ves el dashboard. El RPC queda igual de protegido detrás de la clave."
echo
echo "  Ver la URL luego:   sudo ./deploy/install-dashboard.sh --url"
echo "  BAJARLO (a real):   sudo ./deploy/install-dashboard.sh --uninstall"
echo "  La URL cambia si el túnel reinicia (quick tunnel; dominio propio = fija)."
echo "==========================================================================="
