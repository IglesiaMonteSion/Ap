#!/usr/bin/env bash
# install-tunnel.sh — expone la wallet por HTTPS usando un túnel de Cloudflare,
# SIN abrir ningún puerto en el firewall de la nube (Oracle, AWS, etc.).
#
# Por qué sirve cuando Let's Encrypt/Caddy falla: un túnel de Cloudflare hace
# una conexión SALIENTE desde tu VPS hacia Cloudflare (como cualquier navegador
# saliendo a internet), y Cloudflare te da una URL pública HTTPS que reenvía el
# tráfico por ESA conexión hasta tu wallet local. Nunca se abre un puerto de
# entrada, así que el firewall de la nube deja de importar. Cloudflare pone el
# certificado HTTPS (real, válido en el navegador).
#
# Uso (en la VPS, como root):
#   sudo ./deploy/install-tunnel.sh                 # túnel a la wallet (puerto 8090)
#   sudo ./deploy/install-tunnel.sh --wallet-port 8090
#   sudo ./deploy/install-tunnel.sh --url           # solo imprimir la URL actual
#   sudo ./deploy/install-tunnel.sh --uninstall     # quitar el túnel
#
# LÍMITE HONESTO: este es un "quick tunnel" gratis y sin cuenta. La URL
# (https://algo-al-azar.trycloudflare.com) es NUEVA cada vez que el túnel
# reinicia (reboot, crash, o restart manual). Para una URL FIJA que no cambie
# hace falta una cuenta gratis de Cloudflare + un dominio propio (túnel con
# nombre) — documentado al final. Para probar/usar la wallet desde el celular
# ya, el quick tunnel alcanza.
set -Eeuo pipefail

WALLET_PORT="8090"
MODE="install"

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO. Revisá el mensaje de arriba."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --wallet-port) WALLET_PORT="${2:-}"; shift 2 ;;
    --url) MODE="url"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,26p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo."

SERVICE=/etc/systemd/system/qchain-tunnel.service

# ---------------------------------------------------------------------------
# --url : imprimir la URL pública actual del túnel (de los logs)
# ---------------------------------------------------------------------------
if [ "$MODE" = "url" ]; then
  URL="$(journalctl -u qchain-tunnel --no-pager 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)"
  if [ -n "$URL" ]; then
    echo "URL actual de la wallet:  $URL"
  else
    echo "Todavía no hay URL (¿el túnel está arrancando?). Probá:  journalctl -u qchain-tunnel -e"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# --uninstall
# ---------------------------------------------------------------------------
if [ "$MODE" = "uninstall" ]; then
  systemctl disable --now qchain-tunnel 2>/dev/null || true
  rm -f "$SERVICE"
  systemctl daemon-reload
  echo "Túnel quitado. (No se tocó la wallet ni el nodo.)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Instalar cloudflared si falta (binario oficial, detecta arquitectura)
# ---------------------------------------------------------------------------
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "Instalando cloudflared..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) CF_ARCH="amd64" ;;
    aarch64|arm64) CF_ARCH="arm64" ;;   # Oracle free tier (Ampere A1) suele ser este
    armv7l) CF_ARCH="arm" ;;
    *) error "arquitectura no soportada: $ARCH" ;;
  esac
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
  echo "Descargando $URL"
  curl -fsSL "$URL" -o /usr/local/bin/cloudflared || error "no pude descargar cloudflared (¿salida a internet?)."
  chmod +x /usr/local/bin/cloudflared
fi
echo "cloudflared: $(cloudflared --version 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# Servicio systemd: un quick tunnel a la wallet local. Arranca solo, se
# reinicia solo. --no-autoupdate para que no cambie el binario por su cuenta.
# ---------------------------------------------------------------------------
echo "Instalando el túnel como servicio systemd..."
cat > "$SERVICE" <<EOF
[Unit]
Description=qchain wallet Cloudflare tunnel
After=network-online.target qchain-wallet.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate --url http://localhost:${WALLET_PORT}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now qchain-tunnel

# ---------------------------------------------------------------------------
# Esperar a que Cloudflare asigne la URL y mostrarla
# ---------------------------------------------------------------------------
echo "Esperando la URL pública de Cloudflare (hasta ~30s)..."
URL=""
for _ in $(seq 1 30); do
  sleep 1
  URL="$(journalctl -u qchain-tunnel --no-pager 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)"
  [ -n "$URL" ] && break
done

echo
echo "==========================================================================="
if [ -n "$URL" ]; then
  echo "  Túnel listo. Abrí la wallet (HTTPS, sin contraseña, clave en tu navegador):"
  echo
  echo "      $URL/"
  echo
  echo "  Esa es tu URL pública. Funciona desde cualquier navegador del mundo."
else
  echo "  El túnel arrancó pero todavía no veo la URL. Mirala con:"
  echo "      sudo ./deploy/install-tunnel.sh --url"
  echo "  o:  journalctl -u qchain-tunnel -e --no-pager | grep trycloudflare"
fi
echo
echo "  Ver la URL en cualquier momento:   sudo ./deploy/install-tunnel.sh --url"
echo "  IMPORTANTE: la URL cambia si el túnel reinicia (reboot/crash). Para una"
echo "  URL FIJA necesitás una cuenta gratis de Cloudflare + un dominio (túnel"
echo "  con nombre) - ver docs/DEPLOY.md."
echo "==========================================================================="
