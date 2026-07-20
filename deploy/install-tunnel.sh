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
#   sudo ./deploy/install-tunnel.sh                 # QUICK tunnel a la wallet (URL random, cambia al reiniciar)
#   sudo ./deploy/install-tunnel.sh --wallet-port 8090
#   sudo ./deploy/install-tunnel.sh --url           # solo imprimir la URL actual (quick tunnel)
#   sudo ./deploy/install-tunnel.sh --uninstall     # quitar el túnel
#
#   # TÚNEL NOMBRADO (URL FIJA con TU dominio — recomendado cuando tengas el dominio):
#   #   1) Comprá un dominio (ej. qchain.com) y agregalo a una cuenta gratis de Cloudflare.
#   #   2) En la VPS, una vez:  cloudflared tunnel login   (abre un navegador, autoriza tu dominio)
#   #   3) Después:
#   sudo ./deploy/install-tunnel.sh --hostname wallet.qchain.com
#   sudo ./deploy/install-tunnel.sh --hostname wallet.qchain.com --qscan-hostname scan.qchain.com --qscan-port 8091
#
# LÍMITE HONESTO: sin --hostname es un "quick tunnel" gratis y sin cuenta — la URL
# (https://algo-al-azar.trycloudflare.com) es NUEVA cada vez que el túnel reinicia.
# Para una URL FIJA (necesaria para el allowlist de origen del futuro puente
# wallet-connect) usá --hostname con tu dominio propio (túnel con nombre). El
# subdominio va ANTES del dominio: wallet.qchain.com ✓, NUNCA qchain.wallet.com.
set -Eeuo pipefail

WALLET_PORT="8090"
MODE="install"
HOSTNAME_FQDN=""              # túnel nombrado si se setea (ej. wallet.qchain.com)
QSCAN_HOSTNAME=""             # opcional: exponer QScan en su propio subdominio
QSCAN_PORT="8091"
TUNNEL_NAME="qchain"          # nombre del túnel nombrado en tu cuenta Cloudflare
# Versión de cloudflared a instalar (pin reproducible; ver el bloque de descarga
# más abajo). `latest` = la última (tag mutable). Overridable por env o flag.
CF_VERSION="${CF_VERSION:-2024.12.2}"
CF_SHA256="${CF_SHA256:-}"

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO. Revisá el mensaje de arriba."' ERR

# Exige que un flag que lleva valor realmente lo tenga (y no sea otro flag ni
# esté vacío). Así un comando cortado (ej. `--qscan-hostname` sin nada detrás)
# da un mensaje claro en vez de un error críptico de `shift`.
need_val() {
  case "${2-}" in
    ""|--*) error "el flag $1 necesita un valor. Ej: $1 <valor>" ;;
  esac
}
while [ $# -gt 0 ]; do
  case "$1" in
    --wallet-port) need_val "$1" "${2-}"; WALLET_PORT="$2"; shift 2 ;;
    --hostname) need_val "$1" "${2-}"; HOSTNAME_FQDN="$2"; shift 2 ;;
    --qscan-hostname) need_val "$1" "${2-}"; QSCAN_HOSTNAME="$2"; shift 2 ;;
    --qscan-port) need_val "$1" "${2-}"; QSCAN_PORT="$2"; shift 2 ;;
    --tunnel-name) need_val "$1" "${2-}"; TUNNEL_NAME="$2"; shift 2 ;;
    --cf-version) need_val "$1" "${2-}"; CF_VERSION="$2"; shift 2 ;;
    --cf-sha256) need_val "$1" "${2-}"; CF_SHA256="$2"; shift 2 ;;
    --url) MODE="url"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,33p'; exit 0 ;;
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
  rm -f "$SERVICE" /etc/cloudflared/qchain.yml
  systemctl daemon-reload
  echo "Túnel quitado. (No se tocó la wallet ni el nodo, ni tu login/túnel de Cloudflare.)"
  echo "  (El túnel nombrado sigue existiendo en tu cuenta Cloudflare; borralo con:"
  echo "   cloudflared tunnel delete $TUNNEL_NAME — si querés eliminarlo del todo.)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Instalar cloudflared si falta (binario oficial, detecta arquitectura).
#
# PIN DE VERSIÓN (endurecimiento): descargamos una versión FIJA
# (CF_VERSION), no el tag mutable `latest`, así el binario es reproducible y no
# cambia bajo tus pies entre instalaciones. Overridable con --cf-version <tag>
# o CF_VERSION=... (o `latest` explícito si querés la última).
#
# VERIFICACIÓN DE INTEGRIDAD: tras descargar, SIEMPRE imprimimos y guardamos el
# SHA-256 del binario (en /usr/local/bin/cloudflared.sha256), para que tengas un
# registro y puedas compararlo entre máquinas o contra el checksum publicado por
# Cloudflare. Si pasás --cf-sha256 <hex> (o CF_SHA256=...), se EXIGE que coincida
# y se aborta si no. No hardcodeamos un hash porque cambia con cada versión —
# obtenelo de la página de releases de Cloudflare y pasalo si querés el gate.
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
  if [ "$CF_VERSION" = "latest" ]; then
    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
    echo "AVISO: usando el tag mutable 'latest' (no fijo). Para reproducibilidad pasá --cf-version <tag>."
  else
    URL="https://github.com/cloudflare/cloudflared/releases/download/${CF_VERSION}/cloudflared-linux-${CF_ARCH}"
  fi
  echo "Descargando $URL"
  TMP_CF="$(mktemp)"
  curl -fsSL "$URL" -o "$TMP_CF" || error "no pude descargar cloudflared (¿salida a internet? ¿existe la versión '$CF_VERSION'?)."
  # Verificación de integridad
  GOT_SHA="$(sha256sum "$TMP_CF" 2>/dev/null | cut -d' ' -f1 || true)"
  if [ -n "$CF_SHA256" ]; then
    [ "$GOT_SHA" = "$CF_SHA256" ] || { rm -f "$TMP_CF"; error "checksum de cloudflared NO coincide. esperado=$CF_SHA256 obtenido=$GOT_SHA — descarga abortada."; }
    echo "checksum verificado OK ($GOT_SHA)."
  else
    echo "SHA-256 del binario descargado: $GOT_SHA"
    echo "  (para exigirlo la próxima vez: --cf-sha256 $GOT_SHA)"
  fi
  install -m 0755 "$TMP_CF" /usr/local/bin/cloudflared
  rm -f "$TMP_CF"
  printf '%s  cloudflared-linux-%s (%s)\n' "$GOT_SHA" "$CF_ARCH" "$CF_VERSION" > /usr/local/bin/cloudflared.sha256
  # sanity: el binario corre y es la arquitectura correcta
  /usr/local/bin/cloudflared --version >/dev/null 2>&1 || error "el cloudflared descargado no ejecuta (¿arquitectura equivocada o descarga corrupta?)."
fi
echo "cloudflared: $(cloudflared --version 2>&1 | head -1)"

# ===========================================================================
# TÚNEL NOMBRADO (URL FIJA con tu dominio) — cuando se pasa --hostname.
# Requiere: dominio propio en una cuenta Cloudflare + `cloudflared tunnel login`
# corrido una vez en esta VPS (crea /root/.cloudflared/cert.pem).
# ===========================================================================
if [ -n "$HOSTNAME_FQDN" ]; then
  # Sanidad del hostname: debe tener al menos un punto (subdominio.dominio.tld).
  case "$HOSTNAME_FQDN" in
    *.*.*|*.*) : ;;
    *) error "--hostname debe ser un FQDN tipo wallet.tudominio.com (recibí: '$HOSTNAME_FQDN')" ;;
  esac
  CF_DIR="/root/.cloudflared"
  if [ ! -f "$CF_DIR/cert.pem" ]; then
    echo "==========================================================================="
    echo "  Primero autorizá tu dominio en Cloudflare (una sola vez, abre un navegador):"
    echo
    echo "      cloudflared tunnel login"
    echo
    echo "  Elegí tu dominio (ej. qchain.com) en la página que se abre. Eso crea"
    echo "  $CF_DIR/cert.pem. Después re-corré este comando."
    echo "==========================================================================="
    exit 1
  fi
  # Crear el túnel si no existe (idempotente); obtener su UUID.
  TUNNEL_ID="$(cloudflared tunnel list 2>/dev/null | awk -v n="$TUNNEL_NAME" '$2==n{print $1}' | head -1 || true)"
  if [ -z "$TUNNEL_ID" ]; then
    echo "Creando el túnel nombrado '$TUNNEL_NAME'..."
    cloudflared tunnel create "$TUNNEL_NAME" >/dev/null || error "no pude crear el túnel '$TUNNEL_NAME'."
    TUNNEL_ID="$(cloudflared tunnel list 2>/dev/null | awk -v n="$TUNNEL_NAME" '$2==n{print $1}' | head -1 || true)"
  fi
  [ -n "$TUNNEL_ID" ] || error "no pude obtener el UUID del túnel '$TUNNEL_NAME'."
  CRED="$CF_DIR/${TUNNEL_ID}.json"
  [ -f "$CRED" ] || error "no encuentro el archivo de credenciales del túnel ($CRED). Recreá con: cloudflared tunnel create $TUNNEL_NAME"
  echo "Túnel '$TUNNEL_NAME' = $TUNNEL_ID"

  # Config de ingress: cada hostname → su servicio local; el resto → 404.
  mkdir -p /etc/cloudflared
  {
    echo "tunnel: $TUNNEL_ID"
    echo "credentials-file: $CRED"
    echo "ingress:"
    echo "  - hostname: $HOSTNAME_FQDN"
    echo "    service: http://localhost:${WALLET_PORT}"
    if [ -n "$QSCAN_HOSTNAME" ]; then
      echo "  - hostname: $QSCAN_HOSTNAME"
      echo "    service: http://localhost:${QSCAN_PORT}"
    fi
    echo "  - service: http_status:404"
  } > /etc/cloudflared/qchain.yml
  echo "-> /etc/cloudflared/qchain.yml escrito"

  # Ruta DNS (crea el registro CNAME del subdominio hacia el túnel). Idempotente:
  # si ya existe, cloudflared avisa y seguimos.
  cloudflared tunnel route dns "$TUNNEL_NAME" "$HOSTNAME_FQDN" 2>/dev/null || echo "  (la ruta DNS de $HOSTNAME_FQDN ya existía o se ajustará)"
  if [ -n "$QSCAN_HOSTNAME" ]; then
    cloudflared tunnel route dns "$TUNNEL_NAME" "$QSCAN_HOSTNAME" 2>/dev/null || echo "  (la ruta DNS de $QSCAN_HOSTNAME ya existía)"
  fi

  # Servicio systemd corriendo el túnel nombrado por config.
  cat > "$SERVICE" <<EOF
[Unit]
Description=qchain named Cloudflare tunnel ($TUNNEL_NAME)
After=network-online.target qchain-wallet.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate --config /etc/cloudflared/qchain.yml run
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now qchain-tunnel
  echo
  echo "==========================================================================="
  echo "  Túnel NOMBRADO listo — URL FIJA (no cambia al reiniciar):"
  echo
  echo "      https://$HOSTNAME_FQDN/          (wallet)"
  [ -n "$QSCAN_HOSTNAME" ] && echo "      https://$QSCAN_HOSTNAME/          (QScan)"
  echo
  echo "  El DNS puede tardar 1-2 min la primera vez. Cloudflare pone el HTTPS."
  echo "  Esta URL fija es la que va en el allowlist de origen del puente wallet-connect."
  echo "==========================================================================="
  exit 0
fi

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
