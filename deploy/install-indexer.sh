#!/usr/bin/env bash
# Instalador del explorador QScan (qchain-indexer) - un solo comando deja el
# explorador de bloques corriendo como servicio systemd, siguiendo al nodo
# local por RPC y sirviendo el sitio web tipo Etherscan.
#
# El explorador es de SOLO LECTURA: no toca claves ni el consenso, así que
# exponerlo en público es seguro (a diferencia del RPC o la wallet).
#
# Uso interactivo:
#   sudo ./install-indexer.sh
#
# Uso no interactivo:
#   sudo ./install-indexer.sh --yes
#   sudo ./install-indexer.sh --rpc-port 8080 --port 9200 --yes
#
# Bajar el explorador (no borra el índice):
#   sudo ./install-indexer.sh --uninstall
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="qchain:latest"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
RPC_PORT="8080"
EXPLORER_PORT="9200"
POLL_MS="1000"
ASUMIR_SI=0
UNINSTALL=0
NO_BUILD=0

decir()  { printf '\n==> %s\n' "$1"; }
error()  { printf '\nERROR: %s\n' "$1" >&2; exit 1; }
trap 'error "algo falló en la línea $LINENO del instalador del explorador - no se borró ningún índice existente. Podés volver a correrlo."' ERR

uso() {
  cat <<'EOF'
Uso: sudo ./install-indexer.sh [opciones]

Opciones:
  --port <puerto>        Puerto del explorador web QScan (por defecto 9200).
  --rpc-port <puerto>    Puerto RPC del nodo al que seguir (por defecto 8080).
  --poll-ms <ms>         Intervalo de sondeo del nodo (por defecto 1000).
  --image <nombre>       Imagen Docker a usar (por defecto qchain:latest).
  --home <ruta>          Carpeta de qchain (por defecto /opt/qchain).
  --no-build             No construir la imagen desde el código aunque falte.
  --yes, -y              No pedir confirmaciones.
  --uninstall            Para y desinstala el explorador. NO borra el índice.
  --help, -h             Muestra esta ayuda.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port) EXPLORER_PORT="${2:-}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:-}"; shift 2 ;;
    --poll-ms) POLL_MS="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --help|-h) uso; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré con sudo: sudo ./install-indexer.sh"

if [ "$UNINSTALL" = "1" ]; then
  decir "Desinstalando el explorador QScan (el índice en $QCHAIN_HOME/qscan-data NO se borra)"
  systemctl stop qchain-indexer 2>/dev/null || true
  systemctl disable qchain-indexer 2>/dev/null || true
  rm -f /etc/systemd/system/qchain-indexer.service
  systemctl daemon-reload || true
  decir "Listo. El explorador quedó desinstalado."
  exit 0
fi

command -v docker >/dev/null 2>&1 || error "Docker no está instalado. Corré primero el instalador del nodo (install-node.sh), que instala Docker."
docker info >/dev/null 2>&1 || error "el daemon de Docker no está corriendo (probá: systemctl start docker)."

mkdir -p "$QCHAIN_HOME/qscan-data"

# Conseguir la imagen: si falta y es la imagen por defecto, construirla del repo.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if [ "$IMAGE" = "qchain:latest" ] && [ "$NO_BUILD" != "1" ]; then
    decir "Construyendo la imagen $IMAGE desde el código del repo (una sola vez)"
    docker build -t "$IMAGE" "$REPO_ROOT"
  else
    error "la imagen $IMAGE no está disponible (y --no-build está puesto o es una imagen custom)."
  fi
fi

# Verificar que la imagen trae el binario del explorador.
docker run --rm "$IMAGE" qchain-indexer --help >/dev/null 2>&1 \
  || error "la imagen $IMAGE no trae qchain-indexer (¿imagen vieja? reconstruí con --no-build quitado)."

decir "Instalando el servicio systemd del explorador (nodo RPC :$RPC_PORT -> explorador :$EXPLORER_PORT)"
install -m 644 "$SCRIPT_DIR/systemd/qchain-indexer.service" /etc/systemd/system/qchain-indexer.service
sed -i "s#--node http://127.0.0.1:8080#--node http://127.0.0.1:$RPC_PORT#" /etc/systemd/system/qchain-indexer.service
sed -i "s#--bind 0.0.0.0:9200#--bind 0.0.0.0:$EXPLORER_PORT#" /etc/systemd/system/qchain-indexer.service
sed -i "s#--poll-ms 1000#--poll-ms $POLL_MS#" /etc/systemd/system/qchain-indexer.service

# Abrir el puerto del explorador si ufw está activo.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$EXPLORER_PORT"/tcp >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable qchain-indexer >/dev/null 2>&1 || true
systemctl restart qchain-indexer

sleep 3
if systemctl is-active --quiet qchain-indexer; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  decir "Explorador QScan activo."
  printf '   URL local:   http://127.0.0.1:%s\n' "$EXPLORER_PORT"
  [ -n "$IP" ] && printf '   URL pública: http://%s:%s  (recordá abrir el puerto en el firewall de la nube)\n' "$IP" "$EXPLORER_PORT"
  printf '   Sigue al nodo en RPC :%s. Es de solo lectura, seguro de exponer.\n' "$RPC_PORT"
else
  error "el servicio del explorador no quedó activo. Mirá: journalctl -u qchain-indexer -n 50"
fi
