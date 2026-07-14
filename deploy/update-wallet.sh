#!/usr/bin/env bash
# Actualiza SOLO la wallet web a la última versión del código, sin tocar el
# nodo. Pensado para el caso frecuente de cambios de interfaz (HTML/CSS/JS de
# la wallet): reconstruye la imagen `qchain:latest` (rápido — con las cache
# mounts del Dockerfile solo recompila el crate que cambió) y reinicia el
# servicio `qchain-wallet`. El validador sigue corriendo sin interrupción.
#
# Uso (desde el repo, en la VPS):
#   git pull
#   sudo ./deploy/update-wallet.sh
#
# ¿Cuándo esto y cuándo update-node.sh?
#   - Cambió la wallet (interfaz, staking, respaldo…): update-wallet.sh (rápido,
#     no reinicia el validador).
#   - Cambió el nodo/consenso/protocolo: update-node.sh (reinicia el validador).
#   - Ante la duda, update-node.sh hace las dos cosas.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE="qchain-wallet"
ASUMIR_SI=0

decir() { printf '\n==> %s\n' "$1"; }
error() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) ASUMIR_SI=1; shift ;;
    --help|-h) sed -n '2,20p' "$0"; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./deploy/update-wallet.sh)"
command -v docker >/dev/null 2>&1 || error "Docker no está instalado."
[ -f "$REPO_ROOT/Dockerfile" ] || error "no encontré el Dockerfile en $REPO_ROOT - corré esto desde el repo de qchain"
systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 && systemctl cat "$SERVICE" >/dev/null 2>&1 \
  || error "no encontré el servicio '$SERVICE'. ¿Instalaste la wallet con deploy/install-wallet.sh?"

VERSION_REPO="$(grep -oP '"version"\s*:\s*"\K[^"]+' "$REPO_ROOT/version.json" 2>/dev/null | head -1 || echo 'desconocida')"
decir "Actualizando la wallet a la versión del repo: $VERSION_REPO (el nodo NO se toca)"

if [ "$ASUMIR_SI" -ne 1 ]; then
  read -rp "Reconstruir la imagen y reiniciar solo la wallet. ¿Continuar? [s/N] " r
  case "$r" in s|S|si|Si|SI) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

decir "Reconstruyendo la imagen qchain:latest (rápido si Docker ya tiene la cache)"
DOCKER_BUILDKIT=1 docker build -t qchain:latest "$REPO_ROOT"

decir "Reiniciando la wallet"
systemctl restart "$SERVICE"

OK=0
for _ in $(seq 1 12); do
  sleep 1
  if systemctl is-active --quiet "$SERVICE"; then OK=1; break; fi
done
[ "$OK" -eq 1 ] || error "la wallet no quedó activa. Mirá: journalctl -u $SERVICE -e --no-pager"

decir "Listo. La wallet está corriendo la versión $VERSION_REPO. El validador no se reinició."
echo "Si la abrís en el navegador y ves la versión vieja, hacé un refresco fuerte o abrí en pestaña privada (caché)."
