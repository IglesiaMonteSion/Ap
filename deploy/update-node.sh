#!/usr/bin/env bash
# Actualiza un nodo qchain ya instalado a la última versión del código, sin
# perder tu clave ni el estado de la cadena. Pensado para el mismo flujo que
# `install-node.sh` deja armado (imagen Docker `qchain:latest` + servicio
# systemd `qchain-validator`, archivos en /opt/qchain).
#
# Uso típico (desde el repo, en la VPS del nodo):
#   git pull                       # traé el código nuevo
#   sudo ./deploy/update-node.sh   # reconstruye la imagen y reinicia el nodo
#
# Qué hace:
#   1. Muestra la versión que corre el nodo ahora (GET /version) y la del repo.
#   2. Reconstruye la imagen `qchain:latest` desde el código actual del repo.
#   3. Reinicia el servicio systemd (la clave, config.json y data/ NO se tocan
#      - el nodo resume su estado exacto desde `data_dir`).
#   4. Confirma que quedó activo y muestra la versión nueva.
#
# Es seguro correrlo aunque no haya cambios: reconstruye (rápido si Docker ya
# tiene la cache) y reinicia. No borra nada.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
SERVICE="qchain-validator"
ASUMIR_SI=0

decir() { printf '\n==> %s\n' "$1"; }
error() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --help|-h)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./deploy/update-node.sh)"
command -v docker >/dev/null 2>&1 || error "Docker no está instalado. Instalalo o corré primero deploy/install-node.sh"
[ -f "$REPO_ROOT/Dockerfile" ] || error "no encontré el Dockerfile en $REPO_ROOT - corré esto desde el repo de qchain"

# 1. Versiones
RPC_PORT="$(grep -oP '"rpc_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" 2>/dev/null | head -1 || true)"
RPC_PORT="${RPC_PORT:-8080}"
VERSION_ACTUAL="$(curl -fsSL --max-time 3 "http://127.0.0.1:$RPC_PORT/version" 2>/dev/null | grep -oP '"version"\s*:\s*"\K[^"]+' || echo 'desconocida')"
VERSION_REPO="$(grep -oP '"version"\s*:\s*"\K[^"]+' "$REPO_ROOT/version.json" 2>/dev/null | head -1 || echo 'desconocida')"
decir "Versión que corre el nodo ahora: $VERSION_ACTUAL"
echo "Versión del código en este repo:  $VERSION_REPO"

if [ "$ASUMIR_SI" -ne 1 ]; then
  read -rp "Esto reconstruye la imagen y reinicia el nodo (tu clave y el estado NO se tocan). ¿Continuar? [s/N] " resp
  case "$resp" in s|S|si|Si|SI) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

# 2. Reconstruir la imagen desde el código actual
decir "Reconstruyendo la imagen qchain:latest desde el código (puede tardar unos minutos)"
docker build -t qchain:latest "$REPO_ROOT"

# 3. Reiniciar el servicio (estado y clave intactos)
decir "Reiniciando el nodo"
if systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 && systemctl cat "$SERVICE" >/dev/null 2>&1; then
  systemctl restart "$SERVICE"
else
  error "no encontré el servicio systemd '$SERVICE'. Si instalaste distinto, reiniciá tu nodo a mano usando la imagen recién construida."
fi

# 4. Confirmar
decir "Comprobando que el nodo volvió a arrancar"
OK=0
for _ in $(seq 1 15); do
  sleep 1
  if systemctl is-active --quiet "$SERVICE"; then OK=1; break; fi
done
[ "$OK" -eq 1 ] || error "el servicio no quedó activo. Mirá: journalctl -u $SERVICE -e --no-pager"

sleep 2
VERSION_NUEVA="$(curl -fsSL --max-time 3 "http://127.0.0.1:$RPC_PORT/version" 2>/dev/null | grep -oP '"version"\s*:\s*"\K[^"]+' || echo 'desconocida')"
decir "Listo"
echo "El nodo está activo, ahora corriendo la versión: $VERSION_NUEVA"
echo "Ver logs en vivo:  journalctl -u $SERVICE -f"
