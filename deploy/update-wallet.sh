#!/usr/bin/env bash
# Actualiza SOLO la wallet web a la última versión del código, sin tocar el
# nodo. Pensado para el caso frecuente de cambios de interfaz (HTML/CSS/JS de
# la wallet): reconstruye la imagen `qchain:latest` (rápido — con las cache
# mounts del Dockerfile solo recompila el crate que cambió) y reinicia el
# servicio `qchain-wallet`. El validador sigue corriendo sin interrupción.
#
# Uso (desde el repo, en la VPS) — UN SOLO COMANDO:
#   sudo ./deploy/update-wallet.sh        # git pull + rebuild + restart + health-check
#
# ¿Cuándo esto y cuándo update-node.sh?
#   - Cambió la wallet (interfaz, staking, respaldo…): update-wallet.sh (rápido,
#     no reinicia el validador).
#   - Cambió el nodo/consenso/protocolo: update-node.sh (reinicia el validador).
#   - Ante la duda, deploy/update.sh hace las dos cosas.
#
# Banderas: --no-pull  --force  --yes/-y  --home <dir>  --help
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
SERVICE="qchain-wallet"
ASUMIR_SI=0
HACER_PULL=1
FORZAR=0

decir() { printf '\n==> %s\n' "$1"; }
error() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --no-pull) HACER_PULL=0; shift ;;
    --force) FORZAR=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --help|-h) sed -n '2,18p' "$0"; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./deploy/update-wallet.sh)"
command -v docker >/dev/null 2>&1 || error "Docker no está instalado."
[ -f "$REPO_ROOT/Dockerfile" ] || error "no encontré el Dockerfile en $REPO_ROOT - corré esto desde el repo de qchain"
systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 && systemctl cat "$SERVICE" >/dev/null 2>&1 \
  || error "no encontré el servicio '$SERVICE'. ¿Instalaste la wallet con deploy/install-wallet.sh?"

# 1. git pull (como el dueño del repo)
if [ "$HACER_PULL" -eq 1 ] && [ -d "$REPO_ROOT/.git" ]; then
  DUENO="$(stat -c '%U' "$REPO_ROOT/.git")"
  decir "Trayendo el código nuevo (git pull, como '$DUENO')"
  if [ "$DUENO" != "root" ] && command -v sudo >/dev/null 2>&1; then
    sudo -u "$DUENO" git -C "$REPO_ROOT" pull --ff-only || error "git pull falló. Resolvé el conflicto a mano y reintentá (o corré con --no-pull)."
  else
    git -C "$REPO_ROOT" config --global --add safe.directory "$REPO_ROOT" 2>/dev/null || true
    git -C "$REPO_ROOT" pull --ff-only || error "git pull falló. Resolvé el conflicto a mano y reintentá (o corré con --no-pull)."
  fi
fi

VERSION_REPO="$(grep -oP '"version"\s*:\s*"\K[^"]+' "$REPO_ROOT/version.json" 2>/dev/null | head -1 || echo 'desconocida')"
decir "Actualizando la wallet a la versión del repo: $VERSION_REPO (el nodo NO se toca)"

# 2. Skip si el commit no cambió (la wallet comparte la imagen con el nodo; su marca es aparte)
COMMIT_ACTUAL=""
[ -d "$REPO_ROOT/.git" ] && COMMIT_ACTUAL="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo '')"
MARCA="$QCHAIN_HOME/.last_built_wallet_commit"
if [ "$FORZAR" -ne 1 ] && [ -n "$COMMIT_ACTUAL" ] && [ -f "$MARCA" ] && [ "$(cat "$MARCA" 2>/dev/null)" = "$COMMIT_ACTUAL" ] && docker image inspect qchain:latest >/dev/null 2>&1; then
  decir "El código no cambió desde la última actualización de la wallet (commit ${COMMIT_ACTUAL:0:12})."
  echo "No hay nada que reconstruir. Usá --force para reconstruir igual."
  exit 0
fi

if [ "$ASUMIR_SI" -ne 1 ]; then
  read -rp "Reconstruir la imagen y reiniciar solo la wallet. ¿Continuar? [s/N] " r
  case "$r" in s|S|si|Si|SI) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

decir "Reconstruyendo la imagen qchain:latest (rápido si Docker ya tiene la cache)"
DOCKER_BUILDKIT=1 docker build -t qchain:latest "$REPO_ROOT"

decir "Reiniciando la wallet"
systemctl restart "$SERVICE"

# Health-check: activo + la wallet responde por HTTP
WALLET_PORT="$(systemctl show "$SERVICE" -p ExecStart --value 2>/dev/null | grep -oP -- '--bind[= ][^ ]*:\K[0-9]+' | head -1 || true)"
WALLET_PORT="${WALLET_PORT:-8090}"
ACTIVO=0
for _ in $(seq 1 12); do sleep 1; if systemctl is-active --quiet "$SERVICE"; then ACTIVO=1; break; fi; done
[ "$ACTIVO" -eq 1 ] || error "la wallet no quedó activa. Mirá: journalctl -u $SERVICE -e --no-pager"

RESPONDE=0
for _ in $(seq 1 10); do
  sleep 1
  if curl -fsSL --max-time 3 "http://127.0.0.1:$WALLET_PORT/" >/dev/null 2>&1; then RESPONDE=1; break; fi
done

if [ "$RESPONDE" -eq 1 ]; then
  decir "Listo. La wallet está corriendo la versión $VERSION_REPO y responde por HTTP. El validador no se reinició."
  echo "Si la abrís en el navegador y ves la versión vieja, hacé un refresco fuerte o abrí en pestaña privada (caché)."
  [ -n "$COMMIT_ACTUAL" ] && echo "$COMMIT_ACTUAL" > "$MARCA" 2>/dev/null || true
else
  echo
  echo "ADVERTENCIA: la wallet quedó activa pero no respondió por HTTP en el puerto $WALLET_PORT."
  echo "Revisá:  journalctl -u $SERVICE -e --no-pager"
  exit 1
fi
