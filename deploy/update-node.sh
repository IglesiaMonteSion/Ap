#!/usr/bin/env bash
# Actualiza un nodo qchain ya instalado a la última versión del código, sin
# perder tu clave ni el estado de la cadena. Pensado para el mismo flujo que
# `install-node.sh` deja armado (imagen Docker `qchain:latest` + servicio
# systemd `qchain-validator`, archivos en /opt/qchain).
#
# Uso típico (desde el repo, en la VPS del nodo) — UN SOLO COMANDO:
#   sudo ./deploy/update-node.sh          # git pull + rebuild + restart + health-check
#
# Qué hace, en orden:
#   1. `git pull` del repo (como el dueño del repo, no como root) salvo --no-pull.
#   2. Si el commit no cambió desde la última build, NO reconstruye (salvo --force).
#   3. Etiqueta la imagen actual como `qchain:previous` (punto de rollback real).
#   4. Reconstruye `qchain:latest` desde el código.
#   5. Reinicia el servicio systemd (clave/config.json/data NO se tocan — el
#      nodo resume su estado exacto desde `data_dir`).
#   6. HEALTH-CHECK real: espera a que el RPC responda y a que la RONDA AVANCE
#      (no solo que systemd diga "active"). Si no queda sano, con --rollback
#      vuelve solo a `qchain:previous`; sin la bandera, te deja el comando exacto.
#
# Banderas: --no-pull  --force  --rollback  --yes/-y  --home <dir>  --help
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
SERVICE="qchain-validator"
ASUMIR_SI=0
HACER_PULL=1
FORZAR=0
ROLLBACK_AUTO=0

decir() { printf '\n==> %s\n' "$1"; }
error() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --no-pull) HACER_PULL=0; shift ;;
    --force) FORZAR=1; shift ;;
    --rollback) ROLLBACK_AUTO=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    --help|-h) sed -n '2,26p' "$0"; exit 0 ;;
    *) error "opción desconocida: $1 (ver --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./deploy/update-node.sh)"
command -v docker >/dev/null 2>&1 || error "Docker no está instalado. Instalalo o corré primero deploy/install-node.sh"
[ -f "$REPO_ROOT/Dockerfile" ] || error "no encontré el Dockerfile en $REPO_ROOT - corré esto desde el repo de qchain"

RPC_PORT="$(grep -oP '"rpc_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" 2>/dev/null | head -1 || true)"
RPC_PORT="${RPC_PORT:-8080}"
version_rpc() { curl -fsSL --max-time 3 "http://127.0.0.1:$RPC_PORT/version" 2>/dev/null | grep -oP '"version"\s*:\s*"\K[^"]+' || echo 'desconocida'; }
round_rpc()   { curl -fsSL --max-time 3 "http://127.0.0.1:$RPC_PORT/status"  2>/dev/null | grep -oP '"next_round"\s*:\s*\K[0-9]+' || echo ''; }

# 1. git pull (como el dueño del repo, para evitar el error de "dubious ownership" de git corriendo como root).
# Como el pull puede REEMPLAZAR este mismo script en disco, y bash lee el archivo
# por offset de bytes mientras corre (un cambio a mitad de camino lo desincroniza),
# tras el pull nos RE-EJECUTAMOS con la versión recién traída, desde el arranque
# limpio. El guard QCHAIN_UPDATE_REEXEC evita volver a pullear/loopear.
if [ "$HACER_PULL" -eq 1 ] && [ -d "$REPO_ROOT/.git" ] && [ -z "${QCHAIN_UPDATE_REEXEC:-}" ]; then
  DUENO="$(stat -c '%U' "$REPO_ROOT/.git")"
  decir "Trayendo el código nuevo (git pull, como '$DUENO')"
  if [ "$DUENO" != "root" ] && command -v sudo >/dev/null 2>&1; then
    sudo -u "$DUENO" git -C "$REPO_ROOT" pull --ff-only || error "git pull falló. Resolvé el conflicto a mano y reintentá (o corré con --no-pull)."
  else
    git -C "$REPO_ROOT" config --global --add safe.directory "$REPO_ROOT" 2>/dev/null || true
    git -C "$REPO_ROOT" pull --ff-only || error "git pull falló. Resolvé el conflicto a mano y reintentá (o corré con --no-pull)."
  fi
  export QCHAIN_UPDATE_REEXEC=1
  exec "$0" "$@"   # continuá con el script ya actualizado, sin volver a pullear
fi

VERSION_ACTUAL="$(version_rpc)"
VERSION_REPO="$(grep -oP '"version"\s*:\s*"\K[^"]+' "$REPO_ROOT/version.json" 2>/dev/null | head -1 || echo 'desconocida')"
decir "Versión que corre el nodo ahora: $VERSION_ACTUAL"
echo "Versión del código en este repo:  $VERSION_REPO"

# 2. Skip si el commit no cambió desde la última build exitosa (salvo --force)
COMMIT_ACTUAL=""
[ -d "$REPO_ROOT/.git" ] && COMMIT_ACTUAL="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo '')"
MARCA="$QCHAIN_HOME/.last_built_commit"
if [ "$FORZAR" -ne 1 ] && [ -n "$COMMIT_ACTUAL" ] && [ -f "$MARCA" ] && [ "$(cat "$MARCA" 2>/dev/null)" = "$COMMIT_ACTUAL" ] && docker image inspect qchain:latest >/dev/null 2>&1; then
  decir "El código no cambió desde la última actualización (commit ${COMMIT_ACTUAL:0:12}) y la imagen ya existe."
  echo "No hay nada que reconstruir. Usá --force para reconstruir igual."
  exit 0
fi

if [ "$ASUMIR_SI" -ne 1 ]; then
  read -rp "Esto reconstruye la imagen y reinicia el nodo (tu clave y el estado NO se tocan). ¿Continuar? [S/n] " resp || resp=""
  resp="${resp//[$'\r\t ']/}"   # sacá CR/tab/espacios por si se colaron (la causa de un 'Cancelado' con la 's' bien tipeada)
  case "$resp" in n|N|no|NO|No) echo "Cancelado."; exit 0 ;; esac  # solo 'n' cancela; enter/s/y/cualquier cosa continúa
fi

# 3. Punto de rollback: guardá la imagen actual como qchain:previous
if docker image inspect qchain:latest >/dev/null 2>&1; then
  decir "Guardando la imagen actual como qchain:previous (punto de rollback)"
  docker tag qchain:latest qchain:previous || true
fi

# 4. Reconstruir
decir "Reconstruyendo la imagen qchain:latest desde el código (puede tardar unos minutos)"
DOCKER_BUILDKIT=1 docker build -t qchain:latest "$REPO_ROOT"

# 5. Reiniciar
decir "Reiniciando el nodo"
systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1 && systemctl cat "$SERVICE" >/dev/null 2>&1 \
  || error "no encontré el servicio systemd '$SERVICE'. Reiniciá tu nodo a mano con la imagen recién construida."
systemctl restart "$SERVICE"

# 6. Health-check real: activo + RPC responde + la ronda AVANZA
decir "Comprobando salud del nodo (activo, RPC, y que la ronda avance)"
ACTIVO=0
for _ in $(seq 1 15); do sleep 1; if systemctl is-active --quiet "$SERVICE"; then ACTIVO=1; break; fi; done

SANO=0
if [ "$ACTIVO" -eq 1 ]; then
  # Esperá a que el RPC responda. Tras un test de carga pesado, el nodo
  # recarga del disco (DAG + worker batches + recibos + comités) ANTES de
  # bindear el RPC, y eso puede tardar bastantes segundos en una cadena con
  # mucha historia — el RPC recién responde al terminar. Ventana generosa
  # (90s) para no dar un FALSO 'congelamiento' en ese caso (el nodo está
  # sano, sólo tardó en arrancar). Ver la lección documentada en CLAUDE.md.
  R0=""; for _ in $(seq 1 90); do R0="$(round_rpc)"; [ -n "$R0" ] && break; sleep 1; done
  if [ -n "$R0" ]; then
    # esperá a ver la ronda subir (un nodo sano avanza; uno congelado no)
    for _ in $(seq 1 45); do
      sleep 1; R1="$(round_rpc)"
      if [ -n "$R1" ] && [ "$R1" -gt "$R0" ] 2>/dev/null; then SANO=1; break; fi
    done
  fi
fi

if [ "$SANO" -eq 1 ]; then
  decir "Listo — el nodo está SANO"
  echo "Versión activa: $(version_rpc). La ronda de consenso está avanzando."
  echo "Ver logs en vivo:  journalctl -u $SERVICE -f"
  [ -n "$COMMIT_ACTUAL" ] && echo "$COMMIT_ACTUAL" > "$MARCA" 2>/dev/null || true
  # Este script actualiza SOLO el validador. Si además tenés la wallet web
  # instalada, sigue corriendo la versión vieja hasta que la reinicies aparte.
  if systemctl list-unit-files qchain-wallet.service >/dev/null 2>&1 && systemctl cat qchain-wallet >/dev/null 2>&1; then
    echo
    echo "NOTA: también tenés la wallet web instalada, y este comando NO la actualizó."
    echo "  Para actualizar el nodo Y la wallet de una:  sudo ./deploy/update.sh --yes"
    echo "  O solo la wallet:                            sudo ./deploy/update-wallet.sh --yes"
    echo "  (Después, en el navegador: refresco fuerte Ctrl+Shift+R o pestaña privada — el .wasm se cachea.)"
  fi
  exit 0
fi

# No quedó sano: rollback (automático con --rollback, si no, instrucción exacta)
printf '\nADVERTENCIA: el nodo NO se ve sano tras la actualización '
if [ "$ACTIVO" -ne 1 ]; then
  echo "(el servicio no quedó activo)."
else
  echo "(el RPC no respondió o la ronda no avanzó dentro del tiempo de espera)."
  echo "NOTA: tras un test de carga pesado, el nodo puede tardar más de lo esperado en"
  echo "      recargar el estado del disco al arrancar. Puede estar SANO y sólo lento."
  echo "      Confirmá a mano antes de hacer rollback:"
  echo "        curl -s http://127.0.0.1:$RPC_PORT/status; echo; sleep 3; curl -s http://127.0.0.1:$RPC_PORT/status; echo"
  echo "      Si next_round SUBE entre las dos lecturas, el nodo está sano (fue un falso positivo)."
fi
echo "Logs:  journalctl -u $SERVICE -e --no-pager"

if docker image inspect qchain:previous >/dev/null 2>&1; then
  if [ "$ROLLBACK_AUTO" -eq 1 ]; then
    decir "Haciendo rollback a la versión anterior (qchain:previous)"
    docker tag qchain:previous qchain:latest
    systemctl restart "$SERVICE"
    sleep 3
    if systemctl is-active --quiet "$SERVICE"; then
      echo "Rollback hecho. El nodo volvió a la imagen anterior. Revisá qué falló antes de reintentar."
    else
      error "el rollback tampoco quedó activo. Revisá los logs: journalctl -u $SERVICE -e --no-pager"
    fi
    exit 1
  fi
  echo
  echo "Para volver a la versión anterior (rollback):"
  echo "  docker tag qchain:previous qchain:latest && sudo systemctl restart $SERVICE"
  echo "O reintentá esta actualización con rollback automático:  sudo ./deploy/update-node.sh --rollback --no-pull --force"
fi
exit 1
