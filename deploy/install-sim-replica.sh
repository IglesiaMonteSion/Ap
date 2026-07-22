#!/usr/bin/env bash
# install-sim-replica.sh — levanta una RÉPLICA READ-ONLY DE SIMULACIÓN.
#
# Qué es y por qué existe
# -----------------------
# El endpoint público que más carga puede recibir de terceros no confiables es
# `POST /simulate` (previsualiza el resultado de una tx SIN enviarla — lo usa la
# wallet para mostrar "vas a recibir X / fee Y" antes de firmar). Correrlo en el
# MISMO proceso que valida bloques mezcla una superficie pública abusable con el
# consenso. La postura recomendada (docs/DEPLOY.md) es separarlos: el validador
# de consenso queda PRIVADO (RPC loopback) y la simulación/lectura se sirve desde
# una o varias RÉPLICAS READ-ONLY, en otra máquina.
#
# Una réplica es un nodo en modo "unirse" (seguidor): sincroniza el estado de la
# red y sigue la cadena en vivo, pero NO está en el conjunto de validadores, así
# que NO propone bloques ni participa del consenso. Sirve `/simulate` y todos los
# endpoints de LECTURA (/status, /account, /transfers, /economics, ...) contra su
# estado sincronizado. Si la réplica se cae o la saturan, el consenso NO se ve
# afectado — es una superficie desechable y escalable (podés correr varias).
#
# Este script es un envoltorio FINO sobre `install-node.sh --modo unirse` que:
#   1. la instala como seguidor con RPC PÚBLICO (0.0.0.0) — el punto de la réplica;
#   2. FUERZA el rate limit OBLIGATORIO de /simulate en su config (aunque no haya
#      túnel), porque su RPC queda expuesto a internet;
#   3. con --behind-proxy, activa el modo proxy de confianza para leer la IP REAL
#      del cliente (CF-Connecting-IP / X-Forwarded-For, sólo desde un peer
#      loopback = tu Cloudflare/nginx local), en vez de agrupar a todos;
#   4. te recuerda las reglas: NO la pongas en la misma máquina que el validador,
#      y ponele HTTPS + rate limit de borde adelante (Cloudflare/nginx).
#
# NO es un validador: no se auto-registra, no stakea, no firma bloques. Es una
# ventana de LECTURA/SIMULACIÓN de la red.
#
# Uso (en una VPS distinta a la del validador, como root):
#   sudo ./install-sim-replica.sh \
#       --config config-publico-de-la-red.json \
#       --sync-peer http://<ip-de-un-nodo-vivo>:8080 \
#       [--behind-proxy] [--rate 8] [--rpc-port 8080] [--listen-port 9000]
#
#   sudo ./install-sim-replica.sh --uninstall     # baja el servicio (no toca datos)
#
# El config PÚBLICO de la red (validators+genesis, SIN claves privadas) lo da
# CUALQUIER nodo que ya corra (su archivo config.json). El --sync-peer es el RPC
# de un nodo vivo para ponerse al día por state-sync.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CONFIG=""
SYNC_PEERS=()
BEHIND_PROXY=0
RATE=8
RPC_PORT=8080
LISTEN_PORT=9000
HOME_DIR="/opt/qchain"
IMAGE="qchain:latest"
MODE="install"

error() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[sim-replica] $*"; }
trap 'error "falló en la línea $LINENO."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --config|--red-config) CONFIG="${2:-}"; shift 2 ;;
    --sync-peer) SYNC_PEERS+=("${2:-}"); shift 2 ;;
    --behind-proxy) BEHIND_PROXY=1; shift ;;
    --rate) RATE="${2:-}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:-}"; shift 2 ;;
    --listen-port) LISTEN_PORT="${2:-}"; shift 2 ;;
    --home) HOME_DIR="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --uninstall) MODE="uninstall"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,44p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo."

# --- validaciones -----------------------------------------------------------
case "$RATE" in ''|*[!0-9]*) error "--rate debe ser un entero (tx/IP/10s)." ;; esac
[ "$RATE" -ge 1 ] || error "--rate debe ser >= 1 (el piso efectivo del nodo es 5)."

# ---------------------------------------------------------------------------
# --uninstall: delega en install-node.sh (misma unidad systemd qchain-validator)
# ---------------------------------------------------------------------------
if [ "$MODE" = "uninstall" ]; then
  "$SCRIPT_DIR/install-node.sh" --uninstall --home "$HOME_DIR" --image "$IMAGE" \
    || error "no pude desinstalar el servicio."
  log "réplica desinstalada (los datos en $HOME_DIR NO se tocaron)."
  exit 0
fi

[ -n "$CONFIG" ] || error "falta --config <config-publico-de-la-red.json> (pedíselo a cualquier nodo que ya corra)."
[ -f "$CONFIG" ] || error "no encontré el archivo de config: $CONFIG"
[ "${#SYNC_PEERS[@]}" -ge 1 ] || error "falta --sync-peer http://<ip-de-un-nodo-vivo>:8080 (para ponerse al día)."
command -v python3 >/dev/null 2>&1 || error "falta python3 (apt install -y python3) — se usa para endurecer el config."

# ---------------------------------------------------------------------------
# 1) Instalar como SEGUIDOR con RPC público, reusando toda la maquinaria probada
#    de install-node.sh (Docker/imagen, keygen de identidad P2P, adaptación del
#    config, firewall, systemd). Sin wallet ni túnel: es una réplica pelada.
# ---------------------------------------------------------------------------
SYNC_ARGS=()
for p in "${SYNC_PEERS[@]}"; do SYNC_ARGS+=(--sync-peer "$p"); done

log "instalando la réplica (seguidor, RPC público) con install-node.sh..."
"$SCRIPT_DIR/install-node.sh" --modo unirse --yes \
  --config "$CONFIG" "${SYNC_ARGS[@]}" \
  --rpc-public --rpc-port "$RPC_PORT" --listen-port "$LISTEN_PORT" \
  --home "$HOME_DIR" --image "$IMAGE" \
  || error "install-node.sh falló al levantar la réplica."

# ---------------------------------------------------------------------------
# 2) FORZAR el rate limit de /simulate en el config (aunque no haya túnel: el RPC
#    quedó público). 3) Con --behind-proxy, activar el modo proxy de confianza.
#    Idempotente.
# ---------------------------------------------------------------------------
CFG="$HOME_DIR/config.json"
[ -f "$CFG" ] || error "no encontré $CFG tras la instalación."
RATE="$RATE" BEHIND_PROXY="$BEHIND_PROXY" python3 - "$CFG" <<'PY' || error "no pude endurecer el config de la réplica."
import json, os, sys
p = sys.argv[1]
c = json.load(open(p))
c["simulate_rate_limit_per_10s"] = int(os.environ["RATE"])
if os.environ.get("BEHIND_PROXY") == "1":
    c["rpc_behind_trusted_proxy"] = True   # leer la IP real del cliente reenviada por el proxy local
json.dump(c, open(p, "w"), indent=2)
PY
chmod 600 "$CFG" 2>/dev/null || true
log "rate limit de /simulate fijado en $RATE tx/IP/10s$([ "$BEHIND_PROXY" = 1 ] && echo ' + modo proxy de confianza')."

# Reiniciar el servicio para que tome el config endurecido.
systemctl restart qchain-validator 2>/dev/null || true
sleep 2
if systemctl is-active --quiet qchain-validator; then
  log "réplica activa (systemctl status qchain-validator)."
else
  echo "AVISO: el servicio no quedó activo; revisá: journalctl -u qchain-validator -e" >&2
fi

# ---------------------------------------------------------------------------
# Guía final
# ---------------------------------------------------------------------------
cat <<EOF

============================================================================
 RÉPLICA READ-ONLY DE SIMULACIÓN lista.
============================================================================
Qué es: un SEGUIDOR (no valida, no propone, no stakea). Sincroniza el estado y
sirve /simulate + los endpoints de LECTURA en el puerto $RPC_PORT (público).

Reglas de seguridad (importantes):
  • NO la corras en la misma máquina que el validador de consenso. El punto es
    aislar la superficie pública del consenso.
  • Ponele HTTPS + rate limit de BORDE adelante (Cloudflare/nginx). Si lo hacés,
    reinstalá con --behind-proxy para que lea la IP REAL del cliente (hoy
    rate_limit=$RATE tx/IP/10s aplica sobre la IP que ve directamente).
  • El RPC no tiene autenticación: cualquiera puede leer y simular. Eso es
    esperado para una réplica de lectura; NUNCA le pongas claves de valor.

Para ponerte al día y verificar:
  journalctl -u qchain-validator -f        # buscá 'state-synced ... at round'
  curl -s http://127.0.0.1:$RPC_PORT/status

Escalar: corré este mismo instalador en varias VPS y balanceá /simulate entre
ellas (round-robin en tu nginx/Cloudflare). Cada réplica es independiente.

Desinstalar:  sudo ./install-sim-replica.sh --uninstall --home $HOME_DIR
============================================================================
EOF
