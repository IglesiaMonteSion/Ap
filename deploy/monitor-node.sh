#!/usr/bin/env bash
# monitor-node.sh — monitoreo de salud de un nodo qchain con AVISO EXTERNO.
#
# Por qué corre EN la máquina (no desde afuera): desde v6.3.3 el RPC del nodo
# bindea a 127.0.0.1 (privado, no accesible desde internet — la postura segura).
# Así que el chequeo se hace localmente y, si algo anda mal, EMPUJA un aviso
# HACIA AFUERA (a tu teléfono/chat) por un webhook. No abre ningún puerto.
#
# Qué chequea:
#   1. que el RPC responda (nodo vivo, puerto abierto);
#   2. que las RONDAS AVANCEN (consenso vivo, no congelado) — compara next_round
#      contra la última muestra guardada; si no subió en $STALL_SECS, alerta.
#
# Anti-spam: solo avisa en un CAMBIO de estado (sano→caído / caído→recuperado),
# no en cada corrida. Guarda el estado en $STATE_FILE.
#
# Canales de aviso (elegí uno o varios):
#   --ntfy URL        ntfy.sh (lo más simple para el teléfono). Ej:
#                     --ntfy https://ntfy.sh/mi-canal-secreto-123
#   --discord URL     webhook de Discord.
#   --slack URL       webhook de Slack.
#   --webhook URL     POST genérico {"text":"..."} (compatible con muchos).
#
# Uso (en la VPS, como root):
#   sudo ./deploy/monitor-node.sh --ntfy https://ntfy.sh/mi-canal --check   # un chequeo ahora
#   sudo ./deploy/monitor-node.sh --ntfy https://ntfy.sh/mi-canal --install # cada 2 min (timer)
#   sudo ./deploy/monitor-node.sh --uninstall
#   sudo ./deploy/monitor-node.sh --ntfy https://ntfy.sh/mi-canal --test    # mandar un aviso de prueba
#
# Opciones:
#   --rpc URL         RPC local del nodo (por defecto http://127.0.0.1:8080).
#   --stall-secs N    Segundos sin avanzar de ronda para considerar "congelado" (por defecto 180).
#   --name TXT        Nombre del nodo en los avisos (por defecto el hostname).
set -Eeuo pipefail

RPC="http://127.0.0.1:8080"
STALL_SECS=180
NAME="$(hostname 2>/dev/null || echo nodo)"
NTFY=""
DISCORD=""
SLACK=""
WEBHOOK=""
MODE="check"
STATE_FILE="/var/lib/qchain-monitor/state"
SERVICE=/etc/systemd/system/qchain-monitor.service
TIMER=/etc/systemd/system/qchain-monitor.timer

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --stall-secs) STALL_SECS="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --ntfy) NTFY="${2:-}"; shift 2 ;;
    --discord) DISCORD="${2:-}"; shift 2 ;;
    --slack) SLACK="${2:-}"; shift 2 ;;
    --webhook) WEBHOOK="${2:-}"; shift 2 ;;
    --check) MODE="check"; shift ;;
    --install) MODE="install"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --test) MODE="test"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,34p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo."
command -v curl >/dev/null 2>&1 || error "falta 'curl'."

have_channel() { [ -n "$NTFY$DISCORD$SLACK$WEBHOOK" ]; }

# ---------------------------------------------------------------------------
# Enviar un aviso a todos los canales configurados. $1=título $2=cuerpo $3=prio
# ---------------------------------------------------------------------------
notify() {
  local title="$1" body="$2" prio="${3:-default}"
  local msg="[$NAME] $title — $body"
  if [ -n "$NTFY" ]; then
    curl -fsS --max-time 10 -H "Title: qchain: $title" -H "Priority: $prio" \
      -d "$msg" "$NTFY" >/dev/null 2>&1 || echo "aviso ntfy falló" >&2
  fi
  if [ -n "$DISCORD" ]; then
    curl -fsS --max-time 10 -H 'Content-Type: application/json' \
      -d "{\"content\": $(json_str "$msg")}" "$DISCORD" >/dev/null 2>&1 || echo "aviso discord falló" >&2
  fi
  if [ -n "$SLACK" ]; then
    curl -fsS --max-time 10 -H 'Content-Type: application/json' \
      -d "{\"text\": $(json_str "$msg")}" "$SLACK" >/dev/null 2>&1 || echo "aviso slack falló" >&2
  fi
  if [ -n "$WEBHOOK" ]; then
    curl -fsS --max-time 10 -H 'Content-Type: application/json' \
      -d "{\"text\": $(json_str "$msg")}" "$WEBHOOK" >/dev/null 2>&1 || echo "aviso webhook falló" >&2
  fi
}

# Escapar una cadena para meterla como valor JSON (comillas + backslash + control)
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"
  s="${s//$'\t'/ }"
  printf '"%s"' "$s"
}

# ---------------------------------------------------------------------------
# --uninstall
# ---------------------------------------------------------------------------
if [ "$MODE" = "uninstall" ]; then
  systemctl disable --now qchain-monitor.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER"
  systemctl daemon-reload
  echo "Monitor quitado."
  exit 0
fi

# ---------------------------------------------------------------------------
# --test
# ---------------------------------------------------------------------------
if [ "$MODE" = "test" ]; then
  have_channel || error "configurá al menos un canal (--ntfy/--discord/--slack/--webhook)."
  notify "prueba" "si ves esto, los avisos funcionan." "default"
  echo "Aviso de prueba enviado a los canales configurados."
  exit 0
fi

# ---------------------------------------------------------------------------
# --install (timer cada 2 min que corre este mismo script con --check)
# ---------------------------------------------------------------------------
if [ "$MODE" = "install" ]; then
  have_channel || error "configurá al menos un canal antes de instalar (--ntfy/--discord/--slack/--webhook)."
  SELF="$(readlink -f "$0")"
  CH=""
  [ -n "$NTFY" ]    && CH="$CH --ntfy $NTFY"
  [ -n "$DISCORD" ] && CH="$CH --discord $DISCORD"
  [ -n "$SLACK" ]   && CH="$CH --slack $SLACK"
  [ -n "$WEBHOOK" ] && CH="$CH --webhook $WEBHOOK"
  cat > "$SERVICE" <<EOF
[Unit]
Description=qchain node health monitor (external alerting)
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF --check --rpc $RPC --stall-secs $STALL_SECS --name $NAME$CH
EOF
  cat > "$TIMER" <<EOF
[Unit]
Description=Run qchain node monitor every 2 minutes

[Timer]
OnBootSec=60
OnUnitActiveSec=120

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now qchain-monitor.timer
  echo "Monitor instalado (cada 2 min). Ver:  systemctl list-timers qchain-monitor.timer"
  echo "Probá un aviso ya:  sudo $SELF --test$CH"
  exit 0
fi

# ---------------------------------------------------------------------------
# --check (el chequeo real)
# ---------------------------------------------------------------------------
have_channel || echo "AVISO: sin canal configurado — solo imprimo el estado (no puedo notificar)." >&2

mkdir -p "$(dirname "$STATE_FILE")"

# Estado previo: "STATUS BASE_ROUND BASE_TS", donde BASE_ROUND/BASE_TS son la
# ronda y el momento del ÚLTIMO AVANCE observado. Todo el modelo se apoya en ese
# ancla: mientras la ronda no supere BASE_ROUND, el nodo NO progresó, y el reloj
# de estancamiento corre desde BASE_TS — sin importar en qué estado veníamos.
PREV_STATUS="UNKNOWN"; BASE_ROUND="-1"; BASE_TS="0"
if [ -f "$STATE_FILE" ]; then
  read -r PREV_STATUS BASE_ROUND BASE_TS < "$STATE_FILE" || true
fi
[ -n "$BASE_ROUND" ] || BASE_ROUND="-1"
[ -n "$BASE_TS" ] || BASE_TS="0"
NOW="$(date +%s)"

# Pedir /status al RPC local
BODY="$(curl -fsS --max-time 8 "$RPC/status" 2>/dev/null || true)"

CUR_ROUND=""
if [ -n "$BODY" ]; then
  # extraer next_round del JSON sin depender de jq
  CUR_ROUND="$(printf '%s' "$BODY" | grep -oE '"next_round"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1 || true)"
fi

if [ -z "$BODY" ] || [ -z "$CUR_ROUND" ]; then
  # RPC caído / sin respuesta. Preservamos el ancla de avance (BASE_ROUND/TS)
  # para poder detectar la recuperación cuando vuelva.
  echo "estado: CAÍDO (el RPC no respondió en $RPC)"
  if [ "$PREV_STATUS" != "DOWN" ]; then
    notify "nodo CAÍDO" "el RPC no responde ($RPC). Revisá: systemctl status qchain-validator" "urgent"
  fi
  echo "DOWN $BASE_ROUND $BASE_TS" > "$STATE_FILE"
  exit 0
fi

# RPC vivo. Si veníamos de CAÍDO, el solo hecho de que responda ES la
# recuperación (independiente de si la ronda ya avanzó). Reiniciamos el ancla de
# avance a AHORA para no declarar estancamiento por un BASE_TS viejo de antes del
# corte (si la ronda no vuelve a subir, un chequeo posterior lo detectará).
if [ "$PREV_STATUS" = "DOWN" ]; then
  echo "estado: OK (ronda $CUR_ROUND)"
  notify "nodo RECUPERADO" "el RPC volvió a responder (ronda $CUR_ROUND)." "default"
  echo "OK $CUR_ROUND $NOW" > "$STATE_FILE"
  exit 0
fi

# ¿La ronda AVANZÓ respecto del último avance conocido?
if [ "$BASE_ROUND" -lt 0 ] || [ "$CUR_ROUND" -gt "$BASE_ROUND" ]; then
  # Progreso (o primera muestra). Nuevo ancla de avance = ahora.
  echo "estado: OK (ronda $CUR_ROUND)"
  if [ "$PREV_STATUS" = "STALL" ]; then
    notify "nodo RECUPERADO" "el nodo volvió a avanzar (ronda $CUR_ROUND)." "default"
  fi
  echo "OK $CUR_ROUND $NOW" > "$STATE_FILE"
  exit 0
fi

# Sin avance: la ronda sigue en BASE_ROUND (o por debajo). ¿Cuánto hace?
ELAPSED=$((NOW - BASE_TS))
if [ "$ELAPSED" -ge "$STALL_SECS" ]; then
  echo "estado: CONGELADO (ronda fija en $CUR_ROUND hace ${ELAPSED}s >= ${STALL_SECS}s)"
  if [ "$PREV_STATUS" != "STALL" ]; then
    notify "consenso CONGELADO" "la ronda no avanza (fija en $CUR_ROUND). Revisá pares/logs: journalctl -u qchain-validator -e" "urgent"
  fi
  # Conservamos el ancla del último avance para que el estado siga CONGELADO
  # en cada chequeo hasta que la ronda realmente suba.
  echo "STALL $BASE_ROUND $BASE_TS" > "$STATE_FILE"
  exit 0
fi

# Sin avance todavía, pero dentro de la ventana de gracia: sigue OK.
echo "estado: OK (ronda $CUR_ROUND, sin avanzar hace ${ELAPSED}s)"
echo "OK $BASE_ROUND $BASE_TS" > "$STATE_FILE"
