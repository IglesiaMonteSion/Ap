#!/usr/bin/env bash
# prelaunch-check.sh — auditoría READ-ONLY del estado de una VPS validador contra
# la checklist operativa previa a ir a VALOR REAL. No cambia NADA: sólo lee
# config, servicios systemd, firewall y sshd, e imprime ✓ / ⚠ / ✗ por ítem con
# qué hacer. Corré esto en la VPS por SSH (idealmente con sudo para ver sshd/ufw).
#
# Uso:  sudo ./deploy/prelaunch-check.sh [--home /opt/qchain] [--rpc-port 8080]
set -Eeuo pipefail

HOME_DIR=/opt/qchain
RPC_PORT=8080
while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;;
    --rpc-port) RPC_PORT="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bandera desconocida: $1" >&2; exit 1 ;;
  esac
done

PASS=0; WARN=0; FAIL=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$1"; WARN=$((WARN+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
note() { printf '      %s\n' "$1"; }

CFG="$HOME_DIR/config.json"
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
have() { command -v "$1" >/dev/null 2>&1; }
# Lee un campo top-level del config.json (string o bool). "" si falta python3/campo.
cfg() {
  [ -f "$CFG" ] || { echo ""; return; }
  python3 - "$CFG" "$1" 2>/dev/null <<'PY' || echo ""
import json,sys
try:
    d=json.load(open(sys.argv[1])); v=d.get(sys.argv[2])
    print("" if v is None else v)
except Exception:
    print("")
PY
}

echo "== Checklist pre-lanzamiento de Qchain (read-only) =="
echo "   home=$HOME_DIR  $([ "$IS_ROOT" = 1 ] && echo '(root: chequeos completos)' || echo '(sin sudo: sshd/ufw se saltean)')"
echo

# 1) RPC privado (bind a loopback, no expuesto a internet).
echo "1) RPC privado (no accesible desde internet)"
RPC_ADDR=$(cfg rpc_addr)
if [ -z "$RPC_ADDR" ]; then
  warn "no pude leer rpc_addr de $CFG (¿home correcto? ¿python3?)"
elif printf '%s' "$RPC_ADDR" | grep -qE '^127\.0\.0\.1:|^localhost:'; then
  ok "rpc_addr=$RPC_ADDR (loopback — sólo local/túnel)"
else
  bad "rpc_addr=$RPC_ADDR — el RPC no tiene auth; exponerlo deja a cualquiera mandar tx"
  note "arreglá: poné rpc_addr en 127.0.0.1:$RPC_PORT en $CFG y reiniciá el validador"
fi
if [ "$IS_ROOT" = 1 ] && have ufw; then
  if ufw status 2>/dev/null | grep -qE "^${RPC_PORT}/tcp\s+ALLOW"; then
    bad "ufw tiene ${RPC_PORT}/tcp ABIERTO — cerrá el puerto del RPC: sudo ufw delete allow ${RPC_PORT}/tcp"
  else
    ok "ufw no expone el puerto RPC ${RPC_PORT}/tcp"
  fi
fi
echo

# 2) Dashboard público bajado (para ir a valor real).
echo "2) Dashboard del operador NO expuesto a internet"
DASH_ACTIVE=0
if have systemctl; then
  for svc in qchain-dashboard-tunnel qchain-dashboard-proxy caddy; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "servicio '$svc' ACTIVO — si ya vas a valor real, bajalo: sudo ./deploy/install-dashboard.sh --uninstall"
      DASH_ACTIVE=1
    fi
  done
fi
[ "$DASH_ACTIVE" = 0 ] && ok "no hay túnel/proxy de dashboard activo (o ya lo bajaste)"
echo

# 3) Transporte P2P autenticado + cifrado (cutover coordinado cuando sumes nodos).
echo "3) Transporte P2P autenticado + cifrado"
AUTH=$(cfg authenticated_transport); ENC=$(cfg encrypted_transport)
NVAL=$(python3 - "$CFG" 2>/dev/null <<'PY' || echo "?"
import json,sys
try: print(len(json.load(open(sys.argv[1])).get("validators",[])))
except Exception: print("?")
PY
)
if [ "$AUTH" = "True" ] || [ "$AUTH" = "true" ]; then
  ok "authenticated_transport ON"
  if [ "$ENC" = "True" ] || [ "$ENC" = "true" ]; then ok "encrypted_transport ON (confidencialidad + anti-relay)"; else warn "encrypted_transport OFF — encendelo cuando hagas el cutover (v6.5.0+)"; fi
elif [ "$NVAL" = "1" ]; then
  warn "auth/cifrado OFF y sos 1 validador — está bien por ahora; encendelos en el cutover coordinado al sumar nodos"
  note "TODOS los nodos deben usar el mismo valor y reiniciar juntos (wire-breaking, no cambia génesis)"
else
  bad "sos $NVAL validadores con auth OFF — el P2P es suplantable; encendé auth+cifrado en cutover coordinado"
fi
echo

# 4) Clave de la autoridad de tesorería en frío (no en el server que da a internet).
echo "4) Clave de la AUTORIDAD de tesorería en frío"
TREAS_KEYS=$(ls /root/qchain-treasury/treasury-authority.json "$HOME_DIR"/treasury-authority.json 2>/dev/null || true)
if [ -n "$TREAS_KEYS" ]; then
  warn "clave de tesorería PRESENTE en el server: $TREAS_KEYS"
  note "para valor real: movela a almacenamiento en frío (offline) y sacala del server."
  note "las liberaciones se firman desde frío/montaje temporal; el server nunca necesita la clave para operar."
else
  ok "no hay treasury-authority.json en las rutas típicas del server (bien: en frío)"
fi
echo

# 5) SSH endurecido (sólo clave, sin root, sin password).
echo "5) SSH endurecido"
if [ "$IS_ROOT" = 1 ] && have sshd; then
  EFF=$(sshd -T 2>/dev/null || true)
  if [ -n "$EFF" ]; then
    echo "$EFF" | grep -qi '^passwordauthentication no' && ok "PasswordAuthentication no" || bad "PasswordAuthentication SÍ — corré: sudo ./deploy/harden-ssh.sh"
    echo "$EFF" | grep -qiE '^permitrootlogin (no|prohibit-password)' && ok "PermitRootLogin restringido" || warn "PermitRootLogin permisivo — corré harden-ssh.sh"
  else
    warn "no pude volcar la config efectiva de sshd (sshd -T)"
  fi
elif [ -f /etc/ssh/sshd_config.d/99-qchain-hardening.conf ]; then
  ok "drop-in de hardening presente (corré con sudo para confirmar efectivo)"
elif [ "$IS_ROOT" != 1 ]; then
  warn "sin sudo no puedo verificar sshd; corré 'sudo ./deploy/prelaunch-check.sh' o 'sudo ./deploy/harden-ssh.sh'"
else
  warn "sshd no detectado en este host (raro en un validador); si usás SSH, corré 'sudo ./deploy/harden-ssh.sh'"
fi
echo

# 6) Respaldos + monitoreo externo.
echo "6) Respaldos automáticos + monitoreo externo"
if have systemctl; then
  systemctl is-enabled --quiet qchain-backup.timer 2>/dev/null && ok "timer de backup habilitado" || warn "sin timer de backup — corré: sudo ./deploy/backup-node.sh --install"
  systemctl is-enabled --quiet qchain-monitor.timer 2>/dev/null && ok "timer de monitoreo habilitado" || warn "sin timer de monitoreo — corré: sudo ./deploy/monitor-node.sh --install --url <ntfy/discord>"
else
  warn "systemctl no disponible; no puedo ver timers de backup/monitoreo"
fi
echo

# 7) Wallet de prueba fondeada en génesis (sacala/vaciala antes de valor real).
echo "7) Wallet de prueba de génesis"
if [ -f "$HOME_DIR/wallet.json" ]; then
  warn "existe $HOME_DIR/wallet.json (la wallet de prueba fondeada en génesis)"
  note "antes de valor real, movela a frío o vaciala; su clave está en el server."
else
  ok "no hay wallet.json de prueba en el server"
fi
echo

# Resumen.
echo "== Resumen: ✓ $PASS   ⚠ $WARN   ✗ $FAIL =="
if [ "$FAIL" -gt 0 ]; then
  echo "   Hay ✗ que cerrar antes de ir a valor real (ver arriba)."
  exit 2
elif [ "$WARN" -gt 0 ]; then
  echo "   Sin bloqueantes; revisá los ⚠ (varios son 'todavía no aplica hasta el cutover / valor real')."
  exit 0
else
  echo "   Todo verde. Listo para el checklist final humano (auditoría externa, etc.)."
fi
