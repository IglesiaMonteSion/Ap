#!/usr/bin/env bash
# harden-ssh.sh — endurecer el acceso SSH de un validador antes de ir a valor
# real. Escribe un drop-in en /etc/ssh/sshd_config.d/ (limpiamente reversible)
# que:
#   - deshabilita el login por CONTRASEÑA (sólo clave pública)
#   - deshabilita el login de ROOT
#   - deshabilita keyboard-interactive / challenge-response
#   - baja MaxAuthTries y apaga X11Forwarding
#   - (opcional) cambia el puerto SSH + lo abre en ufw
#   - (opcional) instala fail2ban
#
# GUARDA ANTI-LOCKOUT (lo más importante): NUNCA deshabilita la contraseña si el
# usuario que va a seguir entrando no tiene ya una clave pública autorizada —
# aborta ruidoso en vez de dejarte afuera. Valida la config con `sshd -t` ANTES
# de recargar, y hace `reload` (no `restart`) así tu sesión actual sobrevive.
#
# Reversible: borrá el drop-in y recargá sshd, o corré `--revert`.
#
# Uso:
#   sudo ./deploy/harden-ssh.sh [--user <usuario>] [--port <n>] [--fail2ban]
#                               [--yes] [--revert]
set -Eeuo pipefail

DROPIN=/etc/ssh/sshd_config.d/99-qchain-hardening.conf
SSH_USER="${SUDO_USER:-$(id -un)}"
NEW_PORT=""
INSTALL_F2B=0
ASSUME_YES=0
REVERT=0

trap 'echo "ERROR en la línea $LINENO. Nada se recargó si el error fue antes del reload. Revisá el mensaje de arriba." >&2' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --user) SSH_USER="$2"; shift 2 ;;
    --port) NEW_PORT="$2"; shift 2 ;;
    --fail2ban) INSTALL_F2B=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --revert) REVERT=1; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "bandera desconocida: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Corré con sudo (necesita escribir /etc/ssh y recargar sshd)." >&2
  exit 1
fi

reload_sshd() {
  # Validar SIEMPRE antes de recargar; una config inválida no se aplica.
  if ! sshd -t 2>/tmp/sshd_test.err; then
    echo "!! La config de sshd quedó INVÁLIDA — NO se recarga (tu SSH sigue intacto):" >&2
    cat /tmp/sshd_test.err >&2
    exit 1
  fi
  # reload, no restart: las sesiones abiertas (la tuya) sobreviven.
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload
  echo "-> sshd recargado (tu sesión actual sigue viva)."
}

if [ "$REVERT" = "1" ]; then
  if [ -f "$DROPIN" ]; then
    rm -f "$DROPIN"
    echo "-> drop-in de hardening eliminado ($DROPIN)."
    reload_sshd
    echo "SSH restaurado a su config previa. (Un cambio de puerto o fail2ban NO se revierten acá — hacelo a mano.)"
  else
    echo "No hay drop-in de hardening que revertir ($DROPIN ausente)."
  fi
  exit 0
fi

# --- GUARDA ANTI-LOCKOUT ---
# El usuario que va a seguir entrando DEBE tener ya una clave pública autorizada,
# o deshabilitar la contraseña lo deja afuera para siempre.
HOME_DIR=$(getent passwd "$SSH_USER" | cut -d: -f6)
AUTHKEYS="$HOME_DIR/.ssh/authorized_keys"
if [ -z "$HOME_DIR" ] || [ ! -s "$AUTHKEYS" ]; then
  echo "!! ABORTO anti-lockout: el usuario '$SSH_USER' no tiene un archivo de claves con contenido en:" >&2
  echo "     $AUTHKEYS" >&2
  echo "   Deshabilitar la contraseña sin una clave autorizada te dejaría AFUERA." >&2
  echo "   Solución: copiá tu clave pública primero (desde tu Mac):" >&2
  echo "     ssh-copy-id -i <tu_clave>.pub $SSH_USER@<ip>" >&2
  echo "   o pasá --user con el usuario correcto. Después re-corré este script." >&2
  exit 1
fi
# Contá cuántas claves reales hay (líneas no vacías, no comentario).
NKEYS=$(grep -cvE '^\s*(#|$)' "$AUTHKEYS" || true)
echo "-> '$SSH_USER' tiene $NKEYS clave(s) pública(s) autorizada(s) en $AUTHKEYS — OK, no te vas a quedar afuera."

echo
echo "Se va a aplicar (drop-in $DROPIN):"
echo "  PasswordAuthentication  no      (sólo clave pública)"
echo "  PermitRootLogin         no      (nada de root directo)"
echo "  KbdInteractiveAuthentication no"
echo "  ChallengeResponseAuthentication no"
echo "  PubkeyAuthentication    yes"
echo "  MaxAuthTries            3"
echo "  X11Forwarding           no"
[ -n "$NEW_PORT" ] && echo "  Port                    $NEW_PORT   (+ abrir $NEW_PORT/tcp en ufw)"
[ "$INSTALL_F2B" = "1" ] && echo "  + instalar fail2ban (banea IPs con brute-force)"
echo

if [ "$ASSUME_YES" != "1" ]; then
  printf "IMPORTANTE: dejá ESTA sesión SSH abierta y probá una NUEVA en otra terminal antes de cerrarla.\n¿Aplicar? [y/N] "
  read -r ANS
  case "$ANS" in y|Y|yes|si|sí) ;; *) echo "cancelado."; exit 0 ;; esac
fi

# Validar el puerto si se pidió.
if [ -n "$NEW_PORT" ]; then
  if ! printf '%s' "$NEW_PORT" | grep -Eq '^[0-9]+$' || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
    echo "!! puerto inválido: '$NEW_PORT'" >&2; exit 1
  fi
fi

# Escribir el drop-in.
{
  echo "# Generado por qchain deploy/harden-ssh.sh — endurecimiento pre-lanzamiento."
  echo "# Revertir: borrar este archivo + 'systemctl reload ssh', o './harden-ssh.sh --revert'."
  echo "PasswordAuthentication no"
  echo "PermitRootLogin no"
  echo "KbdInteractiveAuthentication no"
  echo "ChallengeResponseAuthentication no"
  echo "PubkeyAuthentication yes"
  echo "MaxAuthTries 3"
  echo "X11Forwarding no"
  [ -n "$NEW_PORT" ] && echo "Port $NEW_PORT"
} > "$DROPIN"
chmod 644 "$DROPIN"
echo "-> escrito $DROPIN"

# Si se cambia el puerto, ABRIRLO en ufw ANTES de recargar (o te quedás afuera).
if [ -n "$NEW_PORT" ] && command -v ufw >/dev/null 2>&1; then
  ufw allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
  echo "-> ufw allow ${NEW_PORT}/tcp (abrí el nuevo puerto antes de recargar)."
  echo "   OJO: el puerto 22 viejo sigue abierto en ufw hasta que lo cierres a mano una vez confirmes el nuevo:"
  echo "        sudo ufw delete allow 22/tcp"
fi

reload_sshd

# fail2ban opcional.
if [ "$INSTALL_F2B" = "1" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "-> instalando fail2ban..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
    systemctl enable --now fail2ban 2>/dev/null || true
    echo "-> fail2ban activo (jail sshd por defecto banea IPs con brute-force)."
  else
    echo "!! apt-get no disponible; instalá fail2ban a mano para tu distro." >&2
  fi
fi

echo
echo "=== LISTO. AHORA, SIN CERRAR ESTA SESIÓN: ==="
echo "  1. Abrí una terminal NUEVA y probá entrar por SSH$([ -n "$NEW_PORT" ] && echo " -p $NEW_PORT") con tu clave."
echo "  2. Si entrás bien, cerrá esta sesión. Si NO entrás, revertí acá mismo:"
echo "       sudo ./deploy/harden-ssh.sh --revert"
[ -n "$NEW_PORT" ] && echo "  3. Una vez confirmado el puerto $NEW_PORT, cerrá el 22: sudo ufw delete allow 22/tcp"
