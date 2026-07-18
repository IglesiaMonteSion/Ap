#!/usr/bin/env bash
# backup-node.sh — respaldo CIFRADO de lo IRREEMPLAZABLE de un nodo qchain.
#
# Qué respalda (y por qué SOLO esto):
#   - keypair.json      → la clave que firma bloques. IRREEMPLAZABLE: si la
#                         perdés, tu validador deja de existir (no hay forma de
#                         regenerarla). Es lo único que DEBE respaldarse.
#   - config.json       → la identidad de la red (validators+genesis = chain_id).
#                         Público, pero práctico tenerlo junto.
#   - wallets/           → claves de la wallet web (si el nodo también corre la
#                         wallet en /opt/qchain/wallets).
#   - faucet-keypair.json → la clave caliente del faucet (si está instalado).
#
# NO respalda `data/` a propósito: es el estado del ledger (DAG, recibos, cuentas),
# pesado y RE-SINCRONIZABLE de los pares por state-sync (`--sync-peer`). Restaurar
# la CLAVE + reincorporarse a la red reconstruye el estado solo. Si igual querés
# una foto del estado, pasá `--with-state` (incluye data/, puede ser grande).
#
# El respaldo va SIEMPRE cifrado (contiene claves privadas): AES-256 con
# PBKDF2 (openssl). Un archivo robado no sirve sin la contraseña. La contraseña
# se toma de (en orden): $QCHAIN_BACKUP_PASSPHRASE, o el archivo
# /opt/qchain/backup.pass (chmod 600). Sin contraseña, el script SE NIEGA a
# escribir claves — no hay respaldo en texto plano.
#
# Uso (en la VPS, como root):
#   sudo ./deploy/backup-node.sh                       # un respaldo ahora
#   sudo ./deploy/backup-node.sh --with-state          # incluir data/ (estado)
#   sudo ./deploy/backup-node.sh --remote user@host:/ruta   # copiar fuera de la máquina (scp)
#   sudo ./deploy/backup-node.sh --install             # respaldo diario automático (timer systemd)
#   sudo ./deploy/backup-node.sh --uninstall           # quitar el timer
#   sudo ./deploy/backup-node.sh --restore ARCHIVO.enc --into /ruta   # restaurar un respaldo
#   sudo ./deploy/backup-node.sh --list                # listar respaldos guardados
#
# Opciones:
#   --home DIR        Directorio del nodo (por defecto /opt/qchain).
#   --out-dir DIR     Dónde guardar los respaldos (por defecto /opt/qchain-backups).
#   --keep N          Cuántos respaldos conservar (rota los viejos, por defecto 14).
#   --remote DEST     Copiar cada respaldo fuera de la máquina por scp (ej. user@host:/backups).
#   --with-state      Incluir data/ (estado del ledger) además de las claves.
#   --no-encrypt      (NO recomendado) escribir el .tar.gz sin cifrar. Requiere confirmación.
set -Eeuo pipefail

QCHAIN_HOME="/opt/qchain"
FAUCET_HOME="/opt/qchain-faucet"
OUT_DIR="/opt/qchain-backups"
KEEP=14
REMOTE=""
WITH_STATE=0
ENCRYPT=1
MODE="run"
RESTORE_FILE=""
RESTORE_INTO=""
ASSUME_YES=0
SERVICE=/etc/systemd/system/qchain-backup.service
TIMER=/etc/systemd/system/qchain-backup.timer

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO. Revisá el mensaje de arriba."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --keep) KEEP="${2:-}"; shift 2 ;;
    --remote) REMOTE="${2:-}"; shift 2 ;;
    --with-state) WITH_STATE=1; shift ;;
    --no-encrypt) ENCRYPT=0; shift ;;
    --install) MODE="install"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --list) MODE="list"; shift ;;
    --restore) MODE="restore"; RESTORE_FILE="${2:-}"; shift 2 ;;
    --into) RESTORE_INTO="${2:-}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,44p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo."
command -v openssl >/dev/null 2>&1 || error "falta 'openssl' (necesario para cifrar). Instalalo: apt-get install -y openssl"
command -v tar >/dev/null 2>&1 || error "falta 'tar'."

# ---------------------------------------------------------------------------
# Resolver la contraseña de cifrado (nunca se imprime ni se guarda en claro).
# ---------------------------------------------------------------------------
get_passphrase() {
  if [ -n "${QCHAIN_BACKUP_PASSPHRASE:-}" ]; then
    printf '%s' "$QCHAIN_BACKUP_PASSPHRASE"; return 0
  fi
  if [ -f "$QCHAIN_HOME/backup.pass" ]; then
    cat "$QCHAIN_HOME/backup.pass"; return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------
if [ "$MODE" = "list" ]; then
  if [ -d "$OUT_DIR" ]; then
    ls -lh "$OUT_DIR"/qchain-backup-* 2>/dev/null || echo "(no hay respaldos en $OUT_DIR)"
  else
    echo "(no existe $OUT_DIR todavía)"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# --restore
# ---------------------------------------------------------------------------
if [ "$MODE" = "restore" ]; then
  [ -n "$RESTORE_FILE" ] || error "pasá el archivo: --restore ARCHIVO"
  [ -f "$RESTORE_FILE" ] || error "no existe el archivo: $RESTORE_FILE"
  DEST="${RESTORE_INTO:-./qchain-restore}"
  mkdir -p "$DEST"
  echo "Restaurando $RESTORE_FILE  ->  $DEST"
  case "$RESTORE_FILE" in
    *.enc)
      PASS="$(get_passphrase)" || error "el respaldo está cifrado y no hay contraseña (definí \$QCHAIN_BACKUP_PASSPHRASE o $QCHAIN_HOME/backup.pass)."
      PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt \
        -in "$RESTORE_FILE" -pass env:PASS 2>/dev/null \
        | tar -xzf - -C "$DEST" \
        || error "no se pudo descifrar/extraer (¿contraseña incorrecta?)."
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$RESTORE_FILE" -C "$DEST"
      ;;
    *) error "no reconozco el formato de $RESTORE_FILE (esperaba .enc o .tar.gz)." ;;
  esac
  chmod -R go-rwx "$DEST" 2>/dev/null || true
  echo "Listo. Archivos restaurados en $DEST (permisos restringidos)."
  echo "Copiá keypair.json/config.json a $QCHAIN_HOME y reiniciá el servicio."
  exit 0
fi

# ---------------------------------------------------------------------------
# --uninstall (timer)
# ---------------------------------------------------------------------------
if [ "$MODE" = "uninstall" ]; then
  systemctl disable --now qchain-backup.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER"
  systemctl daemon-reload
  echo "Timer de respaldo quitado. (No se borró ningún respaldo ya hecho.)"
  exit 0
fi

# ---------------------------------------------------------------------------
# --install (timer diario que corre este mismo script)
# ---------------------------------------------------------------------------
if [ "$MODE" = "install" ]; then
  SELF="$(readlink -f "$0")"
  EXTRA=""
  [ "$WITH_STATE" -eq 1 ] && EXTRA="$EXTRA --with-state"
  [ -n "$REMOTE" ] && EXTRA="$EXTRA --remote $REMOTE"
  cat > "$SERVICE" <<EOF
[Unit]
Description=qchain node backup (encrypted keys + config)
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF --home $QCHAIN_HOME --out-dir $OUT_DIR --keep $KEEP$EXTRA
EOF
  cat > "$TIMER" <<EOF
[Unit]
Description=Daily qchain node backup

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=1200

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now qchain-backup.timer
  echo "Respaldo diario instalado (todos los días ~03:30). Ver:  systemctl list-timers qchain-backup.timer"
  echo "Probá uno ahora con:  sudo $SELF"
  # asegurar que exista una contraseña antes de irse, o el primer run fallará
  if ! get_passphrase >/dev/null 2>&1; then
    echo
    echo "IMPORTANTE: todavía no hay contraseña de cifrado. El respaldo NO correrá hasta que la definas:"
    echo "  echo 'UNA-CONTRASEÑA-FUERTE' | sudo tee $QCHAIN_HOME/backup.pass >/dev/null && sudo chmod 600 $QCHAIN_HOME/backup.pass"
    echo "  (guardá esa contraseña FUERA de la VPS — sin ella, el respaldo no se puede descifrar)"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# MODO run: armar el respaldo ahora
# ---------------------------------------------------------------------------
[ -f "$QCHAIN_HOME/keypair.json" ] || error "no encontré $QCHAIN_HOME/keypair.json — ¿es el directorio correcto? (usá --home)"

# Resolver la contraseña ANTES de escribir nada. Si falta y se pide cifrado,
# abortamos acá — así nunca dejamos un tar en texto plano (con claves privadas)
# a medio camino. Con --no-encrypt exigimos --yes explícito.
BACKUP_PASS=""
if [ "$ENCRYPT" -eq 1 ]; then
  BACKUP_PASS="$(get_passphrase)" || error "no hay contraseña de cifrado. Definí \$QCHAIN_BACKUP_PASSPHRASE o creá $QCHAIN_HOME/backup.pass (chmod 600). (O usá --no-encrypt --yes bajo tu propio riesgo.)"
  [ -n "$BACKUP_PASS" ] || error "la contraseña de cifrado está vacía — usá una contraseña real."
else
  [ "$ASSUME_YES" -eq 1 ] || error "--no-encrypt escribe tus claves privadas SIN cifrar. Si de verdad lo querés, agregá --yes."
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || date +%s)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"; true' EXIT

# Copiar lo irreemplazable al stage (preservando permisos)
cp -p "$QCHAIN_HOME/keypair.json" "$STAGE/"
[ -f "$QCHAIN_HOME/config.json" ] && cp -p "$QCHAIN_HOME/config.json" "$STAGE/"
[ -f "$QCHAIN_HOME/wallet.json" ] && cp -p "$QCHAIN_HOME/wallet.json" "$STAGE/"
if [ -d "$QCHAIN_HOME/wallets" ]; then
  cp -a "$QCHAIN_HOME/wallets" "$STAGE/wallets"
fi
if [ -f "$FAUCET_HOME/faucet-keypair.json" ]; then
  mkdir -p "$STAGE/faucet"
  cp -p "$FAUCET_HOME/faucet-keypair.json" "$STAGE/faucet/"
fi
if [ "$WITH_STATE" -eq 1 ] && [ -d "$QCHAIN_HOME/data" ]; then
  echo "Incluyendo data/ (estado del ledger) — puede tardar..."
  cp -a "$QCHAIN_HOME/data" "$STAGE/data"
fi

# Un pequeño manifiesto para saber qué es cada respaldo
{
  echo "qchain backup"
  echo "creado: $STAMP"
  echo "home: $QCHAIN_HOME"
  echo "with_state: $WITH_STATE"
  echo "contenido:"; ( cd "$STAGE" && find . -maxdepth 2 -type f | sort )
} > "$STAGE/MANIFEST.txt"

TAR="$OUT_DIR/qchain-backup-$STAMP.tar.gz"
tar -czf "$TAR" -C "$STAGE" .

if [ "$ENCRYPT" -eq 1 ]; then
  OUT="$TAR.enc"
  if ! PASS="$BACKUP_PASS" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
        -in "$TAR" -out "$OUT" -pass env:PASS; then
    rm -f "$TAR" "$OUT"   # no dejar NADA en claro si el cifrado falla
    error "falló el cifrado del respaldo."
  fi
  rm -f "$TAR"          # nunca dejar el tar en claro (tiene claves privadas)
  chmod 600 "$OUT"
  FINAL="$OUT"
else
  # opt-out explícito (ya validado --yes arriba): escribir sin cifrar
  chmod 600 "$TAR"
  FINAL="$TAR"
  echo "ADVERTENCIA: respaldo SIN cifrar (tiene claves privadas): $FINAL"
fi

echo "Respaldo creado: $FINAL ($(du -h "$FINAL" | cut -f1))"

# Rotación: conservar los últimos $KEEP
mapfile -t OLD < <(ls -1t "$OUT_DIR"/qchain-backup-* 2>/dev/null | tail -n +"$((KEEP+1))" || true)
if [ "${#OLD[@]}" -gt 0 ]; then
  for f in "${OLD[@]}"; do rm -f "$f"; done
  echo "Rotación: se borraron ${#OLD[@]} respaldo(s) viejo(s) (conservados los últimos $KEEP)."
fi

# Copia fuera de la máquina (durabilidad real: si la VPS muere, el respaldo vive)
if [ -n "$REMOTE" ]; then
  if command -v scp >/dev/null 2>&1; then
    echo "Copiando a $REMOTE ..."
    if scp -q "$FINAL" "$REMOTE"/ 2>/dev/null; then
      echo "Copia remota OK."
    else
      echo "ADVERTENCIA: no se pudo copiar a $REMOTE (¿clave SSH/host?). El respaldo local sí quedó guardado."
    fi
  else
    echo "ADVERTENCIA: falta 'scp' para la copia remota. Instalá openssh-client."
  fi
fi

echo "Listo. Restaurar con:  sudo $0 --restore $FINAL --into /ruta/destino"
