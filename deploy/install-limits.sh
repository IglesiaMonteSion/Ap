#!/usr/bin/env bash
# Aplica los límites de recursos + rotación de logs a un host qchain YA
# desplegado, sin reinstalar los servicios (tarea #199, QCH-S14). Idempotente y
# reversible (--uninstall). No es disruptivo: no reinicia los servicios (los
# nuevos límites de cgroup se aplican en el próximo restart, o pasá --restart).
#
# Qué hace:
#   1) Límite de tamaño del journal (systemd-journald) → los logs no llenan el
#      disco. Los servicios corren como `docker run` bajo systemd, así que su
#      stdout va al journal — este es el "logrotate" real para ellos.
#   2) logrotate para los *.log de archivo (install.log, monitor, backup).
#   3) Un drop-in systemd por servicio qchain instalado con LimitNOFILE /
#      TasksMax / MemoryMax (cap de fd / hilos / RAM a nivel de la unidad).
#
# NOTA honesta sobre qué acota qué: el workload real corre DENTRO del contenedor
# docker, cuyo cgroup NO es el de esta unidad systemd — así que los límites de
# CONTENEDOR efectivos son los flags `--memory` / `--pids-limit` / `--ulimit`
# que viven en el ExecStart de los archivos deploy/systemd/*.service (se aplican
# en una instalación FRESCA o volviendo a correr install-node.sh). El drop-in de
# esta script acota la unidad (el cliente docker) y es defensa-en-profundidad +
# el camino para aplicar los caps de fd/hilos/RAM a un despliegue existente sin
# reescribir su ExecStart. Para el cap de --memory del contenedor en un box
# existente: `sudo ./deploy/install-node.sh` (re-copia la unidad) o editá la
# unidad instalada a mano.
set -Eeuo pipefail
trap 'echo "ERROR en la línea $LINENO. Abortado." >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOURNALD_DST="/etc/systemd/journald.conf.d/qchain.conf"
LOGROTATE_DST="/etc/logrotate.d/qchain"
SERVICES=(qchain-validator qchain-faucet qchain-indexer qchain-wallet)

# Caps por servicio: "unit:nofile:tasks:mem_max:mem_high" (coinciden con los de
# los .service templates de deploy/systemd/).
declare -A NOFILE=( [qchain-validator]=65536 [qchain-faucet]=16384 [qchain-indexer]=16384 [qchain-wallet]=16384 )
declare -A TASKS=(  [qchain-validator]=8192  [qchain-faucet]=2048  [qchain-indexer]=2048  [qchain-wallet]=2048 )
declare -A MEMMAX=( [qchain-validator]=3G    [qchain-faucet]=1G    [qchain-indexer]=2G    [qchain-wallet]=1G )
declare -A MEMHI=(  [qchain-validator]=2560M [qchain-faucet]=768M  [qchain-indexer]=1536M [qchain-wallet]=768M )

RESTART=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help)
      echo "uso: sudo $0 [--restart] [--uninstall]"
      echo "  --restart    reinicia los servicios qchain para aplicar los caps ya (por defecto: al próximo restart)"
      echo "  --uninstall  quita el drop-in del journal, el logrotate y los drop-ins de límites"
      exit 0 ;;
    *) echo "argumento desconocido: $arg" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "corré con sudo/root." >&2; exit 1; }

installed_units() {
  local u out=()
  for u in "${SERVICES[@]}"; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1 && systemctl cat "$u" >/dev/null 2>&1; then
      out+=("$u")
    fi
  done
  printf '%s\n' "${out[@]}"
}

if [ "$UNINSTALL" -eq 1 ]; then
  echo "Desinstalando límites qchain…"
  rm -f "$JOURNALD_DST" "$LOGROTATE_DST"
  for u in "${SERVICES[@]}"; do rm -f "/etc/systemd/system/$u.service.d/limits.conf"; rmdir --ignore-fail-on-non-empty "/etc/systemd/system/$u.service.d" 2>/dev/null || true; done
  systemctl daemon-reload
  systemctl restart systemd-journald || true
  echo "Listo. (Los flags de --memory/--pids-limit del ExecStart de las unidades no se tocan; se van con la unidad.)"
  exit 0
fi

echo "== 1) Límite de tamaño del journal =="
install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$SCRIPT_DIR/systemd/journald-qchain.conf" "$JOURNALD_DST"
echo "  instalado $JOURNALD_DST"

echo "== 2) logrotate de los *.log de archivo =="
install -d -m 0755 /etc/logrotate.d
install -m 0644 "$SCRIPT_DIR/logrotate/qchain" "$LOGROTATE_DST"
if command -v logrotate >/dev/null 2>&1; then
  # -d = dry-run/debug: valida la sintaxis sin rotar nada.
  if logrotate -d "$LOGROTATE_DST" >/tmp/qchain-logrotate-check 2>&1; then
    echo "  instalado + validado $LOGROTATE_DST"
  else
    echo "  AVISO: logrotate -d reportó algo (revisá /tmp/qchain-logrotate-check), pero el archivo quedó instalado."
  fi
else
  echo "  instalado $LOGROTATE_DST (logrotate no está instalado; instalalo con apt-get install logrotate)"
fi

echo "== 3) Drop-ins de límites systemd por servicio instalado =="
mapfile -t UNITS < <(installed_units)
if [ "${#UNITS[@]}" -eq 0 ]; then
  echo "  (ningún servicio qchain instalado — se omite; los .service templates ya traen los límites para una instalación fresca)"
else
  for u in "${UNITS[@]}"; do
    d="/etc/systemd/system/$u.service.d"
    install -d -m 0755 "$d"
    cat > "$d/limits.conf" <<EOF
# Límites de recursos qchain (tarea #199) — aplicados vía drop-in a un
# despliegue existente por deploy/install-limits.sh. Acotan la unidad (cliente
# docker); los límites del CONTENEDOR son los flags --memory/--pids-limit/
# --ulimit del ExecStart de la unidad. Ver deploy/install-limits.sh.
[Service]
LimitNOFILE=${NOFILE[$u]}
TasksMax=${TASKS[$u]}
MemoryMax=${MEMMAX[$u]}
MemoryHigh=${MEMHI[$u]}
EOF
    echo "  drop-in escrito para $u (NOFILE=${NOFILE[$u]} TasksMax=${TASKS[$u]} MemoryMax=${MEMMAX[$u]})"
  done
fi

echo "== Recargando systemd =="
systemctl daemon-reload
systemctl restart systemd-journald || true

if [ "$RESTART" -eq 1 ] && [ "${#UNITS[@]}" -gt 0 ]; then
  for u in "${UNITS[@]}"; do echo "  reiniciando $u…"; systemctl try-restart "$u" || true; done
fi

echo
echo "Listo. Journal acotado a $(grep -m1 SystemMaxUse "$JOURNALD_DST" | cut -d= -f2), logrotate instalado, y drop-ins de límites para: ${UNITS[*]:-ninguno}."
[ "$RESTART" -eq 0 ] && echo "Los caps de la unidad se aplican en el próximo restart de cada servicio (o corré de nuevo con --restart)."
echo "Recordá: el cap de --memory del CONTENEDOR se aplica en una instalación fresca o corriendo 'sudo ./deploy/install-node.sh'."
