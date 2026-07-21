#!/usr/bin/env bash
# Attestation de la imagen docker qchain (tarea #199, QCH-S14).
#
# Como no hay un registro remoto (la imagen `qchain:latest` se CONSTRUYE en cada
# host desde el Dockerfile del repo — ver install-node.sh), la attestation aquí
# es local: registrar QUÉ imagen está desplegada y de QUÉ código salió, y poder
# VERIFICAR que los contenedores corriendo usan exactamente esa imagen (no una
# vieja o cambiada). Es el gate honesto y accionable en este entorno; la
# attestation de build reproducible / firma de artefactos es la tarea #198.
#
#   record  : escribe image-attestation.json (id de la imagen + commit git +
#             hash del Dockerfile + fecha).
#   verify  : re-lee el manifiesto y confirma que (a) la imagen local sigue
#             siendo esa id y (b) cada contenedor qchain corriendo usa esa id.
#             Exit != 0 si algo no coincide (para CI / un cron de monitoreo).
#   show    : imprime el manifiesto.
set -Eeuo pipefail
trap 'echo "ERROR en la línea $LINENO." >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="${QCHAIN_IMAGE:-qchain:latest}"
MANIFEST="${QCHAIN_ATTEST_FILE:-$REPO_ROOT/image-attestation.json}"
CONTAINERS=(qchain-validator qchain-faucet qchain-indexer qchain-wallet)

need_docker() { command -v docker >/dev/null 2>&1 || { echo "docker no está instalado." >&2; exit 1; }; }

image_id() { docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null; }

cmd_record() {
  need_docker
  local id; id="$(image_id)"
  [ -n "$id" ] || { echo "la imagen $IMAGE no existe localmente — construíla primero (install-node.sh / docker build)." >&2; exit 1; }
  local commit dockerfile_hash dirty
  commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  git -C "$REPO_ROOT" diff --quiet 2>/dev/null && dirty=false || dirty=true
  dockerfile_hash="$(sha256sum "$REPO_ROOT/Dockerfile" 2>/dev/null | cut -d' ' -f1 || echo unknown)"
  # `date` no está permitido en el harness de scripts del proyecto para tests,
  # pero acá es un script de deploy real corrido por el operador — se usa la
  # fecha del sistema para el registro de auditoría.
  local now; now="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
  cat > "$MANIFEST" <<EOF
{
  "image": "$IMAGE",
  "image_id": "$id",
  "git_commit": "$commit",
  "git_dirty": $dirty,
  "dockerfile_sha256": "$dockerfile_hash",
  "recorded_at": "$now"
}
EOF
  echo "Attestation escrita en $MANIFEST:"
  cat "$MANIFEST"
  [ "$dirty" = true ] && echo "AVISO: el repo tenía cambios sin commitear al grabar (git_dirty=true) — la imagen no es reproducible desde el commit solo."
}

cmd_verify() {
  need_docker
  [ -f "$MANIFEST" ] || { echo "no hay manifiesto ($MANIFEST). Corré '$0 record' primero." >&2; exit 1; }
  local want_id want_commit
  want_id="$(grep -o '"image_id":[^,]*' "$MANIFEST" | cut -d'"' -f4)"
  want_commit="$(grep -o '"git_commit":[^,]*' "$MANIFEST" | cut -d'"' -f4)"
  local rc=0

  echo "== Verificando la imagen local =="
  local have_id; have_id="$(image_id)"
  if [ -z "$have_id" ]; then
    echo "  ✗ la imagen $IMAGE no existe localmente"; rc=1
  elif [ "$have_id" = "$want_id" ]; then
    echo "  ✓ imagen local == atestada ($have_id)"
  else
    echo "  ✗ imagen local DIFIERE de la atestada"; echo "     atestada: $want_id"; echo "     local:    $have_id"; rc=1
  fi

  local now_commit; now_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ "$now_commit" != "$want_commit" ]; then
    echo "  ⚠ el repo está en un commit distinto al atestado (atestado $want_commit, actual $now_commit) — reconstruí + record si actualizaste."
  fi

  echo "== Verificando los contenedores en ejecución =="
  local any=0
  for c in "${CONTAINERS[@]}"; do
    local cid; cid="$(docker inspect "$c" --format '{{.Image}}' 2>/dev/null || true)"
    [ -z "$cid" ] && continue
    any=1
    if [ "$cid" = "$want_id" ]; then
      echo "  ✓ $c usa la imagen atestada"
    else
      echo "  ✗ $c usa OTRA imagen ($cid) — reiniciá el servicio para tomar la imagen atestada"; rc=1
    fi
  done
  [ "$any" -eq 0 ] && echo "  (ningún contenedor qchain en ejecución)"

  echo
  if [ "$rc" -eq 0 ]; then echo "OK: todo coincide con la attestation."; else echo "FALLO: hay diferencias con la attestation (exit $rc)."; fi
  # Un rc!=0 aquí es un RESULTADO esperado (drift detectado), no un error del
  # script — se limpia el trap ERR para no imprimir un falso "ERROR en la línea".
  trap - ERR
  exit "$rc"
}

case "${1:-}" in
  record) cmd_record ;;
  verify) cmd_verify ;;
  show) cat "$MANIFEST" 2>/dev/null || { echo "no hay manifiesto ($MANIFEST)." >&2; exit 1; } ;;
  *) echo "uso: $0 {record|verify|show}"; echo "  record  graba la imagen desplegada + commit git + hash del Dockerfile"; echo "  verify  confirma que la imagen local y los contenedores corriendo == la atestada"; echo "  show    imprime el manifiesto"; exit 1 ;;
esac
