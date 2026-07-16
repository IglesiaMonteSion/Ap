#!/usr/bin/env bash
# run-stress.sh — despliega y corre el bot de estrés `qchain stress` contra el
# nodo local, usando la misma imagen Docker `qchain:latest` que ya sirve el
# validador (no compila nada: usa el binario `qchain` horneado en la imagen).
#
# Uso rápido (flood de 50k, ninguna tx se pierde por fee — quedan en cola):
#   sudo ./deploy/run-stress.sh
#
# Con opciones:
#   ./deploy/run-stress.sh --keypair ~/banco.json --rpc http://127.0.0.1:8080 \
#       -- --fire-and-forget --queue-target 50000 --workers 32
#
# Todo lo que va después de `--` se pasa TAL CUAL a `qchain stress`.
set -Eeuo pipefail

IMAGE="${QCHAIN_IMAGE:-qchain:latest}"
KEYPAIR="${KEYPAIR:-$HOME/banco.json}"   # la wallet de prueba con fondos (el "banco")
RPC="${RPC:-http://127.0.0.1:8080}"      # RPC del nodo local

# --- parseo de flags propios (antes del `--`) ---
PASSTHRU=()
while [ $# -gt 0 ]; do
  case "$1" in
    --keypair) KEYPAIR="$2"; shift 2;;
    --rpc)     RPC="$2"; shift 2;;
    --image)   IMAGE="$2"; shift 2;;
    --)        shift; PASSTHRU=("$@"); break;;
    *)         PASSTHRU+=("$1"); shift;;
  esac
done

# defaults del flood si no se pasó nada
if [ ${#PASSTHRU[@]} -eq 0 ]; then
  PASSTHRU=(--fire-and-forget --queue-target 50000 --workers 32)
fi

if [ ! -f "$KEYPAIR" ]; then
  echo "ERROR: no encuentro el keypair del banco en: $KEYPAIR" >&2
  echo "       Pasá --keypair <ruta> o exportá KEYPAIR=<ruta>." >&2
  exit 1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "ERROR: la imagen $IMAGE no existe. Actualizá primero:" >&2
  echo "       cd \$HOME/qchain && git pull && sudo ./deploy/update-node.sh" >&2
  exit 1
fi

KP_DIR="$(cd "$(dirname "$KEYPAIR")" && pwd)"
KP_FILE="$(basename "$KEYPAIR")"

echo "== qchain stress =="
echo "  imagen : $IMAGE"
echo "  banco  : $KEYPAIR"
echo "  rpc    : $RPC"
echo "  args   : ${PASSTHRU[*]}"
echo

# --network host: 127.0.0.1 del contenedor == el host, así llega al RPC local.
exec docker run --rm --network host \
  -v "$KP_DIR:/keys:ro" \
  "$IMAGE" \
  qchain stress \
    --rpc "$RPC" \
    --keypair "/keys/$KP_FILE" \
    --monitor "$RPC" \
    "${PASSTHRU[@]}"
