#!/usr/bin/env bash
# Reinicia la testnet local con un GÉNESIS NUEVO que fondea la wallet de prueba
# del nodo (wallet.json) con un balance grande, para poder estresar sin quedarte
# sin QCH.
#
# DESTRUCTIVO: borra el estado on-chain persistido del nodo (data/). Es una red
# de PRUEBA — la cadena arranca desde un génesis nuevo, lo que además cambia el
# chain_id (los clientes lo re-obtienen solos vía GET /chain_id). Las CLAVES
# (keypair.json, wallet.json) y el resto del config se conservan.
#
# Uso:
#   sudo ./deploy/reset-testnet-genesis.sh                # 10.000.000 QCH (default)
#   sudo ./deploy/reset-testnet-genesis.sh 50000000       # 50.000.000 QCH
#   sudo ./deploy/reset-testnet-genesis.sh 10000000 --yes # sin confirmación
set -Eeuo pipefail

AMOUNT_QCH="${1:-10000000}"
YES=0
[ "${2:-}" = "--yes" ] && YES=1
[ "${1:-}" = "--yes" ] && { YES=1; AMOUNT_QCH="10000000"; }

QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
CONFIG="$QCHAIN_HOME/config.json"
IMAGE="${QCHAIN_IMAGE:-qchain:latest}"
SERVICE="${QCHAIN_SERVICE:-qchain-validator}"
RPC="${QCHAIN_RPC:-http://127.0.0.1:8080}"
DATA_DIR="$QCHAIN_HOME/data"

command -v docker >/dev/null || { echo "ERROR: docker no encontrado"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 no encontrado"; exit 1; }
[ -f "$CONFIG" ] || { echo "ERROR: no existe $CONFIG"; exit 1; }
[ -f "$QCHAIN_HOME/wallet.json" ] || { echo "ERROR: no existe $QCHAIN_HOME/wallet.json"; exit 1; }
case "$AMOUNT_QCH" in ''|*[!0-9]*) echo "ERROR: el monto '$AMOUNT_QCH' no es un entero de QCH"; exit 1;; esac

WADDR=$(docker run --rm -v "$QCHAIN_HOME":/qchain "$IMAGE" qchain address --keypair /qchain/wallet.json)
echo "wallet de prueba: $WADDR"
echo "nuevo génesis:    $AMOUNT_QCH QCH para esa wallet"
echo "servicio:         $SERVICE      data: $DATA_DIR"
echo

if [ "$YES" -ne 1 ]; then
  echo "Esto BORRA el estado actual de la red y la reinicia desde cero con el"
  echo "génesis nuevo (cambia el chain_id). Tus claves y tu config se conservan."
  read -rp "Escribí SI para continuar: " ok
  [ "$ok" = "SI" ] || { echo "cancelado."; exit 1; }
fi

STAMP=$(date +%s 2>/dev/null || echo backup)
cp "$CONFIG" "$CONFIG.bak.$STAMP"
echo "backup del config: $CONFIG.bak.$STAMP"

# Reescribe SOLO el campo genesis (preserva validators, puertos, data_dir, etc.).
python3 - "$CONFIG" "$WADDR" "$AMOUNT_QCH" <<'PY'
import json, sys
cfg_path, addr, amt_qch = sys.argv[1], sys.argv[2], int(sys.argv[3])
cfg = json.load(open(cfg_path))
cfg["genesis"] = [{"address": addr, "balance": amt_qch * 1_000_000_000}]
json.dump(cfg, open(cfg_path, "w"), indent=2)
print("génesis reescrito en el config OK")
PY

echo "parando el nodo ($SERVICE)..."
systemctl stop "$SERVICE" 2>/dev/null || true
sleep 2

if [ -d "$DATA_DIR" ]; then
  echo "borrando estado on-chain en $DATA_DIR ..."
  rm -rf "${DATA_DIR:?}/"* "${DATA_DIR:?}/".[!.]* 2>/dev/null || true
else
  echo "aviso: $DATA_DIR no existe; lo creo vacío."
  mkdir -p "$DATA_DIR"
fi

echo "arrancando el nodo con el génesis nuevo..."
systemctl start "$SERVICE"

echo -n "esperando a que levante"
for _ in $(seq 1 20); do
  sleep 1; echo -n "."
  if curl -s "$RPC/status" >/dev/null 2>&1; then break; fi
done
echo

BAL=$(curl -s "$RPC/account/$WADDR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("balance",0)/1e9)' 2>/dev/null || echo "?")
echo
echo "==================================================================="
echo " LISTO. Red reiniciada con génesis nuevo."
echo " wallet de prueba $WADDR"
echo " saldo ahora: $BAL QCH   (esperado: $AMOUNT_QCH QCH)"
echo "==================================================================="
echo "Nota: el chain_id cambió (red nueva). Cualquier wallet/cliente que"
echo "apunte a este nodo re-obtiene el chain_id solo antes de firmar."
