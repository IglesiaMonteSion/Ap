#!/usr/bin/env bash
# Actualiza TODO lo instalado en esta VPS (nodo y, si está, la wallet) con un
# solo comando. Reconstruye la imagen UNA sola vez (no dos): corre el flujo
# completo de update-node.sh (git pull + rebuild + restart del validador +
# health-check) y, si el servicio de la wallet existe, la reinicia contra la
# misma imagen recién construida (sin reconstruir de nuevo) y la chequea.
#
# Uso (desde el repo, en la VPS):
#   sudo ./deploy/update.sh               # git pull + rebuild + restart nodo + wallet
#
# Banderas: se pasan tal cual a update-node.sh: --no-pull --force --rollback --yes/-y --home <dir>
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_SERVICE="qchain-wallet"

decir() { printf '\n==> %s\n' "$1"; }
error() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || error "corré este script como root (sudo ./deploy/update.sh)"

# 1. Nodo (esto ya hace git pull + rebuild de la imagen compartida + restart + health)
decir "Actualizando el nodo (y reconstruyendo la imagen que la wallet también usa)"
"$SCRIPT_DIR/update-node.sh" "$@"

# 2. Wallet, si está instalada — sin reconstruir de nuevo, solo reiniciar contra la imagen ya fresca
if systemctl list-unit-files "$WALLET_SERVICE.service" >/dev/null 2>&1 && systemctl cat "$WALLET_SERVICE" >/dev/null 2>&1; then
  decir "Reiniciando la wallet contra la imagen recién construida (sin reconstruir)"
  systemctl restart "$WALLET_SERVICE"
  WALLET_PORT="$(systemctl show "$WALLET_SERVICE" -p ExecStart --value 2>/dev/null | grep -oP -- '--bind[= ][^ ]*:\K[0-9]+' | head -1 || true)"
  WALLET_PORT="${WALLET_PORT:-8090}"
  OK=0
  for _ in $(seq 1 12); do
    sleep 1
    if systemctl is-active --quiet "$WALLET_SERVICE" && curl -fsSL --max-time 3 "http://127.0.0.1:$WALLET_PORT/" >/dev/null 2>&1; then OK=1; break; fi
  done
  if [ "$OK" -eq 1 ]; then
    echo "Wallet reiniciada y respondiendo en el puerto $WALLET_PORT."
  else
    echo "ADVERTENCIA: la wallet no respondió tras reiniciar. Revisá: journalctl -u $WALLET_SERVICE -e --no-pager"
  fi
else
  decir "No hay servicio de wallet instalado en esta VPS — solo se actualizó el nodo."
fi

# 3. Explorador QScan, si está instalado — mismo patrón (reiniciar contra la imagen ya fresca)
INDEXER_SERVICE="qchain-indexer"
if systemctl list-unit-files "$INDEXER_SERVICE.service" >/dev/null 2>&1 && systemctl cat "$INDEXER_SERVICE" >/dev/null 2>&1; then
  decir "Reiniciando el explorador QScan contra la imagen recién construida (sin reconstruir)"
  systemctl restart "$INDEXER_SERVICE"
  IDX_PORT="$(systemctl show "$INDEXER_SERVICE" -p ExecStart --value 2>/dev/null | grep -oP -- '--bind[= ][^ ]*:\K[0-9]+' | head -1 || true)"
  IDX_PORT="${IDX_PORT:-9200}"
  OK=0
  for _ in $(seq 1 12); do
    sleep 1
    if systemctl is-active --quiet "$INDEXER_SERVICE" && curl -fsSL --max-time 3 "http://127.0.0.1:$IDX_PORT/api/health" >/dev/null 2>&1; then OK=1; break; fi
  done
  if [ "$OK" -eq 1 ]; then
    echo "Explorador QScan reiniciado y respondiendo en el puerto $IDX_PORT."
  else
    echo "ADVERTENCIA: el explorador no respondió tras reiniciar. Revisá: journalctl -u $INDEXER_SERVICE -e --no-pager"
  fi
fi

decir "Todo listo."
