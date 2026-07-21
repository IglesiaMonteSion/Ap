#!/usr/bin/env bash
# Compila un contrato de Qchain (escrito con qchain-sdk) a un .wasm listo para
# desplegar con `qchain deploy-program` o el panel "Contratos" de QScan.
#
#   deploy/build-contract.sh <carpeta-del-contrato>
#   deploy/build-contract.sh crates/qchain-sdk/templates/payments
#
# Requiere: el target wasm32-unknown-unknown (rustup target add wasm32-unknown-unknown)
# y, opcional, binaryen (wasm-opt) para achicar el binario.
set -Eeuo pipefail

DIR="${1:-}"
if [ -z "$DIR" ] || [ ! -f "$DIR/Cargo.toml" ]; then
  echo "uso: $0 <carpeta-del-contrato>  (una carpeta con su Cargo.toml)"; exit 1
fi
DIR="$(cd "$DIR" && pwd)"
NAME="$(grep -m1 '^name' "$DIR/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"

if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
  echo "Falta el target wasm32. Instalalo con:  rustup target add wasm32-unknown-unknown"; exit 1
fi

echo "==> Compilando '$NAME' a wasm32 (release)…"
( cd "$DIR" && cargo build --release --target wasm32-unknown-unknown )

WASM="$DIR/target/wasm32-unknown-unknown/release/${NAME//-/_}.wasm"
[ -f "$WASM" ] || { echo "no encontré el .wasm en $WASM"; exit 1; }

OUT="$DIR/${NAME}.wasm"
cp "$WASM" "$OUT"

# Achicar con wasm-opt si está (opcional). -Oz optimiza para tamaño.
if command -v wasm-opt >/dev/null 2>&1; then
  BEFORE=$(wc -c < "$OUT")
  wasm-opt -Oz --enable-bulk-memory --enable-sign-ext "$OUT" -o "$OUT.opt" 2>/dev/null && mv "$OUT.opt" "$OUT" || true
  AFTER=$(wc -c < "$OUT")
  echo "==> wasm-opt: $BEFORE -> $AFTER bytes"
fi

SIZE=$(wc -c < "$OUT")
echo ""
echo "==> LISTO: $OUT  ($SIZE bytes)"
if [ "$SIZE" -gt 262144 ]; then
  echo "    ⚠️  supera el tope de 256 KB de bytecode — no se podrá desplegar."
else
  echo "    Desplegalo:  qchain deploy-program --module '$OUT' --entry-point run ..."
  echo "    o subilo en QScan → Contratos → Desplegar."
fi
