#!/usr/bin/env bash
# Regenerates the browser (WASM) self-custody wallet assets from the
# qchain-wasm crate and copies them into qchain-wallet, where they are embedded
# into the binary (served at /wasm). Run this after changing qchain-wasm,
# qchain-core, or qchain-crypto's pure backend, then rebuild qchain-wallet.
#
# Requires: the wasm32 target + wasm-bindgen-cli matching the wasm-bindgen
# crate version (see crates/qchain-wasm/Cargo.lock), y opcionalmente binaryen
# (wasm-opt) para achicar el binario:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <matching>
#   apt-get install binaryen   # (o brew install binaryen) - opcional pero recomendado
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/crates/qchain-wasm"
cargo build --release --target wasm32-unknown-unknown
rm -rf pkg && mkdir pkg
wasm-bindgen --target web --no-typescript --out-dir pkg \
  target/wasm32-unknown-unknown/release/qchain_wasm.wasm

# Achicar el .wasm con wasm-opt (binaryen) si está disponible. -Oz optimiza para
# TAMAÑO. Hay que habilitar explícitamente las features que emite rustc moderno
# (sign-ext, bulk-memory, etc.) o binaryen viejo rechaza el módulo. Reduce el
# binario ~35% (310KB -> ~193KB) sin cambiar el comportamiento (verificado en
# Chromium: misma dirección y firma válida byte-a-byte que el binario nativo).
WASM="pkg/qchain_wasm_bg.wasm"
if command -v wasm-opt >/dev/null 2>&1; then
  BEFORE=$(wc -c < "$WASM")
  wasm-opt -Oz --converge \
    --enable-sign-ext --enable-bulk-memory --enable-mutable-globals \
    --enable-nontrapping-float-to-int --enable-simd --enable-reference-types \
    "$WASM" -o "$WASM.opt"
  mv "$WASM.opt" "$WASM"
  AFTER=$(wc -c < "$WASM")
  echo "wasm-opt: $BEFORE -> $AFTER bytes"
else
  echo "AVISO: wasm-opt no está instalado (apt-get install binaryen) - el .wasm queda sin comprimir."
fi

DEST="$ROOT/crates/qchain-wallet/src/wasm_assets"
mkdir -p "$DEST"
cp pkg/qchain_wasm.js "$DEST/"
cp "$WASM" "$DEST/qchain_wasm_bg.wasm"
echo "Assets del wallet WASM actualizados en $DEST. Ahora recompilá qchain-wallet."
