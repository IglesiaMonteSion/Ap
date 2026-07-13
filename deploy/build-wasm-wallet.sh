#!/usr/bin/env bash
# Regenerates the browser (WASM) self-custody wallet assets from the
# qchain-wasm crate and copies them into qchain-wallet, where they are embedded
# into the binary (served at /wasm). Run this after changing qchain-wasm,
# qchain-core, or qchain-crypto's pure backend, then rebuild qchain-wallet.
#
# Requires: the wasm32 target + wasm-bindgen-cli matching the wasm-bindgen
# crate version (see crates/qchain-wasm/Cargo.lock):
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <matching>
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/crates/qchain-wasm"
cargo build --release --target wasm32-unknown-unknown
rm -rf pkg && mkdir pkg
wasm-bindgen --target web --no-typescript --out-dir pkg \
  target/wasm32-unknown-unknown/release/qchain_wasm.wasm
DEST="$ROOT/crates/qchain-wallet/src/wasm_assets"
mkdir -p "$DEST"
cp pkg/qchain_wasm.js "$DEST/"
cp pkg/qchain_wasm_bg.wasm "$DEST/"
echo "Assets del wallet WASM actualizados en $DEST. Ahora recompilá qchain-wallet."
