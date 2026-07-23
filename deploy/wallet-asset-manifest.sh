#!/usr/bin/env bash
# Manifiesto DETERMINISTA de los assets servidos por la wallet web no-custodial
# (endurecimiento #214/#216). Emite, por cada archivo que el navegador descarga
# y ejecuta, su SHA-256 (hex) y su SRI (SHA-384 en base64) — EXACTAMENTE los
# valores que la wallet muestra en Ajustes (`/api/version`) y que el `<script>`
# usa como `integrity=`. Sin timestamps ni rutas absolutas → dos corridas sobre
# los mismos bytes dan un archivo byte-idéntico (parte de la reproducibilidad).
#
# Para qué sirve: un usuario/operador compara estos hashes contra los de un
# RELEASE FIRMADO (este manifiesto se incluye en `sign-release.sh` y queda bajo
# la firma GPG del maintainer). Como el SRI servido por el MISMO origen no
# defiende contra un servidor malicioso (que reescribe el `integrity`), la
# defensa real es esta comparación fuera de banda. Ver docs/WALLET-HARDENING.md.
#
#   deploy/wallet-asset-manifest.sh [-o <salida>]   # default: stdout
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="$ROOT/crates/qchain-wallet/src/wasm_assets"
HTML="$ROOT/crates/qchain-wallet/src/wasm_wallet.html"

OUT=""
[ "${1:-}" = "-o" ] && { OUT="$2"; shift 2; }

# Los archivos que el navegador REALMENTE descarga y ejecuta (la superficie que
# toca la semilla). Orden fijo → salida determinista.
FILES=(
  "$HTML"
  "$ASSETS/app.js"
  "$ASSETS/custodial.js"
  "$ASSETS/qchain_wasm.js"
  "$ASSETS/qchain_wasm_bg.wasm"
  "$ASSETS/jsQR.min.js"
)

emit() {
  echo "qchain wallet asset manifest v1"
  echo "# name  sha256(hex)  sri(sha384-b64)"
  for f in "${FILES[@]}"; do
    [ -f "$f" ] || { echo "FALTA: $(basename "$f")" >&2; exit 1; }
    local name s256 s384
    name="$(basename "$f")"
    s256="$(sha256sum "$f" | awk '{print $1}')"
    s384="sha384-$(openssl dgst -sha384 -binary "$f" | base64)"
    printf '%-24s %s  %s\n' "$name" "$s256" "$s384"
  done
}

if [ -n "$OUT" ]; then emit > "$OUT"; echo "manifiesto escrito en $OUT" >&2; else emit; fi
