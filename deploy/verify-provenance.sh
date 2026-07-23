#!/usr/bin/env bash
# Verifica una provenance de qchain (tarea de release-verify). Recomputa, desde
# lo que TENÉS localmente, los hashes de la cadena y los compara contra un
# `provenance.json` FIRMADO — así confirmás, sin confiar en el servidor, que:
#
#     el commit que checkouteaste  ==  la version  ==  los binarios que corrés
#       ==  la imagen que desplegás  ==  el JS/WASM que tu navegador ejecuta
#
# Uso típico (tras `gpg --verify provenance.json.asc provenance.json`):
#   deploy/verify-provenance.sh --provenance provenance.json [--bin-dir target/release] [--image qchain:vX.Y.Z]
#
# Sale 0 si TODO lo presente coincide; !=0 si algo difiere (con el detalle).
# Un campo `null` en la provenance (ej. binario no construido localmente, o
# imagen no cargada) se SALTEA — sólo se comparan los artefactos que tenés.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROV=""; BIN_DIR="target/release"; IMAGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --provenance) PROV="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) echo "uso: $0 --provenance <file> [--bin-dir <dir>] [--image <ref>]"; exit 0 ;;
    *) echo "argumento desconocido: $1" >&2; exit 1 ;;
  esac
done
[ -n "$PROV" ] && [ -f "$PROV" ] || { echo "falta --provenance <provenance.json>" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 requerido" >&2; exit 1; }

FAIL=0
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFALLO\033[0m %s\n' "$1"; FAIL=1; }
skip() { printf '  --   %s (null en la provenance, se saltea)\n' "$1"; }

pj() { python3 -c "import json,sys; d=json.load(open('$PROV')); print(eval(sys.argv[1]))" "$1" 2>/dev/null; }

echo "== Provenance: $PROV =="
echo "commit:  $(pj "d.get('commit')")"
echo "version: $(pj "d.get('version')")"
echo "toolchain: $(pj "d.get('toolchain')")"

# 1) commit: el HEAD local debe ser el de la provenance.
LOCAL_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
PROV_COMMIT="$(pj "d.get('commit')")"
[ "$LOCAL_COMMIT" = "$PROV_COMMIT" ] && ok "commit local == provenance ($PROV_COMMIT)" || bad "commit local ($LOCAL_COMMIT) != provenance ($PROV_COMMIT)"

# 2) version: Cargo.toml debe coincidir.
LOCAL_VER="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
PROV_VER="$(pj "d.get('version')")"
[ "$LOCAL_VER" = "$PROV_VER" ] && ok "version Cargo.toml == provenance ($PROV_VER)" || bad "version local ($LOCAL_VER) != provenance ($PROV_VER)"

# 3) source (Cargo.lock / Dockerfile / rust-toolchain.toml)
echo "-- source --"
for f in Cargo.lock Dockerfile rust-toolchain.toml; do
  want="$(pj "d['source'].get('$f')")"
  [ "$want" = "None" ] && { skip "$f"; continue; }
  have="$(sha256sum "$f" | awk '{print $1}')"
  [ "$have" = "$want" ] && ok "$f" || bad "$f (local $have != prov $want)"
done

# 4) binarios
echo "-- binarios ($BIN_DIR) --"
for b in qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer; do
  want="$(pj "d['binaries'].get('$b')")"
  [ "$want" = "None" ] && { skip "$b"; continue; }
  if [ -f "$BIN_DIR/$b" ]; then
    have="$(sha256sum "$BIN_DIR/$b" | awk '{print $1}')"
    [ "$have" = "$want" ] && ok "$b" || bad "$b (local $have != prov $want)"
  else
    skip "$b (no está en $BIN_DIR)"
  fi
done

# 5) wallet assets (recomputados de los fuentes del repo)
echo "-- wallet assets --"
declare -A WPATH=(
  [wasm_wallet.html]="crates/qchain-wallet/src/wasm_wallet.html"
  [app.js]="crates/qchain-wallet/src/wasm_assets/app.js"
  [custodial.js]="crates/qchain-wallet/src/wasm_assets/custodial.js"
  [qchain_wasm.js]="crates/qchain-wallet/src/wasm_assets/qchain_wasm.js"
  [qchain_wasm_bg.wasm]="crates/qchain-wallet/src/wasm_assets/qchain_wasm_bg.wasm"
  [jsQR.min.js]="crates/qchain-wallet/src/wasm_assets/jsQR.min.js"
)
for name in "${!WPATH[@]}"; do
  want="$(pj "d['wallet_assets'].get('$name',{}).get('sha256')")"
  [ "$want" = "None" ] && continue
  p="${WPATH[$name]}"
  if [ -f "$p" ]; then
    have="$(sha256sum "$p" | awk '{print $1}')"
    [ "$have" = "$want" ] && ok "wallet/$name" || bad "wallet/$name (local $have != prov $want)"
  else
    skip "wallet/$name (no está en el repo)"
  fi
done

# 6) imagen de despliegue (opcional)
echo "-- imagen de despliegue --"
PROV_IMG_ID="$(pj "d['deploy_image'].get('id')")"
if [ "$PROV_IMG_ID" = "None" ]; then
  skip "deploy_image (null en la provenance)"
elif [ -n "$IMAGE" ] && command -v docker >/dev/null 2>&1; then
  have="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || echo none)"
  [ "$have" = "$PROV_IMG_ID" ] && ok "imagen $IMAGE id == provenance" || bad "imagen $IMAGE id ($have) != provenance ($PROV_IMG_ID)"
else
  skip "deploy_image (pasá --image <ref> y tené docker para verificarla)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo -e "\033[32mVERIFICACIÓN OK\033[0m — todo lo presente coincide con la provenance firmada."
else
  echo -e "\033[31mVERIFICACIÓN FALLÓ\033[0m — al menos un artefacto NO coincide (ver arriba)."
fi
exit "$FAIL"
