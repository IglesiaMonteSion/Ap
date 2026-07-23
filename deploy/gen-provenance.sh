#!/usr/bin/env bash
# Provenance de la cadena de construcción (tarea de release-verify). Emite UN
# archivo `provenance.json` DETERMINISTA que RELACIONA, sobre el MISMO commit:
#
#     commit  ->  version  ->  binarios  ->  imagen de despliegue  ->  wasm de la wallet
#
# Es el eslabón que faltaba: sign-release.sh ya firmaba un manifiesto con
# version/commit/Cargo.lock/Dockerfile/SBOM/wallet-assets, pero NO ataba los
# HASHES de los BINARIOS de release ni el DIGEST de la IMAGEN docker. Este script
# junta TODO en un solo objeto verificable (estilo SLSA), para que un operador
# confirme que el binario que corre, la imagen que despliega y el JS/WASM que su
# navegador ejecuta salieron TODOS del commit firmado.
#
# DETERMINISTA: JSON con claves ordenadas, sin timestamp de reloj (usa
# SOURCE_DATE_EPOCH si está seteado, si no lo omite) → dos corridas sobre los
# MISMOS bits producen un archivo byte-idéntico (parte de la reproducibilidad).
#
#   deploy/gen-provenance.sh [--bin-dir <dir>] [--image <ref>] [-o <salida>]
#
#   --bin-dir   dónde están los binarios de release (default: target/release).
#               Un binario ausente se registra como null (así corre localmente
#               sin un build de release completo); un release real los tiene todos.
#   --image     referencia de la imagen docker ya construida (ej. qchain:latest).
#               Si se pasa y hay docker, agrega su Id y RepoDigests. Omitir = null.
#   -o          archivo de salida (default: stdout).
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN_DIR="target/release"
IMAGE=""
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --image)   IMAGE="$2"; shift 2 ;;
    -o)        OUT="$2"; shift 2 ;;
    -h|--help) echo "uso: $0 [--bin-dir <dir>] [--image <ref>] [-o <salida>]"; exit 0 ;;
    *) echo "argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 requerido" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum requerido" >&2; exit 1; }

VERSION="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
COMMIT_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY="false"
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then DIRTY="true"; fi
TOOLCHAIN="$(grep -m1 '^channel = ' rust-toolchain.toml | sed -E 's/.*"([^"]+)".*/\1/')"

# Los 7 binarios que el Dockerfile compila y copia a la imagen.
BINARIES=(qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer)

# Imagen docker (opcional).
IMG_ID=""; IMG_DIGESTS=""
if [ -n "$IMAGE" ] && command -v docker >/dev/null 2>&1; then
  IMG_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)"
  IMG_DIGESTS="$(docker image inspect --format '{{join .RepoDigests ","}}' "$IMAGE" 2>/dev/null || true)"
fi

# SBOM: generarlo a un temp determinista y hashearlo (el SBOM en sí ya es
# determinista desde el Cargo.lock).
SBOM_TMP="$(mktemp)"; trap 'rm -f "$SBOM_TMP"' EXIT
bash deploy/gen-sbom.sh -o "$SBOM_TMP" >/dev/null 2>&1 || true
SBOM_SHA="$(sha256sum "$SBOM_TMP" 2>/dev/null | awk '{print $1}')"

# Assets de la wallet: reusar el manifiesto determinista existente.
WALLET_MAN="$(bash deploy/wallet-asset-manifest.sh 2>/dev/null || true)"

sha_of() { [ -f "$1" ] && sha256sum "$1" | awk '{print $1}' || echo ""; }

# Exportamos todo a python vía env para producir JSON canónico (claves ordenadas).
export P_VERSION="$VERSION" P_COMMIT="$COMMIT" P_COMMIT_SHORT="$COMMIT_SHORT"
export P_DIRTY="$DIRTY" P_TOOLCHAIN="$TOOLCHAIN" P_SDE="${SOURCE_DATE_EPOCH:-}"
export P_IMAGE="$IMAGE" P_IMG_ID="$IMG_ID" P_IMG_DIGESTS="$IMG_DIGESTS"
export P_SBOM_SHA="$SBOM_SHA" P_WALLET_MAN="$WALLET_MAN"
export P_LOCK_SHA="$(sha_of Cargo.lock)"
export P_DOCKERFILE_SHA="$(sha_of Dockerfile)"
export P_TOOLCHAIN_SHA="$(sha_of rust-toolchain.toml)"
export P_HTML_SHA="$(sha_of crates/qchain-wallet/src/wasm_wallet.html)"

BIN_KV=""
for b in "${BINARIES[@]}"; do
  s="$(sha_of "$BIN_DIR/$b")"
  BIN_KV+="$b=$s"$'\n'
done
export P_BIN_KV="$BIN_KV"

python3 - <<'PY' > "${OUT:-/dev/stdout}"
import os, json

def orNone(v): return v if v else None

# binarios: {nombre: sha256|null}
binaries = {}
for line in os.environ.get("P_BIN_KV","").splitlines():
    if not line.strip(): continue
    name, _, sha = line.partition("=")
    binaries[name] = orNone(sha)

# wallet assets: parsear las líneas "name sha256 sri" del manifiesto determinista
wallet = {}
for line in os.environ.get("P_WALLET_MAN","").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("qchain wallet"): continue
    parts = line.split()
    if len(parts) >= 3 and len(parts[1]) == 64:
        wallet[parts[0]] = {"sha256": parts[1], "sri": parts[2]}

digests = [d for d in os.environ.get("P_IMG_DIGESTS","").split(",") if d]

prov = {
    "_type": "qchain-provenance/v1",
    "commit": os.environ["P_COMMIT"],
    "commit_short": os.environ["P_COMMIT_SHORT"],
    "source_dirty": os.environ["P_DIRTY"] == "true",
    "version": os.environ["P_VERSION"],
    "toolchain": os.environ["P_TOOLCHAIN"],
    "source": {
        "Cargo.lock": orNone(os.environ.get("P_LOCK_SHA")),
        "Dockerfile": orNone(os.environ.get("P_DOCKERFILE_SHA")),
        "rust-toolchain.toml": orNone(os.environ.get("P_TOOLCHAIN_SHA")),
    },
    "binaries": binaries,
    "deploy_image": {
        "ref": orNone(os.environ.get("P_IMAGE")),
        "id": orNone(os.environ.get("P_IMG_ID")),
        "repo_digests": digests or None,
    },
    "wallet_assets": {
        **({"wasm_wallet.html": {"sha256": os.environ["P_HTML_SHA"]}} if os.environ.get("P_HTML_SHA") else {}),
        **wallet,
    },
    "sbom_sha256": orNone(os.environ.get("P_SBOM_SHA")),
}
sde = os.environ.get("P_SDE")
if sde:
    prov["source_date_epoch"] = int(sde)

# JSON canónico: claves ordenadas, sin espacios variables → determinista.
print(json.dumps(prov, sort_keys=True, indent=2))
PY
