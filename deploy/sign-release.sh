#!/usr/bin/env bash
# Firma una RELEASE de qchain (tarea #198, QCH-S11): produce el SBOM, un
# manifiesto con los hashes de todo lo que se despliega, y firma ese manifiesto
# con GPG (más, opcionalmente, la tag de git). Da a un operador una forma de
# verificar que los bits que corre son los que el maintainer firmó.
#
# REQUIERE la clave GPG del maintainer (esto NO puede firmar por vos — la firma
# es humana). Configurá primero: `git config --global commit.gpgsign true` y
# `git config --global user.signingkey <TU_KEY_ID>` para firmar TODOS los commits;
# esta script firma además el manifiesto de release.
#
#   deploy/sign-release.sh [--key <GPG_KEY_ID>] [--tag vX.Y.Z]
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KEY=""; TAG=""; IMAGE=""; BIN_DIR="target/release"
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    -h|--help) echo "uso: $0 [--key <GPG_KEY_ID>] [--tag vX.Y.Z] [--image <ref>] [--bin-dir <dir>]"; exit 0 ;;
    *) echo "argumento desconocido: $1" >&2; exit 1 ;;
  esac
done

command -v gpg >/dev/null 2>&1 || { echo "gpg no está instalado." >&2; exit 1; }
VERSION="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
OUTDIR="release/$VERSION"
mkdir -p "$OUTDIR"

echo "== SBOM =="
bash deploy/gen-sbom.sh -o "$OUTDIR/sbom.cdx.json"

echo "== Provenance (commit -> version -> binarios -> imagen -> wasm de la wallet) =="
PROVARGS=(--bin-dir "$BIN_DIR" -o "$OUTDIR/provenance.json")
[ -n "$IMAGE" ] && PROVARGS+=(--image "$IMAGE")
bash deploy/gen-provenance.sh "${PROVARGS[@]}"
cat "$OUTDIR/provenance.json"

echo "== Manifiesto de release =="
MAN="$OUTDIR/RELEASE-MANIFEST.txt"
{
  echo "qchain release manifest"
  echo "version: $VERSION"
  echo "git_commit: $COMMIT"
  echo "toolchain: $(grep -m1 '^channel = ' rust-toolchain.toml | sed -E 's/.*"([^"]+)".*/\1/')"
  echo
  echo "# sha256 de los artefactos que se firman con esta release:"
  # El Cargo.lock (deps pinneadas), el Dockerfile (receta de build), el SBOM y
  # la PROVENANCE (que ata commit -> version -> binarios -> imagen -> wasm).
  sha256sum Cargo.lock Dockerfile rust-toolchain.toml "$OUTDIR/sbom.cdx.json" "$OUTDIR/provenance.json" 2>/dev/null || true
  echo
  echo "# sha256 de los BINARIOS de release ($BIN_DIR):"
  for b in qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer; do
    [ -f "$BIN_DIR/$b" ] && sha256sum "$BIN_DIR/$b" || echo "(falta) $b"
  done
  echo
  echo "# huellas de los assets de la WALLET WEB (lo que el navegador ejecuta;"
  echo "# compará contra Ajustes -> 'huella del código' / GET /api/version):"
  bash deploy/wallet-asset-manifest.sh 2>/dev/null || echo "(no se pudo generar el manifiesto de la wallet)"
} > "$MAN"
cat "$MAN"

echo "== Firma GPG del manifiesto =="
GPGARGS=(--armor --detach-sign)
[ -n "$KEY" ] && GPGARGS+=(--local-user "$KEY")
gpg "${GPGARGS[@]}" --output "$MAN.asc" "$MAN"
echo "firma escrita en $MAN.asc"
echo "verificá con: gpg --verify $MAN.asc $MAN"

echo "== Firma GPG de la provenance =="
gpg "${GPGARGS[@]}" --output "$OUTDIR/provenance.json.asc" "$OUTDIR/provenance.json"
echo "firma escrita en $OUTDIR/provenance.json.asc"
echo "verificá con: gpg --verify $OUTDIR/provenance.json.asc $OUTDIR/provenance.json"

if [ -n "$TAG" ]; then
  echo "== Tag firmada $TAG =="
  TAGARGS=(-s -m "qchain $TAG")
  [ -n "$KEY" ] && TAGARGS=(-u "$KEY" -m "qchain $TAG")
  git tag "${TAGARGS[@]}" "$TAG"
  echo "tag firmada creada: $TAG (pushéala con: git push origin $TAG)"
fi

echo
echo "LISTO. Artefactos firmados en $OUTDIR/. Distribuí el manifiesto + su .asc;"
echo "un operador verifica la firma y compara los sha256 con lo que va a desplegar."
