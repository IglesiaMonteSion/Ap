#!/usr/bin/env bash
# reproducible-build.sh — build the qchain release binaries reproducibly and
# emit SHA256SUMS (roadmap #9).
#
# Two modes:
#   (default, --host)  build directly on THIS host, sourcing reproducible-env.sh
#                      so the embedded paths are remapped to canonical
#                      placeholders. Fast when the toolchain is already set up.
#   --docker           build inside the fully hermetic Dockerfile.reproducible
#                      (pinned base, pinned clang/cmake for liboqs, fixed paths).
#                      This is the CANONICAL builder — its output is what a
#                      published release should match. Requires a Docker daemon.
#
# Any independent party runs this on the SAME git commit and gets the SAME
# SHA256SUMS. Compare against a published SHA256SUMS / provenance to confirm the
# published binaries genuinely come from this source (see verify-reproducible.sh).
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$HERE/.." && pwd -P)"
MODE="host"
OUT="$ROOT/reproducible-out"

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE="docker" ;;
    --host)   MODE="host" ;;
    --out)    OUT="$2"; shift ;;
    -h|--help)
      echo "Usage: reproducible-build.sh [--host|--docker] [--out DIR]"
      echo "  --host    build on this host (source reproducible-env.sh)"
      echo "  --docker  build in the hermetic Dockerfile.reproducible (canonical)"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
  shift
done

mkdir -p "$OUT"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "== reproducible-build ($MODE) =="
echo "commit: $COMMIT"

if [ "$MODE" = "docker" ]; then
  : "${DOCKER_BUILDKIT:=1}"; export DOCKER_BUILDKIT
  IMG="qchain-reproducible:${COMMIT:0:12}"
  echo "building hermetic image $IMG ..."
  # The reproducible stage writes /out/{bins,SHA256SUMS}; we extract with a
  # throwaway container (BuildKit cache mounts don't survive to a later COPY).
  docker build -f "$ROOT/Dockerfile.reproducible" -t "$IMG" "$ROOT"
  cid="$(docker create "$IMG")"
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  for b in qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer; do
    docker cp "$cid:/out/$b" "$OUT/$b"
  done
else
  # Host build: source the shared env (remap + SOURCE_DATE_EPOCH), build --locked.
  # shellcheck source=/dev/null
  . "$HERE/reproducible-env.sh"
  ( cd "$ROOT" && cargo build --locked --release $QCHAIN_RELEASE_PKGS )
  for b in $QCHAIN_RELEASE_BINS; do
    cp "$ROOT/target/release/$b" "$OUT/$b"
  done
fi

# Deterministic SHA256SUMS: fixed binary order, basenames only.
( cd "$OUT" && sha256sum qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer > SHA256SUMS )
echo
echo "== SHA256SUMS ($OUT/SHA256SUMS) =="
cat "$OUT/SHA256SUMS"
echo
echo "These hashes are reproducible: a different builder of commit $COMMIT (host"
echo "or --docker) that pins the same toolchain (rust-toolchain.toml) + Cargo.lock"
echo "produces byte-identical binaries. Compare with verify-reproducible.sh."
