#!/usr/bin/env bash
# reproducible-env.sh — shared reproducible-build environment (roadmap #9).
#
# SOURCE this file (`. deploy/reproducible-env.sh`) before a release build so the
# artifact bytes are INDEPENDENT of WHERE it was built. It exports the exact
# RUSTFLAGS + SOURCE_DATE_EPOCH that every reproducible-build path uses
# (Dockerfile.reproducible, deploy/reproducible-build.sh, the CI `reproducible`
# job, release.yml), so two DIFFERENT builders — different checkout dir,
# different $HOME/$CARGO_HOME, different machine — remap their env-specific
# absolute paths to the SAME canonical placeholders and produce BYTE-IDENTICAL
# binaries.
#
# WHY THIS IS NEEDED (measured): a plain `cargo build --release` embeds ~4400
# absolute paths into the binary — every dependency's
# `$CARGO_HOME/registry/src/.../crate-x.y.z/...` path (via `file!()`/panic
# locations + debug info) and every local crate's `<workspace>/crates/.../src`
# path. Those paths differ per builder, so two honest builders of the SAME
# commit get DIFFERENT sha256 — the build is not reproducible cross-host. The
# committed Cargo.lock + `--locked` + the pinned rust-toolchain.toml already fix
# the toolchain and every dependency VERSION; this file fixes the last input:
# the embedded PATHS.
#
# It ONLY affects the strings shown in a panic backtrace / debug info (they read
# `/qchain-src/...` and `/cargo-registry/...` instead of the real host paths).
# It NEVER changes program logic, consensus, wire, or state — the runtime is
# byte-for-byte identical in behavior, only the artifact bytes become
# deterministic. This is why it is applied to the RELEASE/reproducible artifact
# path, not to normal local dev builds (which stay exactly as they are).

# Canonical placeholders every builder remaps to (fixed strings — do NOT change
# without re-baselining the published hashes; changing them changes every hash).
QCHAIN_SRC_PLACEHOLDER="/qchain-src"
QCHAIN_REGISTRY_PLACEHOLDER="/cargo-registry"

# A fixed epoch for any timestamp the toolchain might embed. Arbitrary but must
# be identical across builders. (2023-11-14T22:13:20Z.)
: "${SOURCE_DATE_EPOCH:=1700000000}"
export SOURCE_DATE_EPOCH

# The workspace root = the directory this script lives in, minus /deploy.
_re_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
QCHAIN_WORKSPACE="$(cd "${_re_self}/.." && pwd -P)"

# CARGO_HOME the way cargo actually sees it (this is the literal string cargo
# embeds — must remap the literal value, NOT its realpath, or the prefix won't
# match; verified: a symlinked CARGO_HOME leaks the symlink path, not the
# resolved one).
_re_cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# Two remaps: the dependency registry, and the local workspace. Order matters
# only in that both prefixes are disjoint here.
export RUSTFLAGS="--remap-path-prefix=${_re_cargo_home}/registry=${QCHAIN_REGISTRY_PLACEHOLDER} --remap-path-prefix=${QCHAIN_WORKSPACE}=${QCHAIN_SRC_PLACEHOLDER}${RUSTFLAGS:+ $RUSTFLAGS}"

# The 7 release binaries, in a fixed order (used by the build + verify scripts).
QCHAIN_RELEASE_BINS="qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer"

# The packages to build (some binaries live in the same crate).
QCHAIN_RELEASE_PKGS="-p qchain-node -p qchain-cli -p qchain-faucet -p qchain-wallet -p qchain-indexer -p qchain-remote-signer"

export QCHAIN_SRC_PLACEHOLDER QCHAIN_REGISTRY_PLACEHOLDER QCHAIN_WORKSPACE QCHAIN_RELEASE_BINS QCHAIN_RELEASE_PKGS

if [ "${QCHAIN_REPRO_QUIET:-0}" != "1" ]; then
  echo "reproducible-env: SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
  echo "reproducible-env: remap ${_re_cargo_home}/registry -> ${QCHAIN_REGISTRY_PLACEHOLDER}"
  echo "reproducible-env: remap ${QCHAIN_WORKSPACE} -> ${QCHAIN_SRC_PLACEHOLDER}"
fi
