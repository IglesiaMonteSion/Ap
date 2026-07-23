#!/usr/bin/env bash
# verify-reproducible.sh — independently confirm that published binaries come
# from this source, by REBUILDING them and comparing hashes (roadmap #9).
#
# This is stronger than verify-provenance.sh (which re-hashes binaries you
# already have): here an auditor rebuilds from source with the reproducible
# recipe and checks the result matches a published SHA256SUMS (or the
# provenance's binary hashes). A match proves the published artifact is a
# faithful build of the committed source — no hidden changes in the binary.
#
#   deploy/verify-reproducible.sh --expected published-SHA256SUMS.txt [--docker]
#   deploy/verify-reproducible.sh --provenance provenance.json        [--docker]
#
# Exit 0 = every binary matches. Exit 1 = at least one differs (printed).
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$HERE/.." && pwd -P)"
EXPECTED=""
PROVENANCE=""
BUILD_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --expected)   EXPECTED="$2"; shift ;;
    --provenance) PROVENANCE="$2"; shift ;;
    --docker)     BUILD_ARGS+=(--docker) ;;
    --host)       BUILD_ARGS+=(--host) ;;
    -h|--help)
      echo "Usage: verify-reproducible.sh (--expected SHA256SUMS | --provenance provenance.json) [--host|--docker]"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ -z "$EXPECTED" ] && [ -z "$PROVENANCE" ]; then
  echo "error: pass --expected <SHA256SUMS> or --provenance <provenance.json>" >&2
  exit 1
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "== rebuilding from source (commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo ?)) =="
"$HERE/reproducible-build.sh" "${BUILD_ARGS[@]}" --out "$OUT" >/dev/null
echo "rebuilt. comparing hashes…"

# Build a name->hash map of what we just produced.
declare -A GOT
while read -r h name; do GOT["$name"]="$h"; done < "$OUT/SHA256SUMS"

# Build the expected name->hash map from either source.
declare -A WANT
if [ -n "$EXPECTED" ]; then
  while read -r h name; do
    name="${name#\*}"; name="$(basename "$name")"
    [ -n "$name" ] && WANT["$name"]="$h"
  done < "$EXPECTED"
else
  # Pull the binary hashes out of provenance.json without a JSON dep: match
  # lines like  "qchain-node": "sha256hex"  under a binaries object.
  while IFS= read -r line; do
    n="$(printf '%s' "$line" | sed -nE 's/.*"(qchain[a-z-]*)"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})".*/\1/p')"
    v="$(printf '%s' "$line" | sed -nE 's/.*"(qchain[a-z-]*)"[[:space:]]*:[[:space:]]*"([0-9a-f]{64})".*/\2/p')"
    [ -n "$n" ] && [ -n "$v" ] && WANT["$n"]="$v"
  done < "$PROVENANCE"
fi

if [ "${#WANT[@]}" -eq 0 ]; then
  echo "error: could not read any expected binary hashes from the given file" >&2
  exit 1
fi

fail=0
checked=0
for name in qchain-node qchain-genesis-build qchain qchain-faucet qchain-wallet qchain-indexer qchain-remote-signer; do
  want="${WANT[$name]:-}"
  got="${GOT[$name]:-}"
  [ -z "$want" ] && continue   # published set may omit some binaries
  checked=$((checked+1))
  if [ "$want" = "$got" ]; then
    echo "  OK    $name  $got"
  else
    echo "  DIFF  $name  rebuilt=$got  published=$want"
    fail=1
  fi
done

echo
if [ "$fail" -eq 0 ] && [ "$checked" -gt 0 ]; then
  echo "== MATCH — the published binaries reproduce from this source ($checked checked). =="
  exit 0
fi
if [ "$checked" -eq 0 ]; then
  echo "error: none of the expected names matched a qchain binary" >&2
  exit 1
fi
echo "== MISMATCH — at least one published binary does NOT come from this source. =="
echo "Do NOT trust the published binaries: rebuild and investigate."
exit 1
