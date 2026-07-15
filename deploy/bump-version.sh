#!/usr/bin/env bash
# Safe version bump for the qchain workspace.
#
# WHY THIS EXISTS: bumping the version by `sed`-ing Cargo.lock directly is
# dangerous — a `sed 's/^version = "X"$/version = "Y"/'` matches ANY package at
# version X, and a third-party dependency can legitimately share the old
# workspace version (this bit us once: `curve25519-dalek` was at 4.1.3, the same
# as the old workspace version, so a lock `sed` bumped it to a nonexistent 4.1.4
# and every Docker build failed to resolve it — see the v4.1.6 note in CLAUDE.md).
#
# The correct way, done here: edit ONLY Cargo.toml's `[workspace.package]`
# version, then let CARGO sync the lock (`cargo update --workspace` rewrites only
# the workspace members' entries, never a dependency's), then VERIFY the lock is
# self-consistent with `cargo build --locked` before you commit.
#
# Usage:  deploy/bump-version.sh <new-version>       # e.g. deploy/bump-version.sh 4.1.6
set -Eeuo pipefail

NEW="${1:-}"
if [ -z "$NEW" ]; then echo "uso: $0 <nueva-version>  (ej: 4.1.6)"; exit 1; fi
if ! printf '%s' "$NEW" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "error: la versión debe ser X.Y.Z (recibí '$NEW')"; exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OLD="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
echo "Bump: $OLD -> $NEW"

# 1) Cargo.toml — solo la versión del workspace (primera aparición, línea del
#    [workspace.package]). NO se toca Cargo.lock a mano.
#    Se ancla a la versión vieja exacta para no tocar otras líneas 'version ='.
perl -0pi -e "s/^version = \"\Q$OLD\E\"/version = \"$NEW\"/m" Cargo.toml

# 2) Cargo.lock — lo sincroniza CARGO, no un sed. `--workspace` reescribe solo
#    las entradas de los miembros del workspace (las crates qchain-*), jamás la
#    versión de una dependencia de terceros.
cargo update --workspace >/dev/null 2>&1 || cargo update --workspace

# 3) version.json — solo el campo "version" (el resto lo edita el humano con las notas).
if [ -f version.json ]; then
  perl -0pi -e "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW\"/" version.json
fi

# 4) VERIFICAR que el lock quedó consistente y resuelve — falla ruidoso si no.
echo "Verificando el lock (cargo build --locked)…"
if ! cargo build --locked --offline -p qchain-crypto -p qchain-node >/dev/null 2>&1; then
  # Si el offline falla por falta de cache, reintentar online (aún con --locked).
  cargo build --locked -p qchain-crypto -p qchain-node >/dev/null
fi

# 5) Sanidad final: ninguna crate NO-qchain debe quedar en la versión nueva.
BAD="$(awk -v v="$NEW" '/^name = /{n=$3} $0 == "version = \"" v "\""{print n}' Cargo.lock | grep -v '"qchain' || true)"
if [ -n "$BAD" ]; then
  echo "ERROR: una dependencia NO-qchain quedó en $NEW: $BAD"
  echo "Revertí y revisá a mano — NO commitees este lock."
  exit 1
fi

echo "OK. Cargo.toml, Cargo.lock y version.json en $NEW; lock verificado."
echo "Ahora: editá las notas de version.json + CLAUDE.md y commiteá."
