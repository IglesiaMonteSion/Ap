#!/usr/bin/env bash
# Genera un SBOM (Software Bill of Materials) en formato CycloneDX desde el
# Cargo.lock del workspace (tarea #198, QCH-S11). Un SBOM lista TODA dependencia
# transitiva con su versión exacta y checksum — el inventario que hace falta para
# responder "¿usa qchain la crate X afectada por el aviso Y?" sin adivinar, y para
# auditar la cadena de suministro. Es DETERMINISTA (deriva solo del Cargo.lock,
# ordenado), así que dos corridas del mismo lock producen el mismo archivo.
#
# No necesita ninguna herramienta externa (parsea el Cargo.lock con python3), así
# que corre en cualquier host y en CI sin instalar cargo-cyclonedx. Salida a
# stdout o al archivo de `-o`.
#
#   deploy/gen-sbom.sh [-o sbom.cdx.json]
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/Cargo.lock"
OUT=""
[ "${1:-}" = "-o" ] && OUT="${2:-}"

[ -f "$LOCK" ] || { echo "no se encontró Cargo.lock en $ROOT" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 requerido" >&2; exit 1; }

VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | sed -E 's/version = "([^"]+)"/\1/')"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

python3 - "$LOCK" "$VERSION" "$COMMIT" <<'PY' > "${OUT:-/dev/stdout}"
import sys, json, re
lock_path, version, commit = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(lock_path).read()

# Parse [[package]] blocks from Cargo.lock (TOML-lite; no external dep).
pkgs = []
for block in text.split('[[package]]')[1:]:
    def field(name):
        m = re.search(r'^%s = "([^"]*)"' % name, block, re.M)
        return m.group(1) if m else None
    name = field('name'); ver = field('version')
    if not name or not ver:
        continue
    src = field('source')           # None for local workspace crates
    chk = field('checksum')
    comp = {
        "type": "library",
        "name": name,
        "version": ver,
        "bom-ref": "%s@%s" % (name, ver),
    }
    # purl for registry crates (crates.io); local workspace crates get no purl.
    if src and src.startswith("registry+"):
        comp["purl"] = "pkg:cargo/%s@%s" % (name, ver)
        comp["scope"] = "required"
    if chk:
        comp["hashes"] = [{"alg": "SHA-256", "content": chk}]
    pkgs.append(comp)

# Deterministic order (name, then version) so the SBOM is byte-stable per lock.
pkgs.sort(key=lambda c: (c["name"], c["version"]))

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "qchain",
            "version": version,
            "description": "qchain post-quantum L1 blockchain workspace",
        },
        "properties": [
            {"name": "qchain:git_commit", "value": commit},
            {"name": "qchain:source", "value": "Cargo.lock"},
        ],
    },
    "components": pkgs,
}
# `recorded_at` is deliberately omitted so the file is reproducible from the lock
# alone (a timestamp would make two runs differ). Stamp it externally if needed.
print(json.dumps(sbom, indent=2, sort_keys=False))
PY

if [ -n "$OUT" ]; then
  n="$(grep -c '"bom-ref"' "$OUT" || true)"
  echo "SBOM CycloneDX escrito en $OUT ($n componentes)." >&2
fi
