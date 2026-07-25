#!/usr/bin/env bash
# mainnet-gate.sh — EL GATE INDEPENDIENTE SOBRE EL COMMIT FINAL (pre-mainnet #3).
#
# QUÉ PROBLEMA REAL CIERRA
# ------------------------
# El repo ya tenía CI, pero repartido y NO atado al commit que se lanza:
#   · `ci.yml` corre build/clippy/tests/audit/sbom en CADA push — pero los jobs
#     PESADOS (fuzz, sanitizers, reproducible cross-builder) están gateados a
#     `schedule || workflow_dispatch`, así que corren sobre el HEAD que hubiera a
#     las 04:00 UTC — NO necesariamente sobre el commit que se va a lanzar.
#   · `release.yml` tiene un `gate` sobre el commit tagueado, pero es un
#     SUBCONJUNTO (build/clippy/tests/audit). Su job `provenance` publica hashes
#     y su propio comentario afirma que "los binarios PUBLICADOS son exactamente
#     los que reproduce el job `reproducible` del CI" — pero NADA obliga a que
#     ese job haya corrido sobre ESTE commit. Una afirmación en un comentario no
#     es un gate.
#   · `qsep-sweep.sh` (obligatorio por QSEP-1 en todo cambio R2/R3 y al cerrar
#     una auditoría) NUNCA corría en CI.
#   · Los harness adversariales EN VIVO (`chaos-test.sh`, `byzantine-injector.sh`,
#     `km-lifecycle-test.sh`) NUNCA corrían en CI: el arsenal no estaba atado a
#     ningún commit.
#
# QUÉ ES ESTE SCRIPT
# ------------------
# Una sola orden que corre el ARSENAL COMPLETO sobre el checkout actual y emite
# un REPORTE DETERMINISTA. Lo puede correr CUALQUIERA (no sólo GitHub): esa es
# la parte "INDEPENDIENTE" — un tercero lo corre sobre el mismo commit y
# COMPARA UN SOLO HASH con el que publicó el equipo. Si coinciden, ambos
# verificaron los mismos bytes con el mismo arsenal.
#
# EL REPORTE ES REPRODUCIBLE A PROPÓSITO: claves ordenadas, sin reloj dentro del
# objeto hasheado, y con el sha256 de cada binario de release (que ES
# reproducible cross-builder gracias a `reproducible-env.sh`). Dos verificadores
# independientes sobre el MISMO commit obtienen el MISMO `report_hash`.
# El toolchain (rustc -V) va DENTRO del objeto hasheado a propósito: determina
# los bytes, así que si dos reportes difieren, el reporte mismo dice por qué en
# vez de volverlo un misterio.
#
# LA PROPIEDAD QUE LE DA DIENTES
# ------------------------------
#   Un chequeo OBLIGATORIO que se SALTEA **NO** es un PASS.
# El veredicto es PASS sólo si TODOS los obligatorios están en `pass`. Si alguno
# falló → FAIL (exit 1). Si alguno se salteó (herramienta ausente, `--skip-*`)
# → INCOMPLETE (exit 2), NUNCA 0. Un gate que "pasa" salteando la mitad sería
# exactamente la mentira que este archivo existe para impedir.
#
# Uso:
#   deploy/mainnet-gate.sh [--out report.json] [--skip-live] [--skip-reproducible]
#                          [--skip-sdk] [--allow-dirty] [--list]
#
# Exit: 0 = PASS · 1 = FAIL · 2 = INCOMPLETE (nada rojo, pero no se verificó todo)
set -Eeuo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"

OUT="mainnet-gate-report.json"
SKIP_LIVE=0; SKIP_REPRO=0; SKIP_SDK=0; ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2;;
    --skip-live) SKIP_LIVE=1; shift;;
    --skip-reproducible) SKIP_REPRO=1; shift;;
    --skip-sdk) SKIP_SDK=1; shift;;
    --allow-dirty) ALLOW_DIRTY=1; shift;;
    --list) sed -n '/^# CHEQUEOS/,/^# FIN CHEQUEOS/p' "$0" | sed 's/^# \?//'; exit 0;;
    -h|--help) sed -n '1,60p' "$0" | sed 's/^# \?//'; exit 0;;
    *) echo "arg desconocido: $1" >&2; exit 64;;
  esac
done

# CHEQUEOS (el arsenal, en orden). Cada uno es OBLIGATORIO salvo donde se diga.
#   worktree_clean          el reporte describe un COMMIT, no un árbol sucio
#   version_consistency     Cargo.toml == version.json == todas las qchain-* del lock
#   build_locked            cargo build --workspace --locked
#   clippy_deny_warnings    clippy --workspace --all-targets -D warnings
#   workspace_tests         cargo test --workspace --locked (incluye ataques WASM)
#   dst_consensus           cargo test -p qchain-simulation (safety+liveness determinista)
#   sdk_wasm32              SDK + CADA plantilla de contrato a wasm32 (fuera del workspace)
#   cargo_audit             advisories RUSTSEC contra el Cargo.lock
#   sbom                    inventario CycloneDX determinista (se hashea)
#   release_binaries        los 7 binarios se construyen con el env REPRODUCIBLE y se hashean
#   reproducible_cross      dos builders (paths y CARGO_HOME distintos) -> hashes IDÉNTICOS
#   fuzz_wire               cargo-fuzz sobre los 5 targets del wire (necesita nightly)
#   sanitizers              ASan + UBSan sobre los deserializadores (necesita nightly)
#   qsep_sweep              barrido de clases de error (ADVISORY: informa, no reprueba)
#   live_chaos              chaos-test.sh — fallas mecánicas, convergencia sin fork
#   live_byzantine          byzantine-injector.sh — adversario firmado, sin fork + vivo
# FIN CHEQUEOS

WORK="$(mktemp -d /tmp/qchain-gate.XXXXXX)"
# Los logs viven FUERA del workdir efímero, al lado del reporte: un veredicto
# FAIL/INCOMPLETE es exactamente cuando hacen falta, y borrarlos al salir dejaba
# al operador sin nada que diagnosticar (defecto encontrado corriendo el gate: la
# primera corrida marcó dos chequeos en rojo y sus logs ya no existían).
LOGS="${OUT%.json}-logs"; rm -rf "$LOGS"; mkdir -p "$LOGS"
trap 'rm -rf "$WORK"' EXIT

RESULTS="$WORK/results.tsv"; : > "$RESULTS"
# name <TAB> status(pass|fail|skip) <TAB> kind(required|advisory) <TAB> detail
record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4//$'\t'/ }" >> "$RESULTS"; }

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
skip() { printf '  \033[33m∅\033[0m %s (SALTEADO — el veredicto NO puede ser PASS)\n' "$*"; }

# Corre un chequeo obligatorio: su stdout/stderr va a su propio log.
run_req() { # $1 nombre, resto: comando
  local name="$1"; shift
  say "$name"
  if "$@" > "$LOGS/$name.log" 2>&1; then
    ok "$name"; record "$name" pass required ""
  else
    local rc=$?
    bad "$name (exit $rc) — log: $LOGS/$name.log"
    tail -25 "$LOGS/$name.log" | sed 's/^/      /'
    record "$name" fail required "exit $rc"
  fi
}

# ---------------------------------------------------------------- metadatos
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git status --porcelain 2>/dev/null | head -c 1)"
WSV="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
RUSTC="$(rustc -V 2>/dev/null || echo 'rustc ausente')"
TOOLCHAIN="$(grep -m1 '^channel' rust-toolchain.toml 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/' || echo unknown)"

echo "════════════════════════════════════════════════════════════"
echo "  GATE INDEPENDIENTE SOBRE EL COMMIT FINAL (pre-mainnet #3)"
echo "  commit    : $COMMIT"
echo "  version   : $WSV"
echo "  toolchain : $TOOLCHAIN  ($RUSTC)"
echo "════════════════════════════════════════════════════════════"

# ---------------------------------------------------------------- 1. árbol limpio
say "worktree_clean"
if [ "$ALLOW_DIRTY" = 1 ]; then
  skip "worktree_clean (--allow-dirty)"; record worktree_clean skip required "--allow-dirty"
elif [ -z "$DIRTY" ]; then
  ok "árbol limpio — el reporte describe el commit $COMMIT"; record worktree_clean pass required ""
else
  bad "árbol SUCIO: el reporte no describiría ningún commit"
  git status --porcelain | head -10 | sed 's/^/      /'
  record worktree_clean fail required "uncommitted changes"
fi

# ---------------------------------------------------------------- 2. versión coherente
say "version_consistency"
VJ="$(python3 -c 'import json;print(json.load(open("version.json"))["version"])' 2>/dev/null || echo ERR)"
# Toda crate qchain-* del lock debe estar en la versión del workspace, y ninguna
# third-party debe haber sido arrastrada a ella (la lección del sed sobre el lock).
BADLOCK="$(awk '/^name = /{n=$3} /^version = "'"$WSV"'"$/{print n}' Cargo.lock | tr -d '"' | grep -v '^qchain' || true)"
NQCHAIN="$(awk '/^name = /{n=$3} /^version = "'"$WSV"'"$/{print n}' Cargo.lock | tr -d '"' | grep -c '^qchain' || true)"
if [ "$VJ" != "$WSV" ]; then
  bad "version.json ($VJ) != Cargo.toml ($WSV)"; record version_consistency fail required "version.json=$VJ cargo=$WSV"
elif [ -n "$BADLOCK" ]; then
  bad "una dependencia NO-qchain quedó en la versión del workspace: $BADLOCK"
  record version_consistency fail required "third-party at workspace version: $BADLOCK"
else
  ok "Cargo.toml = version.json = $WSV · $NQCHAIN crates qchain-* en el lock · 0 third-party arrastradas"
  record version_consistency pass required "$NQCHAIN qchain crates"
fi

# ---------------------------------------------------------------- 3-6. Rust
run_req build_locked        cargo build --workspace --locked
run_req clippy_deny_warnings cargo clippy --workspace --all-targets --locked -- -D warnings
run_req workspace_tests     cargo test --workspace --locked
run_req dst_consensus       cargo test -p qchain-simulation --locked

# ---------------------------------------------------------------- 7. SDK a wasm32
say "sdk_wasm32"
if [ "$SKIP_SDK" = 1 ]; then
  skip "sdk_wasm32 (--skip-sdk)"; record sdk_wasm32 skip required "--skip-sdk"
elif ! rustc --print target-list 2>/dev/null | grep -q '^wasm32-unknown-unknown$' \
     || ! ls "$(rustc --print sysroot)"/lib/rustlib/wasm32-unknown-unknown >/dev/null 2>&1; then
  skip "sdk_wasm32 — falta el target wasm32-unknown-unknown (rustup target add wasm32-unknown-unknown)"
  record sdk_wasm32 skip required "wasm32 target not installed"
else
  if (
    set -e
    cargo clippy --manifest-path crates/qchain-sdk/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path crates/qchain-sdk/Cargo.toml --target wasm32-unknown-unknown -- -D warnings
    cargo test  --manifest-path crates/qchain-sdk/Cargo.toml
    for t in token vault payments counter shared_counter escrow; do
      cargo build --manifest-path "crates/qchain-sdk/templates/$t/Cargo.toml" --release --target wasm32-unknown-unknown
    done
  ) > "$LOGS/sdk_wasm32.log" 2>&1; then
    ok "SDK + 6 plantillas compilan a wasm32"; record sdk_wasm32 pass required ""
  else
    bad "sdk_wasm32 — log: $LOGS/sdk_wasm32.log"; tail -20 "$LOGS/sdk_wasm32.log" | sed 's/^/      /'
    record sdk_wasm32 fail required "see log"
  fi
fi

# ---------------------------------------------------------------- 8. cargo-audit
say "cargo_audit"
if ! command -v cargo-audit >/dev/null 2>&1 && ! cargo audit --version >/dev/null 2>&1; then
  skip "cargo_audit — no está instalado (cargo install cargo-audit --locked)"
  record cargo_audit skip required "cargo-audit not installed"
elif cargo audit > "$LOGS/cargo_audit.log" 2>&1; then
  ok "sin advisories RUSTSEC conocidos"; record cargo_audit pass required ""
else
  bad "cargo audit reportó advisories — log: $LOGS/cargo_audit.log"
  tail -20 "$LOGS/cargo_audit.log" | sed 's/^/      /'
  record cargo_audit fail required "advisories found"
fi

# ---------------------------------------------------------------- 9. SBOM
say "sbom"
if bash deploy/gen-sbom.sh -o "$WORK/sbom.cdx.json" > "$LOGS/sbom.log" 2>&1; then
  SBOM_SHA="$(sha256sum "$WORK/sbom.cdx.json" | cut -d' ' -f1)"
  SBOM_N="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["components"]))' "$WORK/sbom.cdx.json" 2>/dev/null || echo '?')"
  ok "SBOM CycloneDX determinista: $SBOM_N componentes · sha256 ${SBOM_SHA:0:16}…"
  record sbom pass required "$SBOM_N components"
else
  SBOM_SHA=""; bad "no se pudo generar el SBOM"; record sbom fail required "gen-sbom failed"
fi

# ------------------------------------------------- 10. binarios de release (REPRODUCIBLES)
# Se construyen con el env reproducible para que sus sha256 sean los MISMOS que
# obtendría cualquier otro builder — que es lo que hace comparable al reporte.
say "release_binaries"
BINS_JSON="$WORK/bins.tsv"; : > "$BINS_JSON"
if ( set -e; . deploy/reproducible-env.sh; QCHAIN_REPRO_QUIET=1 cargo build --locked --release $QCHAIN_RELEASE_PKGS ) \
     > "$LOGS/release_binaries.log" 2>&1; then
  . deploy/reproducible-env.sh >/dev/null 2>&1 || true
  missing=""
  for b in $QCHAIN_RELEASE_BINS; do
    if [ -x "target/release/$b" ]; then
      printf '%s\t%s\n' "$b" "$(sha256sum "target/release/$b" | cut -d' ' -f1)" >> "$BINS_JSON"
    else
      missing="$missing $b"
    fi
  done
  if [ -n "$missing" ]; then
    bad "faltan binarios:$missing"; record release_binaries fail required "missing:$missing"
  else
    ok "7 binarios construidos con el env reproducible y hasheados"
    sed 's/^/      /' "$BINS_JSON"
    record release_binaries pass required "7 binaries"
  fi
else
  bad "falló el build de release — log: $LOGS/release_binaries.log"
  tail -20 "$LOGS/release_binaries.log" | sed 's/^/      /'
  record release_binaries fail required "release build failed"
fi

# ------------------------------------------- 11. reproducible CROSS-BUILDER (dos builders)
say "reproducible_cross"
if [ "$SKIP_REPRO" = 1 ]; then
  skip "reproducible_cross (--skip-reproducible)"; record reproducible_cross skip required "--skip-reproducible"
elif [ ! -s "$BINS_JSON" ]; then
  skip "reproducible_cross — no hay binarios del paso anterior"
  record reproducible_cross skip required "no binaries from builder A"
else
  # Builder B: OTRO directorio + OTRO CARGO_HOME. Si un path se filtrara al
  # binario, los hashes diferirían y este chequeo lo delata.
  SRCB="$WORK/builderB"; rm -rf "$SRCB"
  # `unset RUSTFLAGS` antes de sourcear: el shell principal ya tiene el remap del
  # builder A, y acumularlos dejaría a B con remaps de A que no matchean nada.
  # No cambia los bytes (los extra son no-ops) pero vuelve al chequeo dependiente
  # de un detalle frágil; mejor que cada builder derive su env desde cero.
  if ( set -e
       git -c advice.detachedHead=false clone --quiet --no-hardlinks "$ROOT" "$SRCB"
       cd "$SRCB"; git -c advice.detachedHead=false checkout --quiet "$COMMIT"
       export CARGO_HOME="$WORK/cargohomeB"; unset RUSTFLAGS
       . "$SRCB/deploy/reproducible-env.sh"
       QCHAIN_REPRO_QUIET=1 cargo build --locked --release $QCHAIN_RELEASE_PKGS
     ) > "$LOGS/reproducible_cross.log" 2>&1; then
    diffs=""
    while IFS=$'\t' read -r b sha; do
      shb="$(sha256sum "$SRCB/target/release/$b" 2>/dev/null | cut -d' ' -f1 || echo MISSING)"
      [ "$shb" = "$sha" ] || diffs="$diffs $b"
    done < "$BINS_JSON"
    if [ -z "$diffs" ]; then
      ok "los 7 binarios son BYTE-IDÉNTICOS entre dos builders (paths y CARGO_HOME distintos)"
      record reproducible_cross pass required "7/7 identical"
    else
      bad "NO reproducible cross-builder (difieren:$diffs) — ¿fuga de path?"
      record reproducible_cross fail required "differ:$diffs"
    fi
    # LIBERAR YA el árbol del builder B (clone + target de release completo, varios
    # GB). Si se deja hasta el final, los harness EN VIVO de más abajo — que
    # levantan testnets reales con su propio estado en disco — corren con el disco
    # innecesariamente comprimido. (Defecto encontrado corriendo el gate.)
    rm -rf "$SRCB" "$WORK/cargohomeB"
  else
    bad "falló el builder B — log: $LOGS/reproducible_cross.log"
    tail -20 "$LOGS/reproducible_cross.log" | sed 's/^/      /'
    record reproducible_cross fail required "builder B failed"
  fi
fi

# ---------------------------------------------- 12. fuzzing del wire (necesita nightly)
# En `ci.yml` el fuzzing corre NIGHTLY — o sea sobre el HEAD que hubiera a las
# 04:00 UTC, no sobre el commit que se lanza. Acá corre sobre ESTE commit. Si
# falta el toolchain nightly o cargo-fuzz, se marca SALTEADO y el veredicto cae
# a INCOMPLETE: para un lanzamiento, "no lo corrí" no puede leerse como "pasó".
say "fuzz_wire"
FUZZ_SECS="${QCHAIN_GATE_FUZZ_SECS:-60}"
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly' || ! command -v cargo-fuzz >/dev/null 2>&1; then
  skip "fuzz_wire — falta nightly y/o cargo-fuzz (rustup toolchain install nightly; cargo install cargo-fuzz)"
  record fuzz_wire skip required "nightly/cargo-fuzz not installed"
else
  if ( set -e
       for t in transaction_deserialize message_deserialize network_envelope_deserialize \
                governance_proposal_deserialize execution_decoders; do
         cargo +nightly fuzz run "$t" -- -max_total_time="$FUZZ_SECS"
       done
     ) > "$LOGS/fuzz_wire.log" 2>&1; then
    ok "5 targets del wire fuzzeados ${FUZZ_SECS}s c/u sin crash"
    record fuzz_wire pass required "5 targets x ${FUZZ_SECS}s"
  else
    bad "fuzz_wire encontró un crash — log: $LOGS/fuzz_wire.log"
    tail -25 "$LOGS/fuzz_wire.log" | sed 's/^/      /'
    record fuzz_wire fail required "crash found"
  fi
fi

# ------------------------------------- 13. sanitizers (ASan/UBSan, necesita nightly)
# LÍMITE HONESTO heredado de ci.yml: se acota a los crates de wire PUROS-Rust
# (core/storage/stark). Un sanitizer sobre el workspace completo tropieza con el
# liboqs en C, cuyo análisis es un proceso externo aparte (#185).
say "sanitizers"
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
  skip "sanitizers — falta el toolchain nightly"
  record sanitizers skip required "nightly not installed"
else
  if ( set -e
       for san in address undefined; do
         RUSTFLAGS="-Zsanitizer=$san" RUSTDOCFLAGS="-Zsanitizer=$san" \
           cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu \
             -p qchain-core -p qchain-storage -p qchain-stark
       done
     ) > "$LOGS/sanitizers.log" 2>&1; then
    ok "ASan + UBSan limpios sobre los deserializadores (core/storage/stark)"
    record sanitizers pass required "asan+ubsan"
  else
    bad "sanitizers — log: $LOGS/sanitizers.log"; tail -25 "$LOGS/sanitizers.log" | sed 's/^/      /'
    record sanitizers fail required "see log"
  fi
fi

# ------------------------------------------------------------- 14. QSEP-1 sweep (ADVISORY)
# Por su propio contrato el sweep NUNCA reprueba (es un asistente, no un gate):
# flaggea candidatos para revisión humana. Lo que este gate agrega es que quede
# CORRIDO y ARCHIVADO sobre el commit final, que es lo que QSEP-1 exige.
say "qsep_sweep (advisory)"
if bash deploy/qsep-sweep.sh > "$LOGS/qsep_sweep.log" 2>&1; then
  CAND="$(grep -oE 'Candidatos flaggeados: [0-9]+' "$LOGS/qsep_sweep.log" | grep -oE '[0-9]+' | tail -1 || echo '?')"
  ok "sweep corrido y archivado — $CAND candidatos para revisión (advisory, no reprueba)"
  record qsep_sweep pass advisory "$CAND candidates"
else
  bad "el sweep no pudo correr"; record qsep_sweep fail advisory "sweep failed to run"
fi

# --------------------------------------------------- 13-14. harness adversariales EN VIVO
say "live_chaos + live_byzantine"
if [ "$SKIP_LIVE" = 1 ]; then
  skip "live_chaos (--skip-live)";      record live_chaos     skip required "--skip-live"
  skip "live_byzantine (--skip-live)";  record live_byzantine skip required "--skip-live"
else
  # El inyector bizantino es tooling de TEST: no está en QCHAIN_RELEASE_PKGS (los
  # 7 binarios que se publican), así que hay que construirlo aparte antes de que
  # su harness lo busque en target/release.
  cargo build --release --locked -p qchain-byzantine-injector > "$LOGS/build_injector.log" 2>&1 || true
  if [ -x target/release/qchain-node ] && [ -x target/release/qchain ] \
     && [ -x target/release/qchain-genesis-build ] && [ -x target/release/qchain-byzantine-injector ]; then
    if bash deploy/chaos-test.sh > "$LOGS/live_chaos.log" 2>&1 \
       && grep -q 'FAIL=0' "$LOGS/live_chaos.log"; then
      ok "chaos-test: convergencia sin fork tras cada falla mecánica"
      record live_chaos pass required "$(grep -oE 'PASS=[0-9]+ +FAIL=[0-9]+' "$LOGS/live_chaos.log" | tail -1)"
    else
      bad "chaos-test — log: $LOGS/live_chaos.log"; tail -15 "$LOGS/live_chaos.log" | sed 's/^/      /'
      record live_chaos fail required "see log"
    fi
    if bash deploy/byzantine-injector.sh > "$LOGS/live_byzantine.log" 2>&1 \
       && grep -q 'VEREDICTO: PASS' "$LOGS/live_byzantine.log"; then
      ok "byzantine-injector: la red honesta resistió cada ataque firmado (sin fork, viva)"
      record live_byzantine pass required "$(grep -oE 'PASS=[0-9]+ +FAIL=[0-9]+' "$LOGS/live_byzantine.log" | tail -1)"
    else
      bad "byzantine-injector — log: $LOGS/live_byzantine.log"; tail -15 "$LOGS/live_byzantine.log" | sed 's/^/      /'
      record live_byzantine fail required "see log"
    fi
  else
    skip "harness en vivo — faltan binarios (release y/o el inyector bizantino)"
    record live_chaos     skip required "binaries missing"
    record live_byzantine skip required "binaries missing"
  fi
fi

# ---------------------------------------------------------------- veredicto + reporte
NFAIL="$(awk -F'\t' '$2=="fail"  && $3=="required"' "$RESULTS" | wc -l | tr -d ' ')"
NSKIP="$(awk -F'\t' '$2=="skip"  && $3=="required"' "$RESULTS" | wc -l | tr -d ' ')"
NPASS="$(awk -F'\t' '$2=="pass"  && $3=="required"' "$RESULTS" | wc -l | tr -d ' ')"
NADVF="$(awk -F'\t' '$2=="fail"  && $3=="advisory"' "$RESULTS" | wc -l | tr -d ' ')"

if   [ "$NFAIL" -gt 0 ]; then VERDICT="FAIL";       RC=1
elif [ "$NSKIP" -gt 0 ]; then VERDICT="INCOMPLETE"; RC=2
else                          VERDICT="PASS";       RC=0
fi

python3 - "$RESULTS" "$BINS_JSON" "$OUT" "$COMMIT" "$WSV" "$RUSTC" "$TOOLCHAIN" "${SBOM_SHA:-}" "$VERDICT" <<'PY'
import hashlib, json, sys
res, bins, out, commit, ver, rustc, chan, sbom, verdict = sys.argv[1:10]

checks = []
with open(res) as f:
    for line in f:
        if not line.strip():
            continue
        name, status, kind, detail = (line.rstrip("\n").split("\t") + ["", "", ""])[:4]
        checks.append({"name": name, "status": status, "kind": kind, "detail": detail})
checks.sort(key=lambda c: c["name"])

binaries = {}
try:
    with open(bins) as f:
        for line in f:
            if line.strip():
                b, sha = line.rstrip("\n").split("\t")
                binaries[b] = sha
except FileNotFoundError:
    pass

# El objeto HASHEADO: sin reloj, claves ordenadas. Dos verificadores
# independientes sobre el MISMO commit deben obtener el MISMO report_hash.
core = {
    "schema": "qchain-mainnet-gate/v1",
    "commit": commit,
    "version": ver,
    "toolchain_channel": chan,
    "rustc": rustc,
    "sbom_sha256": sbom or None,
    "binaries_sha256": dict(sorted(binaries.items())),
    "checks": checks,
    "verdict": verdict,
}
canon = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
report = dict(core)
report["report_hash"] = hashlib.sha256(canon).hexdigest()
with open(out, "w") as f:
    json.dump(report, f, sort_keys=True, indent=2)
    f.write("\n")
print(report["report_hash"])
PY
RHASH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["report_hash"])' "$OUT")"

echo
echo "════════════════════════════════════════════════════════════"
printf '  obligatorios: %s pass · %s fail · %s salteados\n' "$NPASS" "$NFAIL" "$NSKIP"
[ "$NADVF" -gt 0 ] && printf '  advisory con problemas: %s\n' "$NADVF"
echo "  reporte : $OUT"
echo "  hash    : $RHASH"
case "$VERDICT" in
  PASS)       echo "  VEREDICTO: PASS — el arsenal COMPLETO está verde sobre $COMMIT";;
  FAIL)       echo "  VEREDICTO: FAIL — algo rojo sobre $COMMIT. NO lanzar.";;
  INCOMPLETE) echo "  VEREDICTO: INCOMPLETE — nada rojo, pero NO se verificó todo."
              echo "             Un chequeo salteado NO es un PASS. NO lanzar con esto.";;
esac
echo "════════════════════════════════════════════════════════════"
echo
echo "Verificación INDEPENDIENTE: otro operador corre este mismo script sobre el"
echo "mismo commit y compara UN solo valor — el report_hash de arriba."
exit "$RC"
