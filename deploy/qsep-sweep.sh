#!/usr/bin/env bash
# qsep-sweep.sh — Detector heurístico de clases de error recurrentes (QSEP-1 §13).
#
# NO prueba nada: FLAGGEA CANDIDATOS de las clases mecánicamente detectables del
# libro mayor `docs/security/LESSONS-LEDGER.md` para que una revisión humana/de
# agente las descarte una por una. Un candidato flaggeado NO es un bug; la
# ausencia de candidatos NO garantiza que la clase esté cerrada (por eso cada
# clase tiene además su "pregunta recurrente" en el ledger, que se responde con
# test/grep). Se corre en cada cambio R2/R3 y al cerrar cada auditoría.
#
# Uso:   ./deploy/qsep-sweep.sh            # todas las clases
#        ./deploy/qsep-sweep.sh EC-01      # una sola clase
#        ./deploy/qsep-sweep.sh --list     # lista las clases
#
# Salida: candidatos por clase + un chequeo de que el ledger y el rastreador de
# la auditoría existen. Exit 0 siempre (es un asistente, no un gate que rompe el
# build); el juicio es humano/agente.
set -uo pipefail
cd "$(dirname "$0")/.."

# Módulos donde vive lógica privilegiada / de valor.
PRIV='crates/qchain-execution/src crates/qchain-governance/src crates/qchain-node/src crates/qchain-remote-signer/src'
VALUE='crates/qchain-execution/src/treasury_v7.rs crates/qchain-execution/src/governance.rs crates/qchain-execution/src/fees_v7.rs crates/qchain-execution/src/staking.rs crates/qchain-execution/src/staking_v7.rs crates/qchain-execution/src/economics_v7.rs crates/qchain-execution/src/ledger.rs'

hr(){ printf '%s\n' '────────────────────────────────────────────────────────'; }
head(){ hr; printf '  %s\n' "$1"; hr; }
note(){ printf '    · %s\n' "$1"; }

want(){ [ $# -eq 0 ] || [ "$1" = "$2" ] || { [ "${1:-}" = "" ]; }; }
SEL="${1:-all}"
run(){ [ "$SEL" = "all" ] || [ "$SEL" = "$1" ]; }

if [ "$SEL" = "--list" ]; then
  grep -E '^\| EC-[0-9]+ ' docs/security/LESSONS-LEDGER.md | sed 's/|/ /g'
  exit 0
fi

FLAGS=0
count(){ FLAGS=$((FLAGS+$1)); }

# ── EC-01: autenticidad de cuenta privilegiada no forzada ──────────────
if run EC-01; then
  head "EC-01  lectores de cuenta privilegiada sin owner-check cercano"
  note "revisar: ¿owner canónico + dirección canónica + magic + versión ANTES de confiar?"
  # decodificadores de cuenta en módulos privilegiados; ojo con los que NO tengan
  # un chequeo de .owner en las ~6 líneas previas (heurística, revisión manual).
  hits=$(grep -rnE 'read_or_legacy|try_from_slice|decode_registry|read_state|read_proposal' $PRIV \
          --include='*.rs' 2>/dev/null | grep -vE 'fn (read_or_legacy|decode_)|test|#\[' || true)
  echo "$hits" | sed '/^$/d' | while IFS= read -r l; do note "$l"; done
  n=$(printf '%s\n' "$hits" | sed '/^$/d' | wc -l | tr -d ' '); count "$n"
  note "→ ($n candidatos) para cada uno confirmar el chequeo de owner/dirección/magic/versión."
fi

# ── EC-02 / EC-09: trial-borsh + peligros de migración ─────────────────
if run EC-02 || run EC-09; then
  head "EC-02/EC-09  decodificadores en cascada + structs *V0 que referencian tipos NUEVOS"
  note "revisar: ¿UN decodificador canónico compartido arranque/runtime? ¿fixture binario real por versión?"
  # funciones con ≥2 try_from_slice/from_slice (adivinar formato):
  for f in $(grep -rlE 'try_from_slice|from_slice' $PRIV --include='*.rs' 2>/dev/null); do
    c=$(grep -cE 'try_from_slice|from_slice::' "$f" 2>/dev/null || echo 0)
    [ "$c" -ge 3 ] && { note "$f  ($c decodificaciones — posible cascada)"; count 1; }
  done
  # structs *V0/*Legacy que referencian un enum/tipo NO-V0 (representación histórica incorrecta):
  note "structs históricas a auditar (deben ser copias EXACTAS, no referenciar tipos nuevos):"
  grep -rnE 'struct [A-Za-z0-9_]*(V0|Legacy)\b|enum [A-Za-z0-9_]*(V0|Legacy)\b' $PRIV --include='*.rs' 2>/dev/null \
    | while IFS= read -r l; do note "$l"; done
fi

# ── EC-05: aritmética de valor sin checked_ ────────────────────────────
if run EC-05; then
  head "EC-05  aritmética de dinero/ronda/tiempo sin checked_/saturating_"
  note "revisar: ¿todo +/-/* de amount/round/timelock/expiry/stake/fee usa aritmética comprobada?"
  # sumas/restas sobre variables sospechosas sin checked_/saturating_ en la línea:
  hits=$(grep -rnE '\b(round|passed_round|proposed_round|amount|balance|timelock|expiry|expiry_quanto|stake|fee|reward|bond|_atoms)[a-z_]*\s*[-+*]\s' $VALUE 2>/dev/null \
          | grep -vE 'checked_|saturating_|//|assert|test|let mut|_bps|for ' || true)
  echo "$hits" | sed '/^$/d' | while IFS= read -r l; do note "$l"; done
  n=$(printf '%s\n' "$hits" | sed '/^$/d' | wc -l | tr -d ' '); count "$n"
  note "→ ($n candidatos) confirmar checked_* o justificar saturating_ (no-dinero)."
fi

# ── EC-08: la interfaz como frontera (política no re-verificada en apply) ─
if run EC-08; then
  head "EC-08  campos de política/versión leídos sin rechazo cercano en ejecución comprometida"
  note "revisar: ¿tx.version y toda regla de aceptación se RE-verifica en apply, no sólo en RPC/gossip?"
  grep -rnE '\.version\b|network_id|fork_id' crates/qchain-execution/src crates/qchain-core/src --include='*.rs' 2>/dev/null \
    | grep -vE 'schema_version|version.json|pkg_version|CARGO|test' \
    | while IFS= read -r l; do note "$l"; done
fi

# ── EC-13: tamaño-wire / cobro inexacto ────────────────────────────────
if run EC-13; then
  head "EC-13  tamaño para fee/cap que puede diferir de los bytes del wire"
  note "revisar: ¿fee y cap usan EXACTAMENTE borsh::to_vec(tx).len()?"
  grep -rnE 'byte_size|fn .*size\(' crates/qchain-core/src crates/qchain-execution/src crates/qchain-node/src --include='*.rs' 2>/dev/null \
    | grep -vE 'test|//' | while IFS= read -r l; do note "$l"; done
fi

# ── EC-19: firma sin binding de INSTANCIA ──────────────────────────────
if run EC-19; then
  head "EC-19  preimágenes firmadas: ¿nombran la red/época? ¿quién más las verifica?"
  note "revisar por cada dominio: (a) su preimagen incluye chain_id/época,"
  note "(b) qué superficies la verifican ADEMÁS de donde se consume el objeto,"
  note "(c) esas superficies re-ejecutan las validaciones del argumento 'ya está cerrado'."
  grep -rnE 'pub const [A-Z_]+_V[0-9]+: &\[u8\]' crates/qchain-crypto/src --include='*.rs' 2>/dev/null \
    | while IFS= read -r l; do note "$l"; done
  note "— sitios que construyen/verifican una preimagen con dominio:"
  grep -rnE '(sign|verify)_domain\(' crates --include='*.rs' 2>/dev/null \
    | grep -vE 'fn (sign|verify)_domain' | while IFS= read -r l; do note "$l"; done
fi

# ── EC-20: dependencia consensus-affecting disfrazada de normal ────────
if run EC-20; then
  head "EC-20  dependencias cuyo COMPORTAMIENTO numérico entra al state root"
  note "revisar: ¿qué dependencia produce un número que se debita/acredita o"
  note "se hashea al estado? Esa versión ES una regla de consenso, y actualizarla"
  note "es un CUTOVER COORDINADO, no un 'cargo update'."
  note "— pin de la que hoy alimenta consenso (fuel -> gas -> state root):"
  grep -nE '^wasmtime = ' Cargo.toml 2>/dev/null | while IFS= read -r l; do note "$l"; done
  note "— rangos MAYORES abiertos (juicio humano: ¿alguno alimenta el estado?):"
  grep -nE '^[a-z0-9_-]+ = "[0-9]+"$' Cargo.toml 2>/dev/null \
    | while IFS= read -r l; do note "$l"; done
  note "— KAT que pinean la cantidad (si falta uno, la clase está ABIERTA):"
  grep -rnE 'fn fuel_.*pinned|consensus_affecting' crates/qchain-execution/src --include='*.rs' 2>/dev/null \
    | grep -E 'fn ' | while IFS= read -r l; do note "$l"; done
fi

# ── Presencia del sistema de aprendizaje ───────────────────────────────
head "Sistema de aprendizaje (debe existir y estar al día)"
for f in docs/security/LESSONS-LEDGER.md docs/security/audits; do
  if [ -e "$f" ]; then note "OK  $f"; else note "FALTA  $f"; count 1; fi
done
audits=$(ls docs/security/audits/*.md 2>/dev/null | wc -l | tr -d ' ')
note "auditorías registradas: $audits"

hr
echo "  Candidatos flaggeados: $FLAGS   (revisión humana/agente obligatoria)"
echo "  Recordá: responder la 'pregunta recurrente' de CADA clase en el ledger"
echo "  con evidencia (test/grep/línea). El sweep asiste, no reemplaza el juicio."
hr
exit 0
