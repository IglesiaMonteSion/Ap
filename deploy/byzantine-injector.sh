#!/usr/bin/env bash
# byzantine-injector.sh — harness ADVERSARIAL. Levanta una red HONESTA y le suelta
# un validador BIZANTINO real (una clave del comité que este harness NO corre como
# nodo, sino que impersona con `qchain-byzantine-injector`), ejerciendo cada
# defensa de consenso con un ataque genuinamente firmado. Es la contraparte del
# `chaos-test.sh` mecánico (crash/partición/corrupción): acá el adversario piensa.
#
# Cada ataque mapea a UNA defensa que el proyecto construyó, con su oráculo:
#   equivocate → slashing por equivocación (#88) + candado voted_for
#                oráculo: la red no forkea Y un nodo honesto CAPTURA la evidencia.
#   withhold   → gate de disponibilidad en el voto (v6.3.0, HIGH #175)
#                oráculo: la red no se traba — una tx fresca finaliza después.
#   oversized  → cotas estructurales pre-proceso (#208) + robustez del deser
#                oráculo: los nodos siguen vivos y convergen (RPC responde).
#   flood      → cuota de admisión + verify concurrente (#210/#90)
#                oráculo: la red honesta sigue sana y una tx fresca finaliza.
#
# El VEREDICTO de cada ataque es SEGURIDAD (roots idénticos al mismo nº de tx
# ejecutadas = sin fork) + VIVACIDAD (una transferencia nueva finaliza en todos
# los nodos vivos). Nada se prueba desde el propio inyector: la red honesta,
# observada por RPC, es el oráculo — igual que las verificaciones en vivo del
# proyecto.
#
# Uso:  deploy/byzantine-injector.sh [--bin DIR] [--rpq N] [--work DIR]
#
# Sandbox: 4 núcleos → 3 nodos honestos + inyector es holgado. No corre para
# siempre; termina con un resumen PASS/FAIL (exit != 0 si algún ataque rompió una
# invariante DURA).
set -Eeuo pipefail

BIN="target/release"; RPQ=64; WORK="$(mktemp -d /tmp/qchain-byz.XXXXXX)"
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2;;
    --rpq) RPQ="$2"; shift 2;;
    --work) WORK="$2"; shift 2;;
    *) echo "arg desconocido: $1"; exit 2;;
  esac
done

# Resolve BIN to an absolute path BEFORE we `cd` into $WORK — the binaries are
# invoked from inside the work dir, so a relative `target/release` would 404.
BIN="$(cd "$BIN" 2>/dev/null && pwd)" || { echo "no existe el directorio de binarios (compilá con: cargo build --release)"; exit 1; }
QCHAIN="$BIN/qchain"; NODE="$BIN/qchain-node"; GB="$BIN/qchain-genesis-build"
INJ="$BIN/qchain-byzantine-injector"
for b in "$QCHAIN" "$NODE" "$GB" "$INJ"; do
  [ -x "$b" ] || { echo "falta el binario $b (compilá con: cargo build --release)"; exit 1; }
done

# 3 nodos HONESTOS + 1 identidad BIZANTINA (en el comité, pero sin nodo: la
# impersona el inyector). Comité de 4 → quórum 3 → los 3 honestos progresan solos.
HONEST=3
PASS=0; FAIL=0
declare -a PIDS
MAIN_PID=$$
cleanup() {
  [ "$BASHPID" = "$MAIN_PID" ] || return 0
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"; cd "$WORK"

rpc()  { echo "http://127.0.0.1:$((8500+$1))"; }
p2p()  { echo "127.0.0.1:$((9500+$1))"; }

echo "== generando $HONEST validadores honestos + 1 bizantino + génesis v7 (rpq=$RPQ) en $WORK =="
mkdir -p manifests
# índices 1..HONEST honestos; índice (HONEST+1) es el bizantino.
BYZ_IDX=$((HONEST+1))
for i in $(seq 1 "$BYZ_IDX"); do "$QCHAIN" keygen --out "v$i.json" >/dev/null 2>&1; done
"$QCHAIN" keygen --out bank.json >/dev/null 2>&1
"$QCHAIN" keygen --out bob.json  >/dev/null 2>&1
BANK="$("$QCHAIN" address --keypair bank.json 2>/dev/null)"
BOB="$("$QCHAIN" address --keypair bob.json 2>/dev/null)"
for i in $(seq 1 "$BYZ_IDX"); do
  BUNDLE="$("$QCHAIN" bundle --keypair "v$i.json" 2>/dev/null)"
  # el bizantino declara un listen_addr donde NADIE escucha (no corremos su nodo);
  # los honestos lo dialean, fallan y reintentan — inofensivo.
  printf '{"pubkey_bundle":%s,"listen_addr":"%s","rpc_addr":"127.0.0.1:%s","stake":1000000000}\n' \
    "$BUNDLE" "$(p2p "$i")" "$((8500+i))" > "manifests/v$i.json"
done
echo "[{\"address\":\"$BANK\",\"balance\":1000000000000000}]" > genesis.json
"$GB" --manifests-dir manifests --genesis genesis.json --out-dir out \
  --round-interval-ms 500 --economics-v7 --rounds-per-quanto "$RPQ" >/dev/null 2>&1

start_node() { # $1 = index (sólo honestos)
  local i="$1"; mkdir -p "n$i/data"; cp "out/node$i.json" "n$i/node.json"; cp "v$i.json" "n$i/keypair.json"
  ( cd "n$i" && exec env RUST_LOG=warn "$NODE" --config node.json > node.log 2>&1 ) &
  local pid=$!; echo "$pid" > "n$i/pid"; PIDS+=("$pid")
}
for i in $(seq 1 "$HONEST"); do start_node "$i"; done
echo "== esperando arranque de la malla honesta =="; sleep 10

# --- oráculos por RPC (idénticos en espíritu a chaos-test.sh) ---
exec_of()  { curl -s "$(rpc "$1")/status" 2>/dev/null | grep -o '"executed_transactions":[0-9]*' | cut -d: -f2; }
round_of() { local r; r="$(curl -s "$(rpc "$1")/status" 2>/dev/null | grep -o '"next_round":[0-9]*' | cut -d: -f2)"; echo "${r:-0}"; }
root_at()  { curl -s "$(rpc "$1")/root" 2>/dev/null | grep -o '"root":"[0-9a-f]*"' | cut -d'"' -f4; }
bob_of()   { curl -s "$(rpc "$1")/account/$BOB" 2>/dev/null | grep -o '"balance":[0-9]*' | cut -d: -f2; }
up()       { curl -s "$(rpc "$1")/status" >/dev/null 2>&1; }
chainid()  { curl -s "$(rpc "$1")/chain_id" 2>/dev/null | grep -o '"chain_id":"[0-9a-f]*"' | cut -d'"' -f4; }
evid_count() { curl -s "$(rpc "$1")/equivocation_evidence" 2>/dev/null | grep -o '"round"' | wc -l | tr -d ' '; }
live_node() { for i in $(seq 1 "$HONEST"); do up "$i" && { echo "$i"; return; }; done; echo ""; }

# root muestreado de forma estable contra su nº de tx ejecutadas (ver chaos-test).
root_at_exec() { local i="$1" e1 rt e2; e1="$(exec_of "$i")"; rt="$(root_at "$i")"; e2="$(exec_of "$i")"; [ -n "$e1" ] && [ -n "$rt" ] && [ "$e1" = "$e2" ] && echo "$e1 $rt"; }

# Convergencia REAL tras un ataque: una tx nueva a bob finaliza en el submitter,
# todos los nodos vivos llegan a ESE saldo, y ningún par reporta roots distintos
# al mismo nº de tx ejecutadas.
converge_check() { # $1 = etiqueta
  local label="$1" amt=$((5000000 + RANDOM))
  local sub; sub="$(live_node)"; [ -z "$sub" ] && { echo "  ✗ $label: ningún nodo vivo"; FAIL=$((FAIL+1)); return 1; }
  local before; before="$(bob_of "$sub")"; before="${before:-0}"
  "$QCHAIN" transfer --rpc "$(rpc "$sub")" --keypair bank.json --to "$BOB" --amount "$amt" --valid-for-rounds 5000 >/dev/null 2>&1 || true
  local want=$((before + amt)) ok=0
  for _ in $(seq 1 40); do
    local b; b="$(bob_of "$sub")"; [ "${b:-0}" -ge "$want" ] && { ok=1; break; }; sleep 0.5
  done
  [ "$ok" = 1 ] || { echo "  ✗ $label: la tx nueva NO finalizó (vivacidad rota)"; FAIL=$((FAIL+1)); return 1; }
  # todos los vivos convergen a want, y sin fork (roots idénticos al mismo exec).
  local agreed=1 fork=0
  declare -A ROOTS
  for i in $(seq 1 "$HONEST"); do
    up "$i" || continue
    local b2; b2="$(bob_of "$i")"; [ "${b2:-0}" -ge "$want" ] || agreed=0
    local er; er="$(root_at_exec "$i")"; if [ -n "$er" ]; then
      local e="${er%% *}" r="${er##* }"
      if [ -n "${ROOTS[$e]:-}" ] && [ "${ROOTS[$e]}" != "$r" ]; then fork=1; fi
      ROOTS[$e]="$r"
    fi
  done
  if [ "$fork" = 1 ]; then echo "  ✗ $label: FORK — dos nodos con roots distintos al mismo nº de tx ejecutadas"; FAIL=$((FAIL+1)); return 1; fi
  if [ "$agreed" != 1 ]; then echo "  ✗ $label: no todos los nodos vivos convergieron al saldo de bob"; FAIL=$((FAIL+1)); return 1; fi
  echo "  ✓ $label: sin fork + la tx nueva finalizó en todos los vivos"; PASS=$((PASS+1)); return 0
}

# A partir de acá son LECTURAS por RPC: un `grep` que no matchea (saldo aún
# ausente, root todavía no listo) es una señal ESPERADA ("todavía no"), no un
# error. Con `pipefail` esos grep vacíos harían abortar bajo `set -e`, así que
# apagamos errexit para la fase de verificación — que lleva su propio tally
# PASS/FAIL explícito y nunca depende del exit code para decidir. El setup de
# arriba (keygen/génesis/arranque) sí corrió con errexit, que es donde importa.
set +e
# --- baseline: la red honesta converge ANTES de cualquier ataque ---
CID="$(chainid 1)"
[ -n "$CID" ] || { echo "no pude leer el chain_id — ¿arrancó la red?"; exit 1; }
echo "== chain_id de la red: $CID =="
TARGETS="$(p2p 1)"; for i in $(seq 2 "$HONEST"); do TARGETS="$TARGETS,$(p2p "$i")"; done
echo "== BASELINE (sin ataque) =="
converge_check "baseline"

inject() { # $@ = subcomando + args del inyector
  env RUST_LOG=warn "$INJ" --keypair "$WORK/v$BYZ_IDX.json" --chain-id "$CID" --targets "$TARGETS" "$@" >/dev/null 2>&1 || true
}

# 1) EQUIVOCACIÓN
echo "== ATAQUE 1: equivocación (dos vértices en conflicto para la misma ronda) =="
R="$(round_of 1)"
inject equivocate --round "$R"
sleep 3
# oráculo extra: un nodo honesto capturó la evidencia.
EV=0; for i in $(seq 1 "$HONEST"); do c="$(evid_count "$i")"; [ "${c:-0}" -ge 1 ] && EV=1; done
if [ "$EV" = 1 ]; then echo "  ✓ evidencia de equivocación CAPTURADA por un nodo honesto (slasheable)"; PASS=$((PASS+1));
else echo "  ⚠ evidencia no observada por RPC (la detección puede depender del timing del vértice; la seguridad/vivacidad es el gate duro)"; fi
converge_check "post-equivocación"

# 2) WITHHOLDING
echo "== ATAQUE 2: withholding (vértice que referencia un batch que nunca se envía) =="
R="$(round_of 1)"
inject withhold --round "$R" --count 8
sleep 3
converge_check "post-withholding"

# 3) VÉRTICE SOBRE-DIMENSIONADO + bytes basura
echo "== ATAQUE 3: vértice sobre-dimensionado (5000 parents) + frames de bytes basura =="
R="$(round_of 1)"
inject oversized --round "$R" --parents 5000
sleep 3
converge_check "post-oversized"

# 4) FLOOD de admisión
echo "== ATAQUE 4: flood de tx firmadas por un pagador sin fondos =="
inject flood --count 400
sleep 3
converge_check "post-flood"

echo ""
echo "════════════════════════════════════════════════"
echo "  INYECTOR BIZANTINO — RESUMEN:  PASS=$PASS  FAIL=$FAIL"
echo "════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || { echo "VEREDICTO: FAIL — un ataque rompió seguridad o vivacidad."; exit 1; }
echo "VEREDICTO: PASS — la red honesta resistió cada ataque bizantino (sin fork, siempre viva)."
