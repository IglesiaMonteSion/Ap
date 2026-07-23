#!/usr/bin/env bash
# Driver de CAOS para la testnet PRE-LANZAMIENTO. Levanta N validadores LOCALES
# (loopback), corre tráfico de fondo, e INYECTA fallas mecánicas una por una,
# verificando tras CADA una que todos los nodos VIVOS convergen al MISMO Merkle
# root y que una transferencia nueva aterriza en todos. Ejercita los caminos
# REALES de recuperación (crash/reinicio, reinicio en borde de época, y — con
# permisos — pérdida/retraso/duplicación de paquetes, particiones, corrupción).
#
# Es la parte AUTOMATIZABLE del plan de pruebas: el soak real multi-VPS / multi-
# operador de varias semanas es operativo (ver docs/PRE-LAUNCH-TESTPLAN.md), pero
# este driver reproduce en UNA máquina los escenarios inyectables como smoke test
# repetible antes y durante ese soak.
#
#   deploy/chaos-test.sh [--nodes N] [--bin DIR] [--rpq N] [--work DIR] [--with-netem] [--with-partition] [--with-corruption]
#
# NOTA: este script SONDEA nodos que a propósito están caídos (kill/partición) y
# hace grep de campos que pueden faltar, así que NO usa `errexit` — un curl a un
# nodo caído o un grep sin match no debe abortar la corrida. Los fallos de SETUP
# (binarios/genesis) se chequean explícitamente.
set -uo pipefail

NODES=4
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release"
RPQ=20
WORK="${TMPDIR:-/tmp}/qchain-chaos.$$"
WITH_NETEM=0; WITH_PARTITION=0; WITH_CORRUPTION=0
while [ $# -gt 0 ]; do
  case "$1" in
    --nodes) NODES="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --rpq) RPQ="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --with-netem) WITH_NETEM=1; shift ;;
    --with-partition) WITH_PARTITION=1; shift ;;
    --with-corruption) WITH_CORRUPTION=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "arg desconocido: $1" >&2; exit 1 ;;
  esac
done

QCHAIN="$BIN/qchain"; NODE="$BIN/qchain-node"; GB="$BIN/qchain-genesis-build"
for b in "$QCHAIN" "$NODE" "$GB"; do [ -x "$b" ] || { echo "falta el binario $b (compilá con: cargo build --release)"; exit 1; }; done

PASS=0; FAIL=0
declare -a PIDS
MAIN_PID=$$
# GUARDA: el trap EXIT lo heredan los subshells de fondo (el flood, los nodos).
# Sin la guarda, cuando el subshell del flood termina corre `cleanup` y borra
# WORK con la testnet todavía viva. Sólo el shell PRINCIPAL debe limpiar.
cleanup() {
  [ "$BASHPID" = "$MAIN_PID" ] || return 0
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"; cd "$WORK"

rpc() { echo "http://127.0.0.1:$((8400+$1))"; }
p2p() { echo "127.0.0.1:$((9400+$1))"; }

echo "== generando $NODES validadores + génesis v7 (rpq=$RPQ) en $WORK =="
mkdir -p manifests
for i in $(seq 1 "$NODES"); do "$QCHAIN" keygen --out "v$i.json" >/dev/null 2>&1; done
"$QCHAIN" keygen --out bank.json >/dev/null 2>&1
"$QCHAIN" keygen --out flooder.json >/dev/null 2>&1
"$QCHAIN" keygen --out bob.json >/dev/null 2>&1
BANK="$("$QCHAIN" address --keypair bank.json 2>/dev/null)"
FLOODER="$("$QCHAIN" address --keypair flooder.json 2>/dev/null)"
BOB="$("$QCHAIN" address --keypair bob.json 2>/dev/null)"
for i in $(seq 1 "$NODES"); do
  BUNDLE="$("$QCHAIN" bundle --keypair "v$i.json" 2>/dev/null)"
  printf '{"pubkey_bundle":%s,"listen_addr":"%s","rpc_addr":"127.0.0.1:%s","stake":1000000000}\n' \
    "$BUNDLE" "$(p2p "$i")" "$((8400+i))" > "manifests/v$i.json"
done
# bank (transferencia discreta de convergencia) y flooder (tráfico de fondo) son
# cuentas SEPARADAS: dos `qchain transfer` concurrentes desde la MISMA cuenta
# compiten por el nonce y uno falla, así que el flood no debe compartir cuenta
# con el chequeo de convergencia.
echo "[{\"address\":\"$BANK\",\"balance\":1000000000000000},{\"address\":\"$FLOODER\",\"balance\":1000000000000000}]" > genesis.json
"$GB" --manifests-dir manifests --genesis genesis.json --out-dir out --round-interval-ms 400 --economics-v7 --rounds-per-quanto "$RPQ" >/dev/null 2>&1

start_node() { # $1 = index
  local i="$1"; mkdir -p "n$i/data"; cp "out/node$i.json" "n$i/node.json"; cp "v$i.json" "n$i/keypair.json"
  # `( cd .. && exec node ) &` → $! es el PID del nodo (exec reemplaza el subshell),
  # así el kill posterior apunta al proceso real.
  ( cd "n$i" && exec env RUST_LOG=warn "$NODE" --config node.json > node.log 2>&1 ) &
  local pid=$!
  echo "$pid" > "n$i/pid"; PIDS+=("$pid")
}
for i in $(seq 1 "$NODES"); do start_node "$i"; done
echo "== esperando arranque de la malla =="; sleep 8

root_at() { curl -s "$(rpc "$1")/root" 2>/dev/null | grep -o '"root":"[0-9a-f]*"' | cut -d'"' -f4; }
round_of() { local r; r="$(curl -s "$(rpc "$1")/status" 2>/dev/null | grep -o '"next_round":[0-9]*' | cut -d: -f2)"; echo "${r:-0}"; }
exec_of()  { local e; e="$(curl -s "$(rpc "$1")/status" 2>/dev/null | grep -o '"executed_transactions":[0-9]*' | cut -d: -f2)"; echo "${e:-}"; }
bob_of()   { local b; b="$(curl -s "$(rpc "$1")/account/$BOB" 2>/dev/null | grep -o '"balance":[0-9]*' | cut -d: -f2)"; echo "${b:-}"; }
up() { curl -s "$(rpc "$1")/status" >/dev/null 2>&1; }
# primer nodo VIVO (para submitir la tx cuando el submitter habitual está caído)
live_node() { for i in $(seq 1 "$NODES"); do up "$i" && { echo "$i"; return; }; done; echo ""; }
# El STATE ROOT es función determinista del nº de tx EJECUTADAS, no de la ronda de
# consenso (la ejecución va DETRÁS del ordenamiento, así que dos nodos honestos a
# la misma `next_round` tienen roots distintos legítimamente). Por eso el chequeo
# de fork se keyea por `executed_transactions`, con doble-lectura para que el root
# corresponda a ese conteo (si el conteo cambió entre lecturas, la muestra se
# descarta). exec=N en dos nodos ⟹ MISMO root, o hay fork.
root_at_exec() { # imprime "EXEC ROOT" si la lectura fue estable, si no vacío
  local i="$1" e1 rt e2
  e1="$(exec_of "$i")"; rt="$(root_at "$i")"; e2="$(exec_of "$i")"
  if [ -n "$e1" ] && [ -n "$rt" ] && [ "$e1" = "$e2" ]; then echo "$e1 $rt"; fi
}

# Convergencia REAL: (1) una tx NUEVA a bob debe FINALIZAR (el saldo de bob sube
# en el nodo que la admite) — prueba de no-pérdida; (2) todos los nodos VIVOS
# deben converger a ESE saldo de bob; (3) ningún par de nodos vivos reporta roots
# DISTINTOS a la misma ronda (no-fork).
converge_check() { # $1 = etiqueta
  # el monto DEBE superar el dust_threshold (1e6 unidades) o la barrida de polvo
  # lo quema y bob nunca recibe — usamos 5M+ (0.005 QCH) por transferencia.
  local label="$1" amt=$((5000000 + RANDOM))
  local sub; sub="$(live_node)"
  if [ -z "$sub" ]; then echo "  ✗ $label: NINGÚN nodo vivo"; FAIL=$((FAIL+1)); return 1; fi
  local before; before="$(bob_of "$sub")"; before="${before:-0}"
  "$QCHAIN" transfer --rpc "$(rpc "$sub")" --keypair bank.json --to "$BOB" --amount "$amt" >/dev/null 2>&1
  local want=$((before + amt))
  local finalized=0 conflict=0
  for _try in $(seq 1 30); do
    sleep 1
    # (3) chequeo de fork: roots keyeados por nº de tx EJECUTADAS entre nodos vivos
    local -A byexec=(); conflict=0
    for i in $(seq 1 "$NODES"); do
      up "$i" || continue
      local pair e rt; pair="$(root_at_exec "$i")"
      [ -z "$pair" ] && continue
      e="${pair%% *}"; rt="${pair##* }"
      if [ -n "${byexec[$e]:-}" ]; then
        if [ "${byexec[$e]}" != "$rt" ]; then conflict=1; fi
      else byexec[$e]="$rt"; fi
    done
    if [ "$conflict" = 1 ]; then
      echo "  ✗ $label: ROOTS DIVERGENTES al mismo nº de tx ejecutadas (FORK)"
      for i in $(seq 1 "$NODES"); do up "$i" && echo "      n$i: $(root_at_exec "$i")"; done
      FAIL=$((FAIL+1)); return 1
    fi
    # (1)+(2): bob alcanzó `want` en TODOS los nodos vivos
    local allreached=1 seen=0
    for i in $(seq 1 "$NODES"); do
      up "$i" || continue
      seen=$((seen+1))
      local b; b="$(bob_of "$i")"; b="${b:-0}"
      if [ "$b" -lt "$want" ]; then allreached=0; fi
    done
    if [ "$seen" -gt 0 ] && [ "$allreached" = 1 ]; then finalized=1; break; fi
  done
  if [ "$finalized" = 1 ]; then
    echo "  ✓ $label: convergió (tx finalizó, bob>=$want en todos los vivos, sin fork)"; PASS=$((PASS+1)); return 0
  else
    echo "  ✗ $label: la tx no finalizó en todos los vivos dentro del timeout (want=$want)"; FAIL=$((FAIL+1)); return 1
  fi
}

# tráfico de fondo desde `flooder` (cuenta aparte). Montos por ENCIMA del dust
# (5M unidades) para que aterricen, y espaciado 1.2s para que cada tx confirme
# antes de la próxima (evita colisiones de nonce del mismo pagador secuencial).
( trap - EXIT  # el subshell NO debe correr cleanup al terminar su loop
  for k in $(seq 1 300); do
    sub="$(live_node)"; [ -n "$sub" ] && "$QCHAIN" transfer --rpc "$(rpc "$sub")" --keypair flooder.json --to "$BOB" --amount 5000000 >/dev/null 2>&1
    sleep 1.2
  done ) &
FLOOD=$!; PIDS+=("$FLOOD")

echo "== ESCENARIO 0: baseline (sin fallas) =="
converge_check "baseline"

echo "== ESCENARIO 1: caída + recuperación (SIGTERM, reinicio elegante) =="
kill -TERM "$(cat n2/pid)" 2>/dev/null || true; sleep 3
echo "  (node2 detenido; la red debe seguir con quórum)"
converge_check "con-node2-caido"
start_node 2; sleep 6
converge_check "node2-reincorporado"

echo "== ESCENARIO 2: corte de energía (SIGKILL, ungraceful) =="
kill -9 "$(cat n3/pid)" 2>/dev/null || true; sleep 3
start_node 3; sleep 6
converge_check "node3-kill9-recuperado"

echo "== ESCENARIO 3: reinicio en BORDE DE ÉPOCA =="
# esperar cerca de un borde de quanto (rpq rondas) y matar/reiniciar node4 ahí
cur1="$(round_of 1)"; target=$(( ( cur1 / RPQ + 1 ) * RPQ ))
for w in $(seq 1 40); do if [ "$(round_of 1)" -ge "$((target-1))" ]; then break; fi; sleep 0.5; done
kill -9 "$(cat n4/pid)" 2>/dev/null || true; sleep 2; start_node 4; sleep 6
converge_check "node4-reinicio-en-borde-epoca"

if [ "$WITH_NETEM" = 1 ]; then
  echo "== ESCENARIO 4: pérdida/retraso/duplicación de paquetes (tc netem en lo) =="
  if command -v tc >/dev/null 2>&1 && tc qdisc add dev lo root netem loss 15% delay 40ms 20ms duplicate 5% 2>/dev/null; then
    converge_check "bajo-perdida-retraso-duplicacion"
    tc qdisc del dev lo root 2>/dev/null || true
    converge_check "tras-limpiar-netem"
  else
    echo "  -- SALTADO (tc/netem no disponible o sin permisos; en un VPS: sudo tc qdisc add dev <iface> root netem loss 15% delay 40ms duplicate 5%)"
  fi
fi

if [ "$WITH_PARTITION" = 1 ]; then
  echo "== ESCENARIO 5: partición de red (iptables) + sanación =="
  if command -v iptables >/dev/null 2>&1 && iptables -A INPUT -p tcp --dport "$((9400+1))" -j DROP 2>/dev/null; then
    iptables -A INPUT -p tcp --dport "$((9400+2))" -j DROP 2>/dev/null || true
    echo "  (node1/node2 particionados del resto)"; sleep 8
    iptables -D INPUT -p tcp --dport "$((9400+1))" -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$((9400+2))" -j DROP 2>/dev/null || true
    converge_check "tras-sanar-particion"
  else
    echo "  -- SALTADO (iptables no disponible o sin permisos)"
  fi
fi

if [ "$WITH_CORRUPTION" = 1 ]; then
  echo "== ESCENARIO 6: corrupción de archivo (registro de validadores v7) =="
  echo "  -- ver docs/PRE-LAUNCH-TESTPLAN.md: el nodo debe TOLERAR un registro de"
  echo "     validadores corrupto (fallback al comité de génesis) y HACER HALT (fail-loud)"
  echo "     ante un singleton de dinero corrupto. Requiere el helper de corrupción del store."
fi

echo ""
echo "======================================================================"
echo "RESULTADO CAOS LOCAL:  PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "✓ Todos los escenarios inyectados convergieron sin fork ni pérdida."
  echo "  (Esto NO reemplaza el soak multi-VPS de varias semanas — ver PRE-LAUNCH-TESTPLAN.md)"
  exit 0
else
  echo "✗ HUBO FALLAS — revisá los logs en $WORK/n*/node.log ANTES de continuar el gate."
  exit 1
fi
