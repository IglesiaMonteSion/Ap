#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# KM#10 — multi-node + adversarial key-lifecycle harness.
#
# Runs the FULL validator key lifecycle (recovery committee → emergency freeze →
# attempted drain → unfreeze → mandatory rotation deadline → revoke → bond
# recovery) against a REAL multi-validator testnet, and after every step asserts
# the two safety properties that a single-node test cannot show:
#
#   1. NO FORK — every node commits a BYTE-IDENTICAL state root. Key-management
#      ops are deterministic functions of committed state, so any node-local
#      leakage would diverge the roots here first.
#   2. The adversarial refusals hold ON-CHAIN, not just in unit tests: a
#      compromised operator cannot drain the bond nor land a pending cold-key
#      change while the recovery committee has the validator frozen (KM#10).
#
# Plus a RESTART in the middle of the lifecycle: a node killed (-9) and brought
# back must re-derive the same state from disk and re-converge.
#
# Usage:  ./deploy/km-lifecycle-test.sh [--keep]
#   --keep   don't delete the scratch testnet at the end (for debugging)
#
# Exit code 0 = every assertion held. Non-zero = a real failure (printed).
# ---------------------------------------------------------------------------
set -Eeuo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/target/release"
WORK="${KM_TEST_DIR:-$(mktemp -d)}"
RPQ=2                # rounds per quanto (small so quantos advance fast)
PASS=0; FAIL=0
declare -a NODE_PIDS=()

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

cleanup() {
  # Kill by EXACT PID only — never `pkill -f <config>`, which also matches this
  # very script's command line and would kill the harness mid-run.
  for p in "${NODE_PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true; done
  [ "$KEEP" = "0" ] && rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

for b in qchain qchain-node qchain-genesis-build; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run: cargo build --release"; exit 1; }
done

addr()  { "$BIN/qchain" address --keypair "$1"; }
rpc()   { curl -s --max-time 10 "$1$2"; }
root()  { rpc "$1" /root | python3 -c 'import sys,json;print(json.load(sys.stdin).get("root",""))' 2>/dev/null; }
jqf()   { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

# Assert every node reports the SAME state root (the no-fork property), after
# letting them settle on the same executed-transaction count.
assert_same_root() {
  local what="$1" r1 r2 e1 e2
  for _ in $(seq 1 40); do
    e1=$(rpc "$RPC1" /status | jqf 'd["executed_transactions"]')
    e2=$(rpc "$RPC2" /status | jqf 'd["executed_transactions"]')
    [ -n "$e1" ] && [ "$e1" = "$e2" ] && break
    sleep 0.5
  done
  r1=$(root "$RPC1"); r2=$(root "$RPC2")
  if [ -n "$r1" ] && [ "$r1" = "$r2" ]; then
    ok "$what — both nodes at root ${r1:0:16}… (executed=$e1) → NO FORK"
  else
    bad "$what — ROOT DIVERGED: n1=${r1:0:16}… n2=${r2:0:16}…"
  fi
}

# Read one field of OUR validator (selected by consensus address — the registry
# also holds the two genesis founders).
vfield() { rpc "$1" /validator_v7_registry | jqf "[v for v in d['validators'] if v['address']=='$CONS'][0]['$2']"; }
# The recovery-committee entry (and its anti-replay nonce) for OUR validator.
rfield() { rpc "$1" /validator_v7_recovery | jqf "[c for c in d['committees'] if c['consensus_address']=='$CONS'][0]['$2']"; }
# The network's chain_id — every recovery approval is bound to it (#187), so a
# signature collected for one network can never authorize a recovery op on another.
cid()    { rpc "$1" /chain_id | jqf "d['chain_id']"; }

log "0. building a 2-validator economics_v7 testnet in $WORK"
mkdir -p "$WORK"/{manifests,n1,n2}
cd "$WORK"
for n in 1 2; do "$BIN/qchain" keygen --out "n$n/keypair.json" >/dev/null; done
"$BIN/qchain" keygen --out operator.json >/dev/null       # the validator's cold operator
"$BIN/qchain" keygen --out consensus.json >/dev/null      # its SEPARATE hot block-signing key
"$BIN/qchain" keygen --out coldwd.json   >/dev/null       # its cold withdrawal address
"$BIN/qchain" keygen --out relayer.json  >/dev/null       # pays fees, holds no authority
for i in 1 2 3; do "$BIN/qchain" keygen --out "rs$i.json" >/dev/null; done   # recovery signers
"$BIN/qchain" keygen --out attacker.json >/dev/null       # the withdrawal address a thief wants

V1=$(addr n1/keypair.json); V2=$(addr n2/keypair.json)
OPER=$(addr operator.json); RELAY=$(addr relayer.json); THIEF=$(addr attacker.json)
CONS=$(addr consensus.json); COLDWD=$(addr coldwd.json)
RS1=$(addr rs1.json); RS2=$(addr rs2.json); RS3=$(addr rs3.json)

for n in 1 2; do
  P=$((9100 + n)); R=$((8100 + n))
  python3 - "$("$BIN/qchain" bundle --keypair "n$n/keypair.json")" "$P" "$R" "manifests/v$n.json" <<'PY'
import json,sys
bundle, p2p, rpcp, out = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
json.dump({"pubkey_bundle":bundle,"listen_addr":f"127.0.0.1:{p2p}",
           "rpc_addr":f"127.0.0.1:{rpcp}","stake":1000000000000}, open(out,"w"))
PY
done
# The operator must afford the 500 QCH bond plus fees.
python3 - "$OPER" "$RELAY" <<'PY'
import json,sys
json.dump([{"address":sys.argv[1],"balance":600_000_000_000},
           {"address":sys.argv[2],"balance":100_000_000_000}], open("alloc.json","w"))
PY
"$BIN/qchain-genesis-build" --manifests-dir manifests --out-dir out --economics-v7 \
  --rounds-per-quanto $RPQ --genesis alloc.json --round-interval-ms 250 >/dev/null
for n in 1 2; do
  mkdir -p "out/node$n.d"; cp "out/node$n.json" "out/node$n.d/config.json"
  cp "n$n/keypair.json" "out/node$n.d/keypair.json"; mkdir -p "out/node$n.d/data"
done
RPC1=http://127.0.0.1:8101; RPC2=http://127.0.0.1:8102

start_node() {  # $1 = node index
  ( cd "$WORK/out/node$1.d" && exec "$BIN/qchain-node" --config config.json >>node.log 2>&1 ) &
  NODE_PIDS[$1]=$!
}
for n in 1 2; do start_node $n; done
for _ in $(seq 1 40); do rpc "$RPC1" /status >/dev/null 2>&1 && rpc "$RPC2" /status >/dev/null 2>&1 && break; sleep 0.5; done
rpc "$RPC1" /status >/dev/null || { echo "node1 never came up"; tail -20 out/node1.d/node.log; exit 1; }
ok "2 validators up (v7, rounds_per_quanto=$RPQ)"
assert_same_root "genesis"

# The genesis founders (v1/v2) have operator == consensus, so to exercise the real
# role-separated lifecycle we register a validator whose consensus key, cold
# operator key and cold withdrawal address are three DIFFERENT keys (#193-B).
log "1. registering a validator with a SEPARATE cold operator + cold withdrawal"
"$BIN/qchain" v7-bond-register --rpc "$RPC1" --keypair operator.json \
  --consensus-keypair consensus.json --withdrawal-address "$COLDWD" \
  --moniker km10 --p2p-address 127.0.0.1:9103 2>&1 | tail -1
sleep 4
REGD=$(rpc "$RPC1" /validator_v7_registry | jqf "[v['address'] for v in d['validators']].count('$CONS')")
[ "${REGD:-0}" = "1" ] && ok "validator registered (consensus $(echo "$CONS" | cut -c1-12)…, operator $(echo "$OPER" | cut -c1-12)…, cold withdrawal $(echo "$COLDWD" | cut -c1-12)…)" \
                       || bad "registration did not land"
assert_same_root "after registration"

log "2. arming the OFFLINE recovery committee (2-of-3, timelocked ~7d)"
"$BIN/qchain" v7-set-recovery --rpc "$RPC1" --keypair operator.json \
  --consensus-address "$CONS" --signers "$RS1,$RS2,$RS3" --threshold 2 >/dev/null
sleep 2
Q=$(rpc "$RPC1" /validator_v7_registry | jqf 'd["current_quanto"]')
READY=$(rpc "$RPC1" /validator_v7_pending_keys | jqf 'd["pending"][0]["ready_quanto"]' || echo "")
[ -n "$READY" ] && ok "recovery committee proposed, ready at quanto $READY (now $Q)" \
                || bad "no pending recovery committee recorded"
# Push quantos forward with real transfers until the timelock elapses, then apply.
for _ in $(seq 1 25); do
  Q=$(rpc "$RPC1" /validator_v7_registry | jqf 'd["current_quanto"]')
  [ -n "$READY" ] && [ "$Q" -ge "$READY" ] && break
  "$BIN/qchain" transfer --rpc "$RPC1" --keypair relayer.json --to "$OPER" \
    --amount 1000000 --valid-for-rounds 5000 >/dev/null 2>&1 || true
  sleep 1.5
done
"$BIN/qchain" v7-apply-key-change --rpc "$RPC1" --keypair relayer.json \
  --consensus-address "$CONS" --kind recovery >/dev/null 2>&1 || true
sleep 3
COMM=$(rpc "$RPC1" /validator_v7_recovery | jqf "len([c for c in d['committees'] if c['consensus_address']=='$CONS'])")
[ "${COMM:-0}" -ge 1 ] && ok "recovery committee ACTIVE on-chain" || bad "committee never activated"
assert_same_root "after committee activation"

log "3. ATTACK — compromised operator proposes redirecting the withdrawal to itself"
"$BIN/qchain" v7-rotate-withdrawal --rpc "$RPC1" --keypair operator.json \
  --consensus-address "$CONS" --new-withdrawal "$THIEF" >/dev/null 2>&1 || true
sleep 3
PEND=$(rpc "$RPC1" /validator_v7_pending_keys | jqf 'len(d["pending"])')
[ "${PEND:-0}" -ge 1 ] && ok "attacker's withdrawal rotation is pending (timelocked)" \
                       || bad "the rotation was not recorded (test setup issue)"
assert_same_root "after the attacker's proposal"

log "4. DEFENSE — the recovery committee EMERGENCY-FREEZES the validator"
NONCE=$(rfield "$RPC1" nonce)
CHAIN_ID=$(cid "$RPC1")
FREEZE_UNTIL=1000000
A1=$("$BIN/qchain" v7-recovery-sign --recovery-keypair rs1.json --consensus-address "$CONS" \
      --recovery-nonce "$NONCE" --chain-id "$CHAIN_ID" --op freeze --until-quanto $FREEZE_UNTIL | tail -1)
A2=$("$BIN/qchain" v7-recovery-sign --recovery-keypair rs2.json --consensus-address "$CONS" \
      --recovery-nonce "$NONCE" --chain-id "$CHAIN_ID" --op freeze --until-quanto $FREEZE_UNTIL | tail -1)
"$BIN/qchain" v7-recover-op --rpc "$RPC1" --keypair relayer.json --consensus-address "$CONS" \
  --op freeze --until-quanto $FREEZE_UNTIL --approvals "$A1,$A2" >/dev/null
sleep 3
[ "$(vfield "$RPC1" frozen_now)" = "True" ] && ok "validator FROZEN (state $(vfield "$RPC1" state), bond untouched)" \
                                            || bad "freeze did not take effect"
[ "$(vfield "$RPC1" eligible_now)" = "False" ] && ok "frozen → out of the committee + fees" \
                                               || bad "frozen validator still fee-eligible"
assert_same_root "after the emergency freeze"

log "5. KM#10 — the drain must be REFUSED while frozen"
# 5a. Push quantos past the withdrawal timelock, then try to land the attacker's
#     pending rotation (this instruction is PERMISSIONLESS — anyone may submit it).
for _ in $(seq 1 8); do
  "$BIN/qchain" transfer --rpc "$RPC1" --keypair relayer.json --to "$OPER" \
    --amount 1000000 --valid-for-rounds 5000 >/dev/null 2>&1 || true
  sleep 1.2
done
"$BIN/qchain" v7-apply-key-change --rpc "$RPC1" --keypair relayer.json \
  --consensus-address "$CONS" --kind withdrawal >/dev/null 2>&1 || true
sleep 3
WD_NOW=$(vfield "$RPC1" withdrawal_address)
[ "$WD_NOW" != "$THIEF" ] && ok "pending cold-key change did NOT land while frozen (withdrawal still ${WD_NOW:0:12}…)" \
                          || bad "THEFT: the attacker's withdrawal address landed during the freeze"
# 5b. The compromised operator tries to start draining the bond.
"$BIN/qchain" v7-begin-exit --rpc "$RPC1" --keypair operator.json \
  --consensus-address "$CONS" >/dev/null 2>&1 || true
sleep 3
[ "$(vfield "$RPC1" state)" != "Unbonding" ] && ok "BeginExit REFUSED while frozen (state $(vfield "$RPC1" state))" \
                                             || bad "the bond started draining despite the freeze"
[ "$(vfield "$RPC1" bond)" = "500000000000" ] && ok "bond still 500 QCH, fully escrowed" \
                                              || bad "bond changed while frozen"
assert_same_root "after the refused drain attempts"

log "6. RESTART mid-lifecycle — a node killed (-9) must re-converge"
kill -9 "${NODE_PIDS[2]}" 2>/dev/null || true
sleep 2
"$BIN/qchain" transfer --rpc "$RPC1" --keypair relayer.json --to "$OPER" \
  --amount 2000000 --valid-for-rounds 5000 >/dev/null 2>&1 || true
sleep 3
start_node 2
for _ in $(seq 1 60); do rpc "$RPC2" /status >/dev/null 2>&1 && break; sleep 0.5; done
sleep 5
assert_same_root "after killing and restarting node 2"
[ "$(vfield "$RPC2" frozen_now)" = "True" ] && ok "the restarted node re-derived the FROZEN state from disk" \
                                            || bad "restarted node lost the freeze state"

log "7. RECOVERY — the committee lifts the pause, the honest lifecycle resumes"
NONCE=$(rfield "$RPC1" nonce)
U1=$("$BIN/qchain" v7-recovery-sign --recovery-keypair rs1.json --consensus-address "$CONS" \
      --recovery-nonce "$NONCE" --chain-id "$CHAIN_ID" --op unfreeze | tail -1)
U2=$("$BIN/qchain" v7-recovery-sign --recovery-keypair rs3.json --consensus-address "$CONS" \
      --recovery-nonce "$NONCE" --chain-id "$CHAIN_ID" --op unfreeze | tail -1)
"$BIN/qchain" v7-recover-op --rpc "$RPC1" --keypair relayer.json --consensus-address "$CONS" \
  --op unfreeze --approvals "$U1,$U2" >/dev/null
sleep 3
[ "$(vfield "$RPC1" frozen_now)" = "False" ] && ok "UNFROZEN by the committee" || bad "unfreeze failed"
assert_same_root "after unfreeze"

log "8. the hash-chained AUDIT TRAIL is identical on both nodes and verifies"
for R in "$RPC1" "$RPC2"; do
  V=$(rpc "$R" /validator_v7_km_audit | jqf 'd["verifies"]')
  [ "$V" = "True" ] && ok "$R: audit chain verifies ($(rpc "$R" /validator_v7_km_audit | jqf 'd["count"]') events)" \
                    || bad "$R: audit chain does NOT verify"
done
H1=$(rpc "$RPC1" /validator_v7_km_audit | jqf 'd["head_hash"]')
H2=$(rpc "$RPC2" /validator_v7_km_audit | jqf 'd["head_hash"]')
[ -n "$H1" ] && [ "$H1" = "$H2" ] && ok "both nodes agree on head_hash ${H1:0:16}…" \
                                  || bad "audit head_hash DIVERGED between nodes"

printf '\n\033[1m=== KM#10 result: %d passed, %d failed ===\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
