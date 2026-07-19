#!/usr/bin/env bash
# v6-snapshot-to-v7-genesis.sh
#
# Coordinated v7 relaunch helper: read the account balances of a running v6 (or
# any) qchain node and emit a v7 GENESIS ALLOCATIONS file
# (`[{ "address": ..., "balance": ... }]`) so those balances CARRY OVER into the
# fresh v7 genesis.
#
# WHY this exists: v7 is a HARD FORK with a brand-new genesis — it does NOT
# migrate the old ledger. If you want holders to keep their QCH after the
# relaunch, you must snapshot their balances and encode them as v7 genesis
# allocations. This tool builds that file from the live v6 node, deterministically.
#
# WHAT it carries: only real USER WALLETS — accounts owned by the System Program
# with a positive balance. Program-owned singletons (the v6 staking pool, params,
# fee-state, registry, etc.) are DELIBERATELY skipped: v7 seeds its own economic
# singletons at genesis (§15), so carrying the v6 ones would be wrong.
#
# DETERMINISM: sorted by address, so every coordinator that runs this against the
# same snapshot round produces a BYTE-IDENTICAL file → the same v7 genesis →
# the same chain_id. Pin the round with --meta first and agree on it.
#
# Usage:
#   deploy/v6-snapshot-to-v7-genesis.sh --rpc http://127.0.0.1:8080 --out v7-genesis.json
#   deploy/v6-snapshot-to-v7-genesis.sh --rpc http://127.0.0.1:8080 --meta   # just show round+root+count
#
# Then feed the file to the genesis build:
#   qchain-genesis-build --manifests-dir ./m --genesis v7-genesis.json \
#       --out-dir ./out --economics-v7 --rounds-per-quanto <n>
#
set -Eeuo pipefail

RPC=""
OUT="v7-genesis.json"
META_ONLY=0
SYSTEM_PROGRAM="11111111111111111111111111111111"   # System Program id (owner of user wallets)

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --meta) META_ONLY=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "flag desconocida: $1" >&2; usage 1 ;;
  esac
done

[ -n "$RPC" ] || { echo "falta --rpc <url del nodo v6>" >&2; usage 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 es necesario" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl es necesario" >&2; exit 1; }

RPC="${RPC%/}"

# 1) snapshot meta (round + root + account count) — the point-in-time being carried.
META="$(curl -fsS "$RPC/snapshot/meta")" || { echo "no pude leer $RPC/snapshot/meta (¿nodo v6 arriba?)" >&2; exit 1; }
echo "snapshot meta: $META" >&2
if [ "$META_ONLY" = "1" ]; then echo "$META"; exit 0; fi

# 2) page through /snapshot/page?after=<addr> (keyset pagination, stable page size)
#    accumulating {address,balance,owner}. Filter + sort + emit happens in python.
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
AFTER=""
PAGES=0
while :; do
  if [ -z "$AFTER" ]; then URL="$RPC/snapshot/page"; else URL="$RPC/snapshot/page?after=$AFTER"; fi
  PAGE="$(curl -fsS "$URL")" || { echo "fallo al leer una página: $URL" >&2; exit 1; }
  # append raw page json (one per line) and get the last address for the next cursor
  NEXT="$(printf '%s' "$PAGE" | python3 -c '
import sys, json
p = json.load(sys.stdin)
accts = p.get("accounts") or []
# each entry is {"address": <base58>, "account": {"balance":.., "owner":<base58>, ..}}
last = ""
for a in accts:
    addr = a.get("address")
    acc  = a.get("account") or {}
    if addr is None: continue
    print(json.dumps({"address": addr, "balance": str(acc.get("balance", 0)), "owner": str(acc.get("owner", ""))}))
    last = addr
sys.stderr.write("CURSOR:" + last + "\n")
' 2>>"$TMP.cursor" >>"$TMP")" || true
  PAGES=$((PAGES+1))
  LAST="$(sed -n 's/^CURSOR://p' "$TMP.cursor" | tail -1)"
  : >"$TMP.cursor"
  # stop when the page returned no new accounts (empty cursor) or didn't advance
  if [ -z "$LAST" ] || [ "$LAST" = "$AFTER" ]; then break; fi
  AFTER="$LAST"
  # hard cap so a misbehaving endpoint can't loop forever
  if [ "$PAGES" -ge 100000 ]; then echo "demasiadas páginas, abortando" >&2; exit 1; fi
done
rm -f "$TMP.cursor"

# 3) filter to system-owned user wallets with balance>0, dedup, sort by address, emit.
python3 - "$TMP" "$OUT" "$SYSTEM_PROGRAM" <<'PY'
import sys, json
tmp, out, sysprog = sys.argv[1], sys.argv[2], sys.argv[3]
seen = {}
skipped_prog = 0
skipped_zero = 0
with open(tmp) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        a = json.loads(line)
        addr, owner = a["address"], a.get("owner", "")
        try: bal = int(a["balance"])
        except: bal = 0
        # only real user wallets (owned by the System Program)
        if owner != sysprog:
            skipped_prog += 1; continue
        if bal <= 0:
            skipped_zero += 1; continue
        seen[addr] = bal   # dedup by address (snapshot is unique already)
# balance is a bare JSON integer (the genesis schema wants u64, not a string).
# Python ints are arbitrary-precision and json.dump writes them exactly (never
# via float), so a value up to u64::MAX round-trips without rounding.
allocs = [{"address": a, "balance": b} for a, b in sorted(seen.items())]
with open(out, "w") as f:
    json.dump(allocs, f, indent=2)
total = sum(b for b in seen.values())
sys.stderr.write(f"wrote {len(allocs)} user-wallet allocations to {out} "
                 f"(total {total} units = {total/1e9:.6f} QCH); "
                 f"skipped {skipped_prog} program-owned + {skipped_zero} zero-balance\n")
PY

echo ""
echo "OK. $OUT lists the v6 user-wallet balances to carry into the v7 genesis."
echo "IMPORTANT: every coordinator must build the v7 genesis from the SAME snapshot"
echo "round (agree on it via --meta) and the SAME manifests, or the chain_id will differ."
