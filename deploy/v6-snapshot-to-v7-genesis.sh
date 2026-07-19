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
#    The node serves a CONSISTENT cached snapshot (short TTL); we pin its round +
#    merkle_root up front and REQUIRE every page to carry the same root, so a
#    cache rotation or an advancing (non-frozen) node can never stitch pages from
#    two different states into a torn genesis (audit fix).
META="$(curl -fsS "$RPC/snapshot/meta")" || { echo "no pude leer $RPC/snapshot/meta (¿nodo v6 arriba?)" >&2; exit 1; }
echo "snapshot meta: $META" >&2
if [ "$META_ONLY" = "1" ]; then echo "$META"; exit 0; fi
EXPECT_ROUND="$(printf '%s' "$META" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("round",""))')"
EXPECT_ROOT="$(printf '%s' "$META" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("merkle_root",""))')"
EXPECT_COUNT="$(printf '%s' "$META" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("account_count",0))')"
[ -n "$EXPECT_ROOT" ] || { echo "meta sin merkle_root — nodo demasiado viejo" >&2; exit 1; }

# 2) page through /snapshot/page?after=<addr> (keyset pagination, stable page size)
#    accumulating {address,balance,owner}. Each page's parser VERIFIES the page's
#    merkle_root matches EXPECT_ROOT and exits non-zero on any parse/mismatch — no
#    `|| true` swallowing errors (which would silently truncate the genesis).
TMP="$(mktemp)"; TMPM="$(mktemp)"; trap 'rm -f "$TMP" "$TMPM" "$TMP.page"' EXIT
AFTER=""
PAGES=0
SEEN_TOTAL=0
while :; do
  if [ -z "$AFTER" ]; then URL="$RPC/snapshot/page"; else URL="$RPC/snapshot/page?after=$AFTER"; fi
  curl -fsS "$URL" > "$TMP.page" || { echo "fallo al leer una página: $URL" >&2; exit 1; }
  # parse.py: verify root, emit account lines to stdout, write CURSOR:/COUNT: markers
  # to stderr, and EXIT NON-ZERO on bad JSON or a root mismatch (no error swallowed).
  if ! python3 - "$TMP.page" "$EXPECT_ROOT" >> "$TMP" 2> "$TMPM" <<'PY'
import sys, json
page_file, expect_root = sys.argv[1], sys.argv[2]
try:
    with open(page_file) as f: p = json.load(f)
except Exception as e:
    sys.stderr.write("PARSE_ERROR:%s\n" % e); sys.exit(2)
root = str(p.get("merkle_root", ""))
if root != expect_root:
    sys.stderr.write("ROOT_MISMATCH:%s\n" % root); sys.exit(3)
accts = p.get("accounts") or []
last = ""; n = 0
for a in accts:
    addr = a.get("address")
    acc  = a.get("account") or {}
    if addr is None: continue
    print(json.dumps({"address": addr, "balance": str(acc.get("balance", 0)), "owner": str(acc.get("owner", ""))}))
    last = addr; n += 1
sys.stderr.write("CURSOR:%s\nCOUNT:%d\n" % (last, n))
PY
  then
    echo "página $PAGES inválida (parse/mismatch): $(cat "$TMPM")" >&2
    echo "el snapshot rotó a mitad de la descarga o el nodo no está congelado — abortá, congelá v6 y reintentá" >&2
    exit 1
  fi
  PAGES=$((PAGES+1))
  LAST="$(sed -n 's/^CURSOR://p' "$TMPM" | tail -1)"
  PCOUNT="$(sed -n 's/^COUNT://p' "$TMPM" | tail -1)"
  SEEN_TOTAL=$((SEEN_TOTAL + ${PCOUNT:-0}))
  : > "$TMPM"
  if [ -z "$LAST" ] || [ "$LAST" = "$AFTER" ]; then break; fi
  AFTER="$LAST"
  if [ "$PAGES" -ge 100000 ]; then echo "demasiadas páginas, abortando" >&2; exit 1; fi
done

# 2b) confirm the snapshot did NOT rotate under us: re-read meta, require the same
#     round + root, and that we saw exactly account_count accounts.
META2="$(curl -fsS "$RPC/snapshot/meta")" || { echo "no pude re-leer meta" >&2; exit 1; }
ROUND2="$(printf '%s' "$META2" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("round",""))')"
ROOT2="$(printf '%s' "$META2" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("merkle_root",""))')"
if [ "$ROUND2" != "$EXPECT_ROUND" ] || [ "$ROOT2" != "$EXPECT_ROOT" ]; then
  echo "el snapshot cambió durante la descarga (round $EXPECT_ROUND/$ROUND2, root $EXPECT_ROOT/$ROOT2) — congelá v6 y reintentá" >&2
  exit 1
fi
if [ "$SEEN_TOTAL" != "$EXPECT_COUNT" ]; then
  echo "conté $SEEN_TOTAL cuentas pero meta dice $EXPECT_COUNT — descarga incompleta, abortando" >&2
  exit 1
fi
echo "snapshot íntegro: round $EXPECT_ROUND, $SEEN_TOTAL/$EXPECT_COUNT cuentas, root $EXPECT_ROOT" >&2

# 3) filter to system-owned user wallets with balance>0, dedup, sort by address, emit.
python3 - "$TMP" "$OUT" "$SYSTEM_PROGRAM" <<'PY'
import sys, json
tmp, out, sysprog = sys.argv[1], sys.argv[2], sys.argv[3]
seen = {}
skipped_prog = 0
skipped_zero = 0
dropped_prog_balance = 0   # QCH held in program-owned accounts NOT carried (esp. STAKED principal)
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
            skipped_prog += 1
            if bal > 0: dropped_prog_balance += bal
            continue
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
if dropped_prog_balance > 0:
    sys.stderr.write(
        "\n*** ATENCIÓN: NO se carga el principal STAKEADO ni el de los pools ***\n"
        f"    {dropped_prog_balance} units = {dropped_prog_balance/1e9:.6f} QCH viven en cuentas\n"
        "    program-owned (cuentas de stake de usuarios + pools) y NO se incluyen en el\n"
        "    genesis v7 (v7 tiene un staking nuevo shares+índice; el ledger v6 no migra).\n"
        "    Si querés que los usuarios conserven lo que tenían STAKEADO, pediles que\n"
        "    DESSTAKEEN (Undelegate) ANTES de congelar la red v6 — así su principal vuelve\n"
        "    a su wallet líquida y SÍ se carga. Lo que dejen stakeado se pierde en v7.\n")
PY

echo ""
echo "OK. $OUT lists the v6 user-wallet balances to carry into the v7 genesis."
echo "IMPORTANT: every coordinator must build the v7 genesis from the SAME snapshot"
echo "round (agree on it via --meta) and the SAME manifests, or the chain_id will differ."
