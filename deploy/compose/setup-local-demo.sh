#!/usr/bin/env bash
# Builds a 3-validator + faucet demo under deploy/compose/{v1,v2,v3,faucet}
# ready for `docker compose up --build`. This is a LOCAL SMOKE TEST of the
# Docker image on one host, not a real multi-region deployment - real
# deployments give each validator its own real machine/public IP and use
# `qchain-genesis-build` directly with manifests from real participants
# (see docs/DEPLOY.md). Requires the qchain binaries built locally first
# (`cargo build --release --workspace`) - keygen/bundle/genesis-build run
# natively here, only the validators themselves run inside Docker.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN="../../target/release"
if [ ! -x "$BIN/qchain" ] || [ ! -x "$BIN/qchain-node" ] || [ ! -x "$BIN/qchain-genesis-build" ] || [ ! -x "$BIN/qchain-faucet" ]; then
  echo "release binaries not found - run: cargo build --release --workspace" >&2
  exit 1
fi

rm -rf v1 v2 v3 faucet manifests genesis.json
mkdir -p v1 v2 v3 faucet manifests

STATIC_IPS=(172.28.0.11 172.28.0.12 172.28.0.13)
for i in 1 2 3; do
  ip="${STATIC_IPS[$((i-1))]}"
  "$BIN/qchain" keygen --out "v$i/keypair.json" >/dev/null
  bundle=$("$BIN/qchain" bundle --keypair "v$i/keypair.json")
  cat > "manifests/v$i.json" <<EOF
{ "pubkey_bundle": $bundle, "listen_addr": "$ip:9000", "rpc_addr": "0.0.0.0:8080", "stake": 1000000 }
EOF
done

"$BIN/qchain" keygen --out faucet/keypair.json >/dev/null
faucet_addr=$("$BIN/qchain" address --keypair faucet/keypair.json)
cat > genesis.json <<EOF
[ { "address": "$faucet_addr", "balance": 1000000000000 } ]
EOF

"$BIN/qchain-genesis-build" --manifests-dir manifests --genesis genesis.json --out-dir . --round-interval-ms 1000
for i in 1 2 3; do
  mv "node$i.json" "v$i/config.json"
done
rm -rf manifests genesis.json

echo
echo "Demo faucet wallet: $faucet_addr (funded 1,000,000,000,000 units at genesis)"
echo "Ready - run: docker compose up --build"
echo "Then e.g.: curl -X POST http://127.0.0.1:9090/faucet -H 'content-type: application/json' -d '{\"address\":\"<your address>\"}'"
