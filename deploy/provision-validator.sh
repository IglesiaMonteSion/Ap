#!/usr/bin/env bash
# Bootstraps a fresh Debian/Ubuntu VPS to run a qchain validator as a
# systemd-managed Docker container - see docs/DEPLOY.md for the full
# multi-region flow this fits into (this script only covers "get one
# empty VPS ready to receive a config.json/keypair.json and start").
#
# Usage (as root or via sudo):
#   ./provision-validator.sh <image-name-or-path>
#
# After this script finishes, copy config.json + keypair.json into
# /opt/qchain (data/ is created empty for you if config.json sets
# data_dir), then:
#   systemctl enable --now qchain-validator
set -euo pipefail

IMAGE="${1:-qchain:latest}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run this as root (sudo ./provision-validator.sh)" >&2
  exit 1
fi

echo "== installing Docker if missing =="
if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io
else
  echo "docker already installed, skipping"
fi

echo "== opening firewall ports (ufw, if present) =="
# listen_addr and rpc_addr default to 9000/8080 in docs/DEPLOY.md's
# examples - open both plus SSH. Adjust if your config.json uses
# different ports.
if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH || true
  ufw allow 9000/tcp comment 'qchain p2p'
  ufw allow 8080/tcp comment 'qchain rpc'
  ufw --force enable
else
  echo "ufw not found, skipping firewall setup - configure your provider's security group manually"
fi

echo "== syncing clock (NTP) =="
# Round timing (round_interval_ms) is wall-clock driven on each
# validator independently, not coordinated by a shared clock - but a
# validator whose clock has drifted far from its peers' will still log
# and propose on its own schedule, making its round-checkpoint recovery
# and log timestamps hard to correlate against other regions' logs
# during an incident. Cheap insurance for a multi-region deployment.
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-ntp true || true
else
  echo "timedatectl not found, skipping - ensure NTP is running some other way"
fi

echo "== creating /opt/qchain =="
mkdir -p /opt/qchain
echo "load the image: docker load -i qchain-image.tar   (or) docker pull <registry>/$IMAGE"
echo "then: docker tag <whatever-you-loaded> qchain:latest   (systemd unit expects this tag)"

echo "== installing systemd unit =="
cp "$(dirname "$0")/systemd/qchain-validator.service" /etc/systemd/system/qchain-validator.service
systemctl daemon-reload

cat <<EOF

Done. Next steps:
  1. Get the qchain image onto this machine (docker load / docker pull), tag it qchain:latest
  2. Copy this validator's config.json + keypair.json into /opt/qchain
  3. systemctl enable --now qchain-validator
  4. journalctl -u qchain-validator -f    # watch it come up
EOF
