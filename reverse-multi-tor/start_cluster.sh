#!/usr/bin/env bash
# ==============================================================================
# Master launch script for 10 Tor Nodes Reverse Cluster
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# 1. Ensure all 10 Tor ports are active (checking last port 9059)
if ! nc -z 127.0.0.1 9059 2>/dev/null && ! (echo > /dev/tcp/127.0.0.1/9059) 2>/dev/null; then
    echo "[*] Tor 10-port cluster is not configured or port 9059 is closed."
    echo "[*] Configuring /etc/tor/torrc and restarting Tor..."
    sudo bash start_tor.sh
fi

# 2. Run Python Multi-Agent Cluster
echo "[*] Starting 10 Reverse Agents connected to control server..."
python3 cluster.py --config config.json
