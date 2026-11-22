#!/usr/bin/env bash
# ==============================================================================
# Setup 50-Port Multi-Tor Service on Ubuntu/Debian
# Configures system Tor daemon (/etc/tor/torrc) with 50 isolated SOCKS ports
# ==============================================================================
set -e

echo "=========================================================="
echo "          Setting up 50-Port Multi-Tor Service            "
echo "=========================================================="

# 1. Install Tor if missing
if ! command -v tor &> /dev/null; then
    echo "[*] Tor not found. Installing via apt..."
    sudo apt-get update -y
    sudo apt-get install -y tor
fi

# 2. Configure /etc/tor/torrc with 10 isolated ports
TORRC="/etc/tor/torrc"

if [ -f "$TORRC" ]; then
    echo "[*] Configuring $TORRC with 10 isolated ports (9050..9059)..."
    
    # Remove any existing multi-tor block to prevent duplicates
    sudo sed -i '/# BEGIN MULTI-TOR CLUSTER/,/# END MULTI-TOR CLUSTER/d' "$TORRC"

    # Append fresh 10-port cluster block
    sudo python3 -c '
import sys

start_port = 9050
count = 10
control_port = 9049

lines = [
    "\n# BEGIN MULTI-TOR CLUSTER",
    "ControlPort 127.0.0.1:%d" % control_port,
    "CookieAuthentication 0",
    "ClientOnly 1",
    "ExitRelay 0",
]
for i in range(count):
    port = start_port + i
    lines.append("SocksPort 127.0.0.1:%d IsolateDestAddr IsolateDestPort" % port)
lines.append("# END MULTI-TOR CLUSTER\n")

with open("/etc/tor/torrc", "a", encoding="utf-8") as f:
    f.write("\n".join(lines))
'
    echo "[*] Verifying Tor configuration..."
    if sudo tor --verify-config -f "$TORRC" > /dev/null 2>&1; then
        echo "[OK] Configuration syntax verified successfully."
    fi

    echo "[*] Restarting system Tor service..."
    sudo systemctl restart tor 2>/dev/null || sudo systemctl restart tor@default 2>/dev/null || true
else
    # Fallback for environments without /etc/tor/torrc (e.g. non-root / standalone)
    echo "[*] /etc/tor/torrc not found, generating local torrc..."
    python3 generate_torrc.py --count 10 --start-port 9050 --output torrc
    
    # Kill any existing standalone tor process
    pkill -f "tor -f torrc" 2>/dev/null || true
    sleep 1
    
    tor -f torrc --runasdaemon 1
fi

# 3. Wait and verify ports are open
echo "[*] Waiting for Tor ports to initialize..."
sleep 3

PORT_9050_OPEN=false
PORT_LAST_OPEN=false

if nc -z 127.0.0.1 9050 2>/dev/null || (echo > /dev/tcp/127.0.0.1/9050) 2>/dev/null; then
    PORT_9050_OPEN=true
fi
if nc -z 127.0.0.1 9059 2>/dev/null || (echo > /dev/tcp/127.0.0.1/9059) 2>/dev/null; then
    PORT_LAST_OPEN=true
fi

if [ "$PORT_9050_OPEN" = true ] && [ "$PORT_LAST_OPEN" = true ]; then
    echo "=========================================================="
    echo "  [SUCCESS] All 10 Tor ports (9050..9059) are ACTIVE!"
    echo "            ControlPort: 127.0.0.1:9049"
    echo "=========================================================="
else
    echo "[!] Warning: Some ports might still be initializing. Checking..."
    sleep 2
    if nc -z 127.0.0.1 9059 2>/dev/null || (echo > /dev/tcp/127.0.0.1/9059) 2>/dev/null; then
        echo "  [SUCCESS] All 10 Tor ports (9050..9059) are ACTIVE!"
    else
        echo "  [INFO] Check status with: sudo systemctl status tor"
    fi
fi
