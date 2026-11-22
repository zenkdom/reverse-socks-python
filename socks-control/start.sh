#!/bin/bash
# Startup script for socks-control on Ubuntu / Linux
cd "$(dirname "$0")"
ulimit -n 65535 2>/dev/null || true
python3 server.py "$@"
