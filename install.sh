#!/usr/bin/env bash
# ==============================================================================
# Reverse SOCKS5 & MTProto Proxy Cluster (Python) - One-Line Installer
# Repository: https://github.com/zenkdom/reverse-socks-python
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: This installer must be run as root.${NC}"
    echo -e "${YELLOW}Please run with sudo: sudo bash install.sh or sudo -i${NC}"
    exit 1
fi

prompt_val() {
    local text="$1"
    local default_val="$2"
    local var_name="$3"
    local is_secret="${4:-0}"
    local user_input=""

    if [ -n "$default_val" ]; then
        echo -ne "${CYAN}${text} ${YELLOW}[${default_val}]${NC}: "
    else
        echo -ne "${CYAN}${text}${NC}: "
    fi

    if [ "$is_secret" -eq 1 ]; then
        if [ -c /dev/tty ]; then
            read -r -s user_input < /dev/tty
        else
            read -r -s user_input
        fi
        echo ""
    else
        if [ -c /dev/tty ]; then
            read -r user_input < /dev/tty
        else
            read -r user_input
        fi
    fi

    if [ -z "$user_input" ]; then
        eval "$var_name=\"$default_val\""
    else
        eval "$var_name=\"$user_input\""
    fi
}

rand_str() {
    local length="${1:-16}"
    head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

rand_hex() {
    local bytes="${1:-16}"
    head -c "$bytes" /dev/urandom | xxd -p | tr -d '\n' 2>/dev/null || od -An -tx1 -N"$bytes" /dev/urandom | tr -d ' \n'
}

str_to_hex() {
    echo -n "$1" | xxd -p | tr -d '\n' 2>/dev/null || echo -n "$1" | od -An -tx1 | tr -d ' \n'
}

detect_ip() {
    local pub_ip=""
    pub_ip=$(curl -4 -s --max-time 4 https://api.ipify.org 2>/dev/null || \
             curl -4 -s --max-time 4 https://ifconfig.me 2>/dev/null || \
             hostname -I | awk '{print $1}')
    echo "$pub_ip"
}

clear || true
echo -e "${BLUE}${BOLD}=================================================================${NC}"
echo -e "${GREEN}${BOLD}     Reverse SOCKS5, UDP & MTProto Cluster (Python) Installer    ${NC}"
echo -e "${CYAN}     Repository: https://github.com/zenkdom/reverse-socks-python  ${NC}"
echo -e "${BLUE}${BOLD}=================================================================${NC}"
echo ""

echo -e "${BOLD}Select what you want to install:${NC}"
echo -e "  ${GREEN}1)${NC} ${BOLD}Control Server (Master)${NC} - SOCKS5, Telegram Fake-TLS, Web UI & Node Bridge"
echo -e "  ${YELLOW}2)${NC} ${BOLD}Reverse Exit Node (Worker)${NC} - Outbound proxy agent connecting to Control Server"
echo ""

prompt_val "Enter your choice" "1" INSTALL_CHOICE

# ------------------------------------------------------------------------------
# OPTION 1: CONTROL SERVER
# ------------------------------------------------------------------------------
if [ "$INSTALL_CHOICE" = "1" ]; then
    echo ""
    echo -e "${BLUE}${BOLD}--- [1/3] Control Server Configuration ---${NC}"
    echo -e "${YELLOW}Press Enter to accept recommended default values in brackets.${NC}"
    echo ""

    prompt_val "SOCKS5 / HTTP Proxy Port" "1080" SOCKS5_PORT
    prompt_val "Telegram MTProto Fake-TLS Port" "8443" MTPROTO_PORT
    prompt_val "Fake-TLS Masking Domain" "google.com" MTPROTO_DOMAIN
    prompt_val "Reverse Node Bridge Port" "9000" BRIDGE_PORT

    DEFAULT_TOKEN="SecretToken_$(rand_str 12)"
    prompt_val "Reverse Node Secret Token" "$DEFAULT_TOKEN" SECRET_TOKEN

    echo ""
    echo -e "${BLUE}${BOLD}--- [2/3] Web Admin Dashboard Credentials ---${NC}"
    prompt_val "Admin Panel Port" "9001" ADMIN_PORT
    prompt_val "Admin Username" "admin" ADMIN_USER

    DEFAULT_PASS="$(rand_str 14)"
    prompt_val "Admin Password" "$DEFAULT_PASS" ADMIN_PASS

    echo ""
    echo -e "${BLUE}${BOLD}--- [3/3] Installing Dependencies & System Services ---${NC}"

    # Install Python & cryptography
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1
        apt-get install -y python3 python3-pip python3-cryptography git curl >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 python3-pip git curl >/dev/null 2>&1
        pip3 install cryptography >/dev/null 2>&1
    fi

    INSTALL_DIR="/opt/socks-control"
    mkdir -p "$INSTALL_DIR"

    # Download source files from GitHub
    BASE_URL="https://raw.githubusercontent.com/zenkdom/reverse-socks-python/main/socks-control"
    FILES=("admin_web.py" "agent_manager.py" "mtproto.py" "mtproto_users.py" "protocol.py" "server.py" "socks5.py" "socks_users.py" "user_manager.py")
    
    echo -e "[*] Fetching server components from GitHub..."
    for f in "${FILES[@]}"; do
        curl -fsSL "${BASE_URL}/${f}" -o "${INSTALL_DIR}/${f}"
    done

    # Generate config.json
    cat <<EOF > "${INSTALL_DIR}/config.json"
{
  "socks5": {
    "host": "0.0.0.0",
    "port": ${SOCKS5_PORT}
  },
  "mtproto": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": ${MTPROTO_PORT},
    "secret": "d04843361111fc744f516582107f9fb6",
    "domain": "${MTPROTO_DOMAIN}",
    "mask_host": "${MTPROTO_DOMAIN}",
    "mask_port": 443
  },
  "control": {
    "host": "0.0.0.0",
    "port": ${BRIDGE_PORT},
    "secret_token": "${SECRET_TOKEN}"
  },
  "admin": {
    "host": "0.0.0.0",
    "port": ${ADMIN_PORT},
    "username": "${ADMIN_USER}",
    "password": "${ADMIN_PASS}"
  },
  "balance_strategy": "rotation",
  "fast_failover_seconds": 2.0,
  "connect_timeout": 15.0,
  "log_level": "INFO"
}
EOF

    # Generate MTProto Secret
    MT_RAW_SECRET="$(rand_hex 16)"
    MT_DOMAIN_HEX="$(str_to_hex "$MTPROTO_DOMAIN")"
    MT_FAKETLS_SECRET="ee${MT_RAW_SECRET}${MT_DOMAIN_HEX}"

    cat <<EOF > "${INSTALL_DIR}/mtproto_users.json"
{
  "clients": [
    {
      "client_name": "default",
      "secret": "${MT_RAW_SECRET}",
      "domain": "${MTPROTO_DOMAIN}",
      "fake_tls_secret": "${MT_FAKETLS_SECRET}",
      "tag": null,
      "created_at": "$(date '+%Y-%m-%d %H:%M:%S')"
    }
  ]
}
EOF

    echo "{}" > "${INSTALL_DIR}/users.json"

    # Firewall
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        echo -e "[*] Adding UFW firewall rules..."
        ufw allow "${SOCKS5_PORT}/tcp" >/dev/null 2>&1 || true
        ufw allow "${MTPROTO_PORT}/tcp" >/dev/null 2>&1 || true
        ufw allow "${BRIDGE_PORT}/tcp" >/dev/null 2>&1 || true
        ufw allow "${ADMIN_PORT}/tcp" >/dev/null 2>&1 || true
    fi

    # Systemd Service
    cat <<EOF > /etc/systemd/system/socks-control.service
[Unit]
Description=Reverse SOCKS5 Control Server (Python)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/server.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now socks-control >/dev/null 2>&1

    SERVER_IP=$(detect_ip)

    echo ""
    echo -e "${GREEN}${BOLD}=================================================================${NC}"
    echo -e "${GREEN}${BOLD}       ✔ Control Server Successfully Installed & Started!        ${NC}"
    echo -e "${GREEN}${BOLD}=================================================================${NC}"
    echo ""
    echo -e "${BOLD}🔑 Web Administration Dashboard:${NC}"
    echo -e "   URL:      ${CYAN}${BOLD}http://${SERVER_IP}:${ADMIN_PORT}${NC}"
    echo -e "   Username: ${YELLOW}${ADMIN_USER}${NC}"
    echo -e "   Password: ${YELLOW}${ADMIN_PASS}${NC}"
    echo ""
    echo -e "${BOLD}⚡ 1-Click Telegram MTProto Proxy (Fake-TLS 1.3):${NC}"
    echo -e "   ${CYAN}tg://proxy?server=${SERVER_IP}&port=${MTPROTO_PORT}&secret=${MT_FAKETLS_SECRET}${NC}"
    echo ""
    echo -e "${BOLD}🌐 Multi-Protocol Proxy Port:${NC}"
    echo -e "   Host:     ${YELLOW}${SERVER_IP}${NC}"
    echo -e "   Port:     ${YELLOW}${SOCKS5_PORT}${NC} (SOCKS5 with TCP/UDP, SOCKS4, HTTP CONNECT)"
    echo -e "   Auth:     Manage user credentials in the Web Dashboard above."
    echo ""
    echo -e "${BOLD}🔗 To Connect a Reverse Exit Node from Another Server:${NC}"
    echo -e "   Run the one-line installer on the other machine and select Option 2, or run:"
    echo -e "   ${YELLOW}python3 client.py --host ${SERVER_IP} --port ${BRIDGE_PORT} --token ${SECRET_TOKEN} --agent-id node-1${NC}"
    echo ""
    echo -e "${BOLD}🛠 Service Management Commands:${NC}"
    echo -e "   Status:   ${CYAN}systemctl status socks-control${NC}"
    echo -e "   Logs:     ${CYAN}journalctl -u socks-control -f${NC}"
    echo -e "   Restart:  ${CYAN}systemctl restart socks-control${NC}"
    echo -e "${BLUE}${BOLD}=================================================================${NC}"
    exit 0
fi

# ------------------------------------------------------------------------------
# OPTION 2: REVERSE EXIT NODE
# ------------------------------------------------------------------------------
if [ "$INSTALL_CHOICE" = "2" ]; then
    echo ""
    echo -e "${BLUE}${BOLD}--- Reverse Exit Node Configuration ---${NC}"
    echo ""

    prompt_val "Control Server IP / Hostname" "" CONTROL_HOST
    if [ -z "$CONTROL_HOST" ]; then
        echo -e "${RED}[!] Control Server IP/Hostname is required!${NC}"
        exit 1
    fi

    prompt_val "Control Server Bridge Port" "9000" CONTROL_PORT
    prompt_val "Secret Token" "" SECRET_TOKEN
    if [ -z "$SECRET_TOKEN" ]; then
        echo -e "${RED}[!] Secret Token is required!${NC}"
        exit 1
    fi

    DEFAULT_NODE="node-$(rand_str 4)"
    prompt_val "Agent ID / Node Name" "$DEFAULT_NODE" AGENT_ID
    prompt_val "Enable Fake-TLS for tunnel? (y/n)" "n" USE_FAKE_TLS

    INSTALL_DIR="/opt/socks-reverse"
    mkdir -p "$INSTALL_DIR"

    # Zero dependencies for exit node! Only standard library
    BASE_URL="https://raw.githubusercontent.com/zenkdom/reverse-socks-python/main/socks-reverse"
    curl -fsSL "${BASE_URL}/client.py" -o "${INSTALL_DIR}/client.py"
    curl -fsSL "${BASE_URL}/agent.py" -o "${INSTALL_DIR}/agent.py"
    curl -fsSL "${BASE_URL}/protocol.py" -o "${INSTALL_DIR}/protocol.py"

    FAKE_TLS_BOOL="false"
    if [ "$USE_FAKE_TLS" = "y" ] || [ "$USE_FAKE_TLS" = "Y" ]; then
        FAKE_TLS_BOOL="true"
    fi

    cat <<EOF > "${INSTALL_DIR}/config.json"
{
  "control_server": {
    "host": "${CONTROL_HOST}",
    "port": ${CONTROL_PORT},
    "secret_token": "${SECRET_TOKEN}"
  },
  "fake_tls": {
    "enabled": ${FAKE_TLS_BOOL},
    "domain": "google.com"
  },
  "agent_id": "${AGENT_ID}",
  "connect_timeout": 15,
  "keepalive_interval": 25,
  "reconnect_delay": 3,
  "log_level": "INFO"
}
EOF

    cat <<EOF > /etc/systemd/system/socks-reverse.service
[Unit]
Description=Reverse SOCKS5 Worker Node (Python)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/client.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now socks-reverse >/dev/null 2>&1

    echo ""
    echo -e "${GREEN}${BOLD}=================================================================${NC}"
    echo -e "${GREEN}${BOLD}       ✔ Reverse Exit Node Successfully Connected!               ${NC}"
    echo -e "${GREEN}${BOLD}=================================================================${NC}"
    echo ""
    echo -e "   Node ID:        ${YELLOW}${AGENT_ID}${NC}"
    echo -e "   Control Server: ${CYAN}${CONTROL_HOST}:${CONTROL_PORT}${NC}"
    echo -e "   Status:         Connected & active as exit relay"
    echo ""
    echo -e "${BOLD}🛠 Service Management Commands:${NC}"
    echo -e "   Status:   ${CYAN}systemctl status socks-reverse${NC}"
    echo -e "   Logs:     ${CYAN}journalctl -u socks-reverse -f${NC}"
    echo -e "   Restart:  ${CYAN}systemctl restart socks-reverse${NC}"
    echo -e "${BLUE}${BOLD}=================================================================${NC}"
    exit 0
fi
