# Reverse SOCKS5, UDP, HTTP & MTProto Proxy Cluster (Python)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version Available](https://img.shields.io/badge/High--Speed-Go%20Version-brightgreen.svg)](https://github.com/zenkdom/reverse-socks-go)
[![Telegram Fake-TLS 1.3](https://img.shields.io/badge/Telegram-MTProto%20Fake--TLS-blue.svg)](https://telegram.org)

> [!IMPORTANT]
> 🚀 **High Load & Maximum Stability Notice:**  
> For production environments, multi-gigabit throughput, and high concurrency, we strongly recommend using the **[Go Version of Reverse SOCKS Cluster](https://github.com/zenkdom/reverse-socks-go)**.  
> 
> 🔄 **100% Cross-Compatible Protocol:**  
> Both Python and Go implementations share the exact same binary multiplexing wire protocol. Any Python reverse agent (`socks-reverse`) can connect to a Go control server, and any Go reverse agent can connect to a Python control server!

A high-performance reverse proxy cluster built with Python (`asyncio`):
- **Universal Multi-Protocol Listener** (Port `1080`):
  - **SOCKS5 with full TCP & UDP support**: commands `CONNECT` (0x01), `BIND` (0x02), and `UDP ASSOCIATE` (0x03) per RFC 1928 / RFC 1929. Supports Telegram VoIP calls, WebRTC, DNS, gaming, and QUIC/HTTP3.
  - **SOCKS4 & SOCKS4a**: support for legacy applications and remote domain resolution.
  - **HTTP & HTTPS (CONNECT) Proxy**: tunneling for HTTPS traffic and direct HTTP forward-proxying with Basic authentication.
  - Automatic on-the-fly protocol detection on a single unified port `1080`.
- **Telegram MTProto Proxy with Fake-TLS 1.3** (Port `8443`):
  - Circumvents strict DPI / firewall filtering by masquerading as TLS 1.3 traffic to legitimate domains (e.g. `google.com`).
  - Active probe defense: unauthorized scanner probes are routed to the real Google servers, returning valid certificates.
- **Built-in Web Administration UI** (Port `9001`):
  - Manage SOCKS5 and MTProto credentials with real-time node health monitoring.
  - 1-click `tg://proxy` connect links and clipboard export.
- **Reverse Exit Node Pool (`socks-reverse`)**:
  - Outbound nodes connect back to the control server, punching through NATs, firewalls, and CGNAT without public IPs.
  - Independent round-robin rotation per user and automatic 2-second failover.

---

## 🏗 Architecture

```
                             +---------------------------------------+
                             |           WEB ADMINISTRATOR           |
                             |       http://CONTROL_IP:9001          |
                             |       Default: admin / changeme123    |
                             +-------------------+-------------------+
                                                 |
                                                 | 1-Click Telegram Setup /
                                                 | SOCKS5 User Management
                                                 v
+---------------------------------------+   +---------------------------------------+
|                CLIENTS                |   |             socks-control             |
|    (Browser, curl, Telegram, apps)    |   |           (Master Server)             |
+-------------------+-------------------+   |                                       |
                    | SOCKS5 / HTTP (Auth)  |   * Port 1080: SOCKS5/4/HTTP Proxy    |
                    +---------------------->|   * Port 8443: MTProto Fake-TLS (TG)  |
                                            |   * Port 9000: Reverse Agent Bridge   |
+---------------------------------------+   |   * Port 9001: Web Admin Panel        |
|            TELEGRAM CLIENT            |   |   * Balancer: Per-User Rotation       |
|        (iOS, Android, Desktop)        |   +-------------------+-------------------+
+-------------------+-------------------+                       ^
                    | MTProto Fake-TLS (8443)                           |
                    | (Masquerading as google.com)                      |
                    +---------------------------------------------------+
                                                                        |
                                                Outbound Tunnels        |
                                +---------------------------------------+---------------------------------------+
                                |                                                                               |
                                | Port 9000                                                             | Port 9000
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |      socks-reverse      |                                                     |      socks-reverse      |
                   |      (Exit Node #1)     |                                                     |      (Exit Node #2)     |
                   |      reverse-node-1     |                                                     |      reverse-node-2     |
                   +------------+------------+                                                     +------------+------------+
                                |                                                                               |
                                | Direct Internet Access                                                        | Direct Internet Access
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |    Target Websites      |                                                     |   Telegram DataCenters  |
                   |      (Node #1 IP)       |                                                     |       (Node #2 IP)      |
                   +-------------------------+                                                     +-------------------------+
```

---

## ⚡ Why SOCKS5 Fails on Strict Firewalls While MTProto Fake-TLS Works

1. **The Issue with Plain SOCKS5:**
   - Standard SOCKS5 transmits the target connection in cleartext: `CONNECT 149.154.167.51:443`.
   - Modern Deep Packet Inspection (DPI) systems immediately detect Telegram IP blocks (`149.154.x.x`, `91.108.x.x`) and drop the connection with TCP RST packets. Clients get stuck on "Connecting...".
2. **The MTProto Fake-TLS Solution:**
   - The MTProto server encapsulates traffic inside a legitimate TLS 1.3 ClientHello session with SNI `google.com`.
   - To firewalls and DPI engines, the connection looks identical to standard HTTPS browsing to Google.
   - The master control server strips the Fake-TLS envelope and relays clean data through outbound reverse nodes located in open networks.

---

## 🔑 Key Features

1. **Dual-Mode MTProto (Fake-TLS + Hex32) on Port `8443`**:
   - Automatically detects client handshake format: Fake-TLS (`ee...`) or standard 32-hex Obfuscated2.
   - Masquerades as TLS 1.3 to avoid SNI filtering.
   - Sponsor channel support: attach Promo TAGs from `@MTProxybot` directly via the web UI.
   - Active probe protection: unauthorized probes are forwarded to genuine Google endpoints.
2. **Web Administration Dashboard on Port `9001`**:
   - Default login: `admin` / `changeme123`.
   - Create and revoke MTProto secret keys and SOCKS5 user credentials.
   - Live monitor for connected reverse nodes (status, Fake-TLS encapsulation, uptime, packet counters).
3. **Multi-Protocol Handler on Port `1080`**:
   - **TCP & UDP**: Stream TCP (`CONNECT`), incoming TCP (`BIND`), and datagram UDP (`UDP ASSOCIATE`). Fully compatible with Telegram VoIP calls, DNS lookups, WebRTC, and QUIC.
   - **SOCKS4 & SOCKS4a**: Legacy software support with remote domain resolution.
   - **HTTP CONNECT Tunneling**: Forward-proxy support for HTTPS and HTTP web traffic.
   - **Strict Authentication**: SOCKS5 user/pass (RFC 1929), SOCKS4 username validation, and HTTP `Proxy-Authorization: Basic`.
4. **NAT Traversal & Reverse Node Tunneling**:
   - Outbound nodes connect back to master server on port `9000`. Nodes can run behind NAT, firewalls, mobile connections, or restricted free tiers (such as PythonAnywhere).
   - Optional upstream HTTP proxy support (`CONNECT proxy:3128`) and Fake-TLS wrapping between nodes and control server.
5. **Per-User Rotation & Fast Failover**:
   - Balancing is calculated **independently per user**, ensuring equitable exit distribution.
   - Automatic 2-second failover: if an exit node fails to reach the destination, the request immediately redirects to a healthy backup node.
6. **Multi-Tor Cluster (`reverse-multi-tor`)**:
   - Orchestrates 10 isolated reverse agents through a local Tor daemon with `IsolateSOCKSAuth`.
   - ⚠️ *Note on Tor latency:* Tor onion routing introduces significant latency (300–800ms ping). For streaming, gaming, and VoIP, **we strongly recommend using your own VPS servers** with standard `socks-reverse` agents.

---

## 📁 Repository Structure

```text
reverse-socks-python/
├── socks-control/               # Master Control Server
│   ├── config.example.json      # Configuration template
│   ├── server.py                # Main server entrypoint
│   ├── admin_web.py             # Web Admin UI
│   ├── socks5.py                # Multi-protocol SOCKS5/4/HTTP engine
│   ├── mtproto.py               # MTProto Fake-TLS 1.3 engine
│   ├── agent_manager.py         # Reverse node pool & load balancer
│   ├── protocol.py              # Multiplexing binary protocol
│   └── requirements.txt         # Dependencies (cryptography)
│
├── socks-reverse/               # Outbound Reverse Exit Node
│   ├── config.example.json      # Node configuration template
│   ├── client.py                # Exit node launcher
│   ├── agent.py                 # Remote traffic executor
│   ├── protocol.py              # Multiplexing protocol
│   └── requirements.txt         # Zero dependencies (Python standard library)
│
├── reverse-multi-tor/           # Multi-Tor 10-node Cluster Module
│   ├── cluster.py               # Tor agent orchestrator
│   ├── start_tor.sh             # Tor multi-port setup script
│   └── start_cluster.sh         # Master launch script
│
├── test_system.py               # End-to-end integration test suite
└── README.md                    # Documentation
```

---

## 🚀 Quick Start Guide

### Step 1. Master Server Setup (`socks-control`)

1. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip
   cd socks-control
   pip install -r requirements.txt
   ```

2. Configure firewall ports:
   ```bash
   sudo ufw allow 1080/tcp comment "SOCKS5 proxy"
   sudo ufw allow 8443/tcp comment "Telegram MTProto Fake-TLS"
   sudo ufw allow 9000/tcp comment "Reverse control bridge"
   sudo ufw allow 9001/tcp comment "Admin Web Panel"
   ```

3. Initialize configuration:
   ```bash
   cp config.example.json config.json
   ```

4. Launch server:
   ```bash
   python3 server.py
   ```

---

### Step 2. One-Click Telegram Connection

1. Open your browser and navigate to: `http://YOUR_SERVER_IP:9001`
2. Sign in with `admin` / `changeme123`.
3. In the **Telegram MTProto Proxy** card, click **🚀 Connect in Telegram (1-Click)**.
4. Telegram will automatically open and prompt to enable your secure Fake-TLS proxy.

---

### Step 3. Launching Reverse Exit Nodes (`socks-reverse`)

Run an exit node on any VPS, cloud VM, or machine behind NAT:

```bash
cd socks-reverse
cp config.example.json config.json

# Launch agent (zero external dependencies required):
python3 client.py --host YOUR_CONTROL_SERVER_IP --port 9000 --token SecretProxyToken2026! --agent-id exit-node-1
```

*With Fake-TLS encapsulation:*
```bash
python3 client.py --host YOUR_CONTROL_SERVER_IP --port 9000 --token SecretProxyToken2026! --agent-id exit-node-1 --fake-tls --fake-tls-domain google.com
```

---

### Step 4. Multi-Tor 10-Node Cluster (Optional)

```bash
cd reverse-multi-tor
sudo bash start_cluster.sh
```

---

## 🧪 Testing

Run the full end-to-end integration test suite locally:
```bash
python test_system.py
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
