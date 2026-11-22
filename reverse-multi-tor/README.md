# Multi-Tor Reverse Cluster (10 Isolated Exit Nodes)

> [!WARNING]
> ⚠️ **Notice Regarding Tor Network Latency & Speed:**  
> Routing traffic through the Tor network introduces substantial latency (300–800ms ping) and limited bandwidth. For high-throughput use cases (streaming video, Telegram VoIP, WebRTC, downloading large files), **we strongly recommend deploying standard `socks-reverse` agents on your own VPS servers**.  
> The cluster is optimized to **10 nodes** to ensure rock-solid stability in Python asyncio.

A pool of **10 virtual reverse exit nodes** running on top of an isolated **Tor** daemon, connecting back to the primary `socks-control` server.

---

## 🏗 Architecture

```
                             +---------------------------------------+
                             |           WEB ADMINISTRATOR           |
                             |       http://CONTROL_IP:9001          |
                             |       (Shows 10 active nodes)         |
                             +-------------------+-------------------+
                                                 |
+---------------------------------------+        |
|                CLIENTS                |        |
|    (SOCKS5 :1080 / MTProto :8443)     |        |
+-------------------+-------------------+        |
                    | Round-robin per user       v
                    +------------------->+-------------------------------+
                                         |         socks-control         |
                                         |      (Bridge Port: 9000)      |
                                         +---------------+---------------+
                                                         ▲
     10 independent persistent tunnels                   │
  ┌──────────────────────────────────────────────────────┴────────────────────────────────────────┐
  │                                                                                               │
+─┴───────────────────+             +─────────────────────+             +─────────────────────+   │
|     tor-node-01     |             |     tor-node-02     |             |     tor-node-10     |   │
|  (Reverse Agent #1) |             |  (Reverse Agent #2) |             |  (Reverse Agent #10)|   │
+----------+----------+             +----------+----------+             +----------+----------+   │
           │                                   │                                   │              │
           v (Port 9050)                       v (Port 9051)                       v (Port 9059)  │
┌──────────┴───────────────────────────────────┴───────────────────────────────────┴──────────┐   │
│                             Local Multi-Port Tor Daemon                                      │   │
│             10 Isolated SOCKS Ports with Stream Isolation (IsolateDestAddr / Port)           │   │
└──────────┬───────────────────────────────────┬───────────────────────────────────┬──────────┘   │
           │                                   │                                   │              │
           v                                   v                                   v              │
    [Tor Exit Node]                     [Tor Exit Node]                     [Tor Exit Node]       │
```

---

## 🚀 Quick Start on Linux / Ubuntu

### Step 1. Navigate to directory
```bash
cd reverse-multi-tor
```

### Step 2. Start the cluster
The automated script verifies Tor installation, generates a 10-port isolated configuration, restarts the daemon, and registers all 10 reverse agents:
```bash
chmod +x start_tor.sh start_cluster.sh
./start_cluster.sh
```

---

## 🛡️ Circuit Isolation (IsolateSOCKSAuth)

To ensure each virtual node receives a distinct circuit and external IP address:
1. **Tor Stream Isolation (`IsolateSOCKSAuth`):** Each agent provides a unique session token to Tor on connect.
2. **Automated Registration:** Each node tests its external IP address and registers with the master control server.

---

## 🛠 Configuration (`config.json`)

```json
{
  "control_server": {
    "host": "127.0.0.1",
    "port": 9000,
    "secret_token": "SecretProxyToken2026!"
  },
  "cluster": {
    "node_count": 10,
    "prefix": "tor-node-",
    "tor_host": "127.0.0.1",
    "tor_start_port": 9050,
    "tor_control_port": 9049,
    "check_ips_on_start": false
  },
  "connect_timeout": 20,
  "keepalive_interval": 25,
  "reconnect_delay": 3,
  "log_level": "INFO"
}
```

---

## 📊 Resource Usage
- **Memory (RAM):** The Tor daemon with 10 ports + Python async worker consume only **~40–60 MB RAM**.
- **CPU:** < 1% at idle.
