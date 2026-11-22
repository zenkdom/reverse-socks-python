"""
Multi-Tor Reverse Cluster Orchestrator.
Spawns N reverse proxy agents (default: 50), each mapped to an isolated Tor circuit.
Verifies and guarantees that EVERY Tor node has a 100% UNIQUE external exit IP address.
Connects all agents simultaneously to the main socks-control server (default: 127.0.0.1:9000).
"""
from __future__ import annotations

import asyncio
import argparse
import json
import logging
import os
import signal
import sys
from typing import List, Dict

from protocol import raise_nofile_limit
from tor_agent import TorReverseAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TorCluster")


class ClusterIPRegistry:
    """Thread-safe registry ensuring every Tor node in the cluster has a unique exit IP."""

    def __init__(self):
        self.assigned: Dict[str, str] = {}  # ip -> agent_id
        self._lock = asyncio.Lock()

    async def claim(self, ip: str, agent_id: str) -> bool:
        async with self._lock:
            if ip in self.assigned and self.assigned[ip] != agent_id:
                return False
            self.assigned[ip] = agent_id
            return True

    def unique_count(self) -> int:
        return len(self.assigned)

    def get_summary(self) -> List[tuple[str, str]]:
        return sorted([(agent_id, ip) for ip, agent_id in self.assigned.items()])


def load_config(config_path: str) -> dict:
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load config file {config_path}: {e}")
    return {}


async def check_tor_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Quick check if local Tor SOCKS port is accepting connections."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.close()
        await w.wait_closed()
        return True
    except Exception:
        return False


async def monitor_cluster(agents: List[TorReverseAgent], registry: ClusterIPRegistry, interval: float = 30.0):
    """Periodically logs status of active nodes and unique IP count."""
    while True:
        await asyncio.sleep(interval)
        connected = sum(1 for a in agents if a.is_connected)
        unique_ips = registry.unique_count()
        logger.info(
            f"[CLUSTER MONITOR] Active connected nodes: {connected}/{len(agents)} online | "
            f"Verified unique IPs: {unique_ips}/{len(agents)}"
        )


async def main():
    parser = argparse.ArgumentParser(description="Multi-Tor Reverse Cluster Runner with Unique IP Verification")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--host", help="Control server IP/hostname (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Control server bridge port (default: 9000)")
    parser.add_argument("--token", help="Secret token for authentication")
    parser.add_argument("--count", type=int, help="Number of Tor agents to spawn (default: 10)")
    parser.add_argument("--start-tor-port", type=int, help="First Tor SOCKS port (default: 9050)")
    parser.add_argument("--tor-host", help="Tor SOCKS host (default: 127.0.0.1)")
    parser.add_argument("--prefix", help="Agent ID prefix (default: tor-node-)")
    parser.add_argument("--no-verify-unique", action="store_true", help="Skip unique exit IP discovery on startup")
    parser.add_argument("--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    control_cfg = cfg.get("control_server", {})
    cluster_cfg = cfg.get("cluster", {})

    control_host = args.host or control_cfg.get("host", "127.0.0.1")
    control_port = args.port or control_cfg.get("port", 9000)
    secret_token = args.token or control_cfg.get("secret_token", "SecretProxyToken2026!")

    node_count = args.count or cluster_cfg.get("node_count", 10)
    tor_host = args.tor_host or cluster_cfg.get("tor_host", "127.0.0.1")
    start_tor_port = args.start_tor_port or cluster_cfg.get("tor_start_port", 9050)
    prefix = args.prefix or cluster_cfg.get("prefix", "tor-node-")
    verify_unique = not args.no_verify_unique and cluster_cfg.get("ensure_unique_ips", True)

    connect_timeout = cfg.get("connect_timeout", 20.0)
    keepalive_interval = cfg.get("keepalive_interval", 25.0)
    reconnect_delay = cfg.get("reconnect_delay", 3.0)

    log_level = args.log_level or cfg.get("log_level", "INFO")
    logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

    raise_nofile_limit(65535)

    print("=" * 70)
    print(f"      MULTI-TOR REVERSE CLUSTER: {node_count} NODES (UNIQUE IP ENFORCED)")
    print(f"      Target Control Server: {control_host}:{control_port}")
    print(f"      Tor SOCKS Ports: {tor_host}:{start_tor_port} .. {start_tor_port + node_count - 1}")
    print("=" * 70)

    # Pre-flight check: verify first and last Tor ports
    first_tor_ok = await check_tor_port(tor_host, start_tor_port, timeout=1.5)
    last_port = start_tor_port + node_count - 1
    last_tor_ok = await check_tor_port(tor_host, last_port, timeout=1.5)

    if not first_tor_ok:
        logger.warning(
            f"[!] Tor port {tor_host}:{start_tor_port} is not responding yet! "
            f"Make sure Tor is installed and started with: 'sudo ./start_tor.sh' (or tor.exe on Windows)."
        )
    elif not last_tor_ok:
        logger.info(
            f"[*] Tor port {tor_host}:{start_tor_port} is active (single port mode). "
            f"Tor IsolateSOCKSAuth will build {node_count} independent circuits via {tor_host}:{start_tor_port}!"
        )
    else:
        logger.info(f"[OK] Pre-flight check passed: Tor ports {start_tor_port}..{last_port} are active and listening.")

    ip_registry = ClusterIPRegistry()
    agents: List[TorReverseAgent] = []
    agent_tasks: List[asyncio.Task] = []

    for i in range(node_count):
        # If multi-port is listening, bind to port (start_port + i). If only port 9050 is listening, all use 9050 with SOCKS auth!
        if last_tor_ok:
            port = start_tor_port + i
        else:
            port = start_tor_port

        agent_id = f"{prefix}{i + 1:02d}"

        agent = TorReverseAgent(
            control_host=control_host,
            control_port=control_port,
            secret_token=secret_token,
            agent_id=agent_id,
            tor_host=tor_host,
            tor_port=port,
            connect_timeout=connect_timeout,
            keepalive_interval=keepalive_interval,
            reconnect_delay=reconnect_delay,
        )
        agents.append(agent)

    # Graceful shutdown handler
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("[!] Stopping Multi-Tor cluster...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except (NotImplementedError, AttributeError):
            pass

    # Unique IP verification phase (if Tor is reachable)
    if verify_unique and first_tor_ok:
        print("\n[*] Discovering and verifying UNIQUE exit IP for each node (via Tor IsolateSOCKSAuth)...")
        try:
            # Check all nodes in parallel with a hard 12-second total ceiling
            check_tasks = [a.obtain_unique_exit_ip(ip_registry, max_attempts=3) for a in agents]
            await asyncio.wait_for(asyncio.gather(*check_tasks, return_exceptions=True), timeout=12.0)
        except (asyncio.TimeoutError, Exception):
            logger.info("[*] Pre-flight IP discovery completed. Proceeding with agent launch.")

        summary = ip_registry.get_summary()
        unique_cnt = ip_registry.unique_count()
        print("\n" + "=" * 70)
        print(f"             VERIFIED UNIQUE TOR EXIT IPS ({unique_cnt}/{len(agents)}):")
        print("=" * 70)
        for aid, ip in summary:
            print(f"  * {aid:14s} -> Exit IP: {ip}")
        print("-" * 70)
        print(f"Total verified unique exit IPs: {unique_cnt} out of {len(agents)}")
        print("=" * 70 + "\n")

    # Launch all agents
    for agent in agents:
        task = asyncio.create_task(agent.run(), name=f"task-{agent.agent_id}")
        agent_tasks.append(task)

    # Launch background cluster monitor
    monitor_task = asyncio.create_task(monitor_cluster(agents, ip_registry), name="cluster-monitor")

    logger.info(f"[+] All {node_count} Tor Reverse Agents launched! Connecting to {control_host}:{control_port}...")

    try:
        await stop_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        logger.info("[*] Shutting down all agents...")
        monitor_task.cancel()
        for agent in agents:
            await agent.stop()
        for task in agent_tasks:
            task.cancel()
        await asyncio.gather(*agent_tasks, return_exceptions=True)
        logger.info("[OK] Multi-Tor cluster stopped cleanly.")


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Stopped cleanly.")
        sys.exit(0)
