"""
Main Entrypoint for Reverse SOCKS Agent.
Runs on executing server(s) / worker nodes.
Connects outbound to socks-control server, receives client proxy requests,
executes them to the internet, and returns the response data.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import argparse
from agent import ReverseAgent
from protocol import raise_nofile_limit

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ReverseClient")


def load_config(config_path: str) -> dict:
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


async def main():
    parser = argparse.ArgumentParser(description="Reverse SOCKS5 Agent Client")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--host", help="Control server IP/hostname")
    parser.add_argument("--port", type=int, help="Control server bridge port")
    parser.add_argument("--token", help="Secret token for authentication")
    parser.add_argument("--agent-id", help="Unique ID/Name for this reverse agent")
    parser.add_argument("--fake-tls", action="store_true", help="Enable Fake-TLS 1.3 tunnel with white SNI (bypasses firewalls/DPI)")
    parser.add_argument("--fake-tls-domain", help="Whitelisted domain for TLS SNI (default: google.com)")
    parser.add_argument("--http-proxy", help="HTTP proxy URL (e.g. http://proxy.server:3128 for PythonAnywhere free tier)")
    parser.add_argument("--connect-host", help="Custom host to send in HTTP CONNECT request")
    args = parser.parse_args()

    cfg = load_config(args.config)
    control_cfg = cfg.get("control_server", {})
    fake_tls_cfg = cfg.get("fake_tls", {})
    http_proxy_cfg = cfg.get("http_proxy", {})

    control_host = args.host or control_cfg.get("host", "127.0.0.1")
    control_port = args.port or control_cfg.get("port", 9000)
    secret_token = args.token or control_cfg.get("secret_token", "SecretProxyToken2026!")

    agent_id = args.agent_id or cfg.get("agent_id") or f"agent-{os.getpid()}"
    use_faketls = args.fake_tls or fake_tls_cfg.get("enabled", False)
    faketls_domain = args.fake_tls_domain or fake_tls_cfg.get("domain", "google.com")
    http_proxy = args.http_proxy or http_proxy_cfg.get("proxy_url") or os.environ.get("https_proxy") or os.environ.get("http_proxy")
    connect_host = args.connect_host or http_proxy_cfg.get("connect_host")

    connect_timeout = cfg.get("connect_timeout", 15.0)
    keepalive_interval = cfg.get("keepalive_interval", 25.0)
    reconnect_delay = cfg.get("reconnect_delay", 3.0)

    log_level = cfg.get("log_level", "INFO")
    logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Raise open file descriptor limit to handle high concurrent connections
    raise_nofile_limit(65535)

    mode_info = f"Fake-TLS ({faketls_domain})" if use_faketls else "Plain TCP"
    proxy_info = f" via Proxy {http_proxy}" if http_proxy else ""
    logger.info("=" * 60)
    logger.info("   REVERSE SOCKS5 WORKER AGENT")
    logger.info(f"   Agent ID:          {agent_id}")
    logger.info(f"   Target Control:    {control_host}:{control_port}{proxy_info}")
    logger.info(f"   Transport Mode:    {mode_info}")
    logger.info("=" * 60)

    agent = ReverseAgent(
        control_host=control_host,
        control_port=control_port,
        secret_token=secret_token,
        agent_id=agent_id,
        use_faketls=use_faketls,
        faketls_domain=faketls_domain,
        http_proxy=http_proxy,
        connect_host=connect_host,
        connect_timeout=connect_timeout,
        keepalive_interval=keepalive_interval,
        reconnect_delay=reconnect_delay,
    )

    agent_task = asyncio.create_task(agent.start())

    stop_event = asyncio.Event()

    def request_shutdown(*args):
        if not stop_event.is_set():
            logger.info("Shutdown signal received, stopping agent...")
            stop_event.set()

    loop = asyncio.get_running_loop()

    # Silence noisy Proactor socket reset errors during teardown
    def silence_socket_reset(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        loop.default_exception_handler(context)

    loop.set_exception_handler(silence_socket_reset)

    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, request_shutdown)
    else:
        try:
            signal.signal(signal.SIGINT, lambda s, f: request_shutdown())
            signal.signal(signal.SIGTERM, lambda s, f: request_shutdown())
        except Exception:
            pass

    try:
        while not stop_event.is_set():
            await asyncio.sleep(0.3)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        logger.info("Stopping agent...")
        try:
            await asyncio.wait_for(agent.stop(), timeout=2.0)
        except Exception as e:
            logger.warning(f"Timeout stopping agent: {e}")

        agent_task.cancel()
        try:
            await asyncio.wait_for(agent_task, timeout=1.0)
        except Exception:
            pass
        logger.info("Agent stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
