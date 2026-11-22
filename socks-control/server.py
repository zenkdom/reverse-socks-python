"""
Main Control Server for Reverse SOCKS5.
Runs on Ubuntu VPS (or any OS).
- Listens on SOCKS5 port (default 1080) for incoming client traffic.
- Listens on Control port (default 9000) for reverse agent registrations.
- Balances requests randomly across all connected reverse agents.
"""
from __future__ import annotations

import sys
import os

# Guarantee local directory has top priority in sys.path
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

import asyncio
import json
import logging
import signal
import argparse
import struct
from typing import Optional
from agent_manager import AgentManager, AgentSession
from socks_users import UserManager
from mtproto_users import MtprotoUserManager
from socks5 import Socks5Server
from admin_web import AdminWebServer
from mtproto import MtprotoProxyServer
from protocol import (
    MAGIC,
    HEADER_SIZE,
    CMD_AUTH_REQ,
    CMD_AUTH_RESP,
    read_frame,
    pack_json,
    safe_close_writer,
    enable_socket_keepalive,
    raise_nofile_limit,
    perform_tls_server_handshake,
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ControlServer")


class ControlBridgeServer:
    """Manages the control channel where socks-reverse agents connect."""

    def __init__(self, agent_manager: AgentManager, host: str, port: int, secret_token: str):
        self.agent_manager = agent_manager
        self.host = host
        self.port = port
        self.secret_token = secret_token
        self.server: Optional[asyncio.Server] = None
        self.active_tasks: set[asyncio.Task] = set()
        self.reaper_task: Optional[asyncio.Task] = None
        self.closed = False

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_agent,
            host=self.host,
            port=self.port,
            backlog=2048,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"[*] Control Bridge Server listening on {addrs} (Agents connect here)")
        self.reaper_task = asyncio.create_task(self._reaper_loop(), name="agent-reaper")

    async def _reaper_loop(self):
        try:
            while not self.closed:
                await asyncio.sleep(15.0)
                await self.agent_manager.reap_stale_agents(max_inactive=60.0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Error in reaper loop: {e}")

    async def stop(self):
        self.closed = True
        if self.reaper_task and not self.reaper_task.done():
            self.reaper_task.cancel()
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
            except Exception:
                pass

        # Gracefully disconnect all agents and close active streams
        await self.agent_manager.close_all()

        for task in list(self.active_tasks):
            if not task.done():
                task.cancel()
        if self.active_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self.active_tasks), return_exceptions=True),
                    timeout=1.0,
                )
            except Exception:
                pass
        self.active_tasks.clear()
        logger.info("Control Bridge Server stopped.")

    async def handle_agent(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self.closed:
            try:
                writer.close()
            except Exception:
                pass
            return

        current_task = asyncio.current_task()
        if current_task:
            self.active_tasks.add(current_task)

        peername = writer.get_extra_info("peername")
        remote_ip = f"{peername[0]}:{peername[1]}" if peername else "unknown"
        logger.info(f"Incoming connection from potential reverse agent at {remote_ip}")

        enable_socket_keepalive(writer)
        agent_session: Optional[AgentSession] = None
        active_writer = writer
        try:
            # 1. Read first 4 bytes to detect transport: Plain RSX5 vs Fake-TLS ClientHello vs HTTP CONNECT
            prefix = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)

            # Case A: HTTP CONNECT request (forwarded proxy tunnel)
            if prefix.startswith(b"CONN"):
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if not line or line in (b"\r\n", b"\n"):
                        break
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                logger.info(f"[{remote_ip}] Accepted HTTP CONNECT tunnel, awaiting transport handshake...")
                prefix = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)

            is_faketls = False
            sni_domain = ""
            active_reader = reader
            active_writer = writer

            # Case B: Fake-TLS 1.3 Handshake (disguised as HTTPS with whitelisted SNI)
            if prefix[:2] == b"\x16\x03":
                tls_r, tls_w, sni_domain = await perform_tls_server_handshake(
                    reader, writer, first_bytes=prefix, timeout=10.0
                )
                active_reader = tls_r
                active_writer = tls_w
                is_faketls = True
                logger.info(f"[{remote_ip}] Upgraded agent transport to Fake-TLS (SNI: '{sni_domain}')")
                frame = await asyncio.wait_for(read_frame(active_reader), timeout=10.0)

            # Case C: Plain RSX5 protocol frame (existing reverse nodes)
            elif prefix == MAGIC:
                hdr_rest = await asyncio.wait_for(reader.readexactly(HEADER_SIZE - 4), timeout=10.0)
                cmd, stream_id, length = struct.unpack("!BII", hdr_rest)
                if length > 0:
                    payload = await asyncio.wait_for(reader.readexactly(length), timeout=10.0)
                else:
                    payload = b""
                frame = (cmd, stream_id, payload)
                logger.info(f"[{remote_ip}] Connected agent using Plain TCP transport")

            else:
                logger.warning(f"[{remote_ip}] Unknown protocol prefix: {prefix.hex()}, closing connection")
                await safe_close_writer(writer, timeout=0.5)
                return

            if not frame:
                await safe_close_writer(active_writer, timeout=0.5)
                return

            cmd, stream_id, payload = frame
            if cmd != CMD_AUTH_REQ:
                logger.warning(f"[{remote_ip}] Expected AUTH_REQ, got cmd {cmd}")
                await safe_close_writer(active_writer, timeout=0.5)
                return

            auth_data = json.loads(payload.decode("utf-8"))
            token = auth_data.get("token", "")
            agent_id = auth_data.get("agent_id") or f"agent-{peername[0]}-{peername[1]}"
            exit_ip = auth_data.get("exit_ip", "")

            # 2. Check secret token
            if self.secret_token and token != self.secret_token:
                logger.warning(f"[{remote_ip}] Authentication failed for agent '{agent_id}': Invalid token")
                resp = pack_json(CMD_AUTH_RESP, 0, {"status": "error", "message": "Invalid authentication token"})
                active_writer.write(resp)
                await active_writer.drain()
                await safe_close_writer(active_writer, timeout=0.5)
                return

            # Prevent duplicate agent_id collisions
            if agent_id in self.agent_manager.agents:
                agent_id = f"{agent_id}-{peername[1]}"

            # Send auth success
            resp = pack_json(CMD_AUTH_RESP, 0, {"status": "ok", "message": "Authenticated"})
            active_writer.write(resp)
            await active_writer.drain()

            # 3. Create session and register
            agent_session = AgentSession(
                agent_id=agent_id,
                reader=active_reader,
                writer=active_writer,
                remote_ip=remote_ip,
                is_faketls=is_faketls,
                sni_domain=sni_domain,
                exit_ip=exit_ip,
            )
            agent_session.start_writer()
            self.agent_manager.register(agent_session)

            # 4. Agent frame loop
            while not agent_session.closed and not self.closed:
                try:
                    frame = await asyncio.wait_for(read_frame(active_reader), timeout=90.0)
                except asyncio.TimeoutError:
                    logger.warning(f"[{remote_ip}] [{agent_session.agent_id}] Keepalive timeout (no data/pings in 90s)")
                    break
                if not frame:
                    # Connection closed by reverse agent
                    break
                cmd, stream_id, payload = frame
                agent_session.handle_incoming_frame(cmd, stream_id, payload)

        except asyncio.TimeoutError:
            logger.warning(f"[{remote_ip}] Timeout during authentication")
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error(f"[{remote_ip}] Error in agent session: {e}", exc_info=True)
        finally:
            if current_task:
                self.active_tasks.discard(current_task)
            if agent_session:
                self.agent_manager.unregister(agent_session.agent_id)
                await agent_session.close()
            else:
                await safe_close_writer(active_writer, timeout=0.5)


def load_config(config_path: str) -> dict:
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content:
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        # Auto-repair common syntax issues: missing commas, trailing commas, comments
        import re
        repaired = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        repaired = re.sub(r"#.*$", "", repaired, flags=re.MULTILINE)
        repaired = re.sub(r'([}\]"0-9a-zA-Z_])\s*\n\s*("[\w_-]+"\s*:)', r"\1,\n    \2", repaired)
        repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
        try:
            cfg = json.loads(repaired)
            logger.warning(
                f"[CONFIG] Warning: syntax error in '{config_path}' at line {e.lineno}, col {e.colno} ({e.msg}). "
                f"Auto-repaired successfully."
            )
            return cfg
        except Exception:
            logger.error(
                f"[CONFIG ERROR] Invalid JSON in '{config_path}' (Line {e.lineno}, Col {e.colno}: {e.msg}). "
                f"Please verify commas and quotes."
            )
            raise


async def main():
    parser = argparse.ArgumentParser(description="Reverse SOCKS5 Control Server")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--socks-host", help="SOCKS5 bind host (default: 0.0.0.0)")
    parser.add_argument("--socks-port", type=int, help="SOCKS5 bind port (default: 1080)")
    parser.add_argument("--mtproto-port", type=int, help="MTProto bind port (default: 8443)")
    parser.add_argument("--mtproto-secret", help="MTProto secret (hex)")
    parser.add_argument("--mtproto-domain", help="Fake-TLS mask domain (default: google.com)")
    parser.add_argument("--mtproto-tag", help="MTProto promo channel TAG from @MTProxybot (32 hex chars)")
    parser.add_argument("--control-host", help="Control bridge bind host (default: 0.0.0.0)")
    parser.add_argument("--control-port", type=int, help="Control bridge bind port (default: 9000)")
    parser.add_argument("--admin-host", help="Admin panel bind host (default: 0.0.0.0)")
    parser.add_argument("--admin-port", type=int, help="Admin panel bind port (default: 9001)")
    parser.add_argument("--admin-user", help="Admin username (default: admin)")
    parser.add_argument("--admin-pass", help="Admin password (default: changeme)")
    parser.add_argument("--token", help="Secret token for reverse agents")
    parser.add_argument(
        "--strategy",
        choices=["rotation", "round_robin", "random", "sticky"],
        help="Load balance strategy (default: rotation)",
    )
    parser.add_argument(
        "--failover-timeout",
        type=float,
        help="Timeout in seconds before failing over to previous/other reverse node (default: 2.0)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        help="Total timeout in seconds for target connections (default: 15.0)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)

    socks_cfg = cfg.get("socks5", {})
    mtproto_cfg = cfg.get("mtproto", {})
    control_cfg = cfg.get("control", {})
    admin_cfg = cfg.get("admin", {})

    socks_host = args.socks_host or socks_cfg.get("host", "0.0.0.0")
    socks_port = args.socks_port or socks_cfg.get("port", 1080)

    mtproto_enabled = mtproto_cfg.get("enabled", True)
    mtproto_host = mtproto_cfg.get("host", "0.0.0.0")
    mtproto_port = args.mtproto_port or mtproto_cfg.get("port", 8443)
    mtproto_secret = args.mtproto_secret or mtproto_cfg.get("secret", "d04843361111fc744f516582107f9fb6")
    mtproto_domain = args.mtproto_domain or mtproto_cfg.get("domain", "google.com")
    mtproto_tag = args.mtproto_tag or mtproto_cfg.get("tag")
    mask_host = mtproto_cfg.get("mask_host", "google.com")
    mask_port = mtproto_cfg.get("mask_port", 443)

    control_host = args.control_host or control_cfg.get("host", "0.0.0.0")
    control_port = args.control_port or control_cfg.get("port", 9000)
    secret_token = args.token or control_cfg.get("secret_token", "SecretProxyToken2026!")

    admin_host = args.admin_host or admin_cfg.get("host", "0.0.0.0")
    admin_port = args.admin_port or admin_cfg.get("port", 9001)
    admin_user = args.admin_user or admin_cfg.get("username", "admin")
    admin_pass = args.admin_pass or admin_cfg.get("password", "changeme")

    strategy = args.strategy or cfg.get("balance_strategy", "rotation")
    fast_timeout = args.failover_timeout or cfg.get("fast_failover_seconds", 2.0)
    connect_timeout = args.connect_timeout or cfg.get("connect_timeout", 15.0)

    log_level = cfg.get("log_level", "INFO")
    logging.getLogger().setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Raise open file descriptor limit to handle high concurrent connections
    raise_nofile_limit(65535)

    logger.info("=" * 60)
    logger.info("   REVERSE SOCKS5 & MTPROTO CONTROL SERVER")
    logger.info(f"   SOCKS5 Service:    {socks_host}:{socks_port} (Auth: REQUIRED)")
    if mtproto_enabled:
        tag_info = f", TAG: {mtproto_tag}" if mtproto_tag else ""
        logger.info(f"   MTProto Fake-TLS:  {mtproto_host}:{mtproto_port} (Domain: {mtproto_domain}{tag_info})")
    logger.info(f"   Control Bridge:    {control_host}:{control_port}")
    logger.info(f"   Admin Web Panel:   http://{admin_host}:{admin_port} (User: {admin_user})")
    logger.info(f"   Balance Strategy:  {strategy.upper()} (Failover: {fast_timeout}s)")
    logger.info("=" * 60)

    agent_manager = AgentManager(strategy=strategy, fast_timeout=fast_timeout)
    user_manager = UserManager(filepath="users.json")

    mtproto_user_manager: Optional[MtprotoUserManager] = None
    if mtproto_enabled:
        mtproto_user_manager = MtprotoUserManager(
            filepath="mtproto_users.json",
            default_secret=mtproto_secret,
            default_domain=mtproto_domain,
            default_tag=mtproto_tag,
        )

    control_server = ControlBridgeServer(
        agent_manager=agent_manager,
        host=control_host,
        port=control_port,
        secret_token=secret_token,
    )

    socks_server = Socks5Server(
        agent_manager=agent_manager,
        user_manager=user_manager,
        host=socks_host,
        port=socks_port,
        fast_timeout=fast_timeout,
        connect_timeout=connect_timeout,
    )

    mtproto_server: Optional[MtprotoProxyServer] = None
    if mtproto_enabled:
        mtproto_server = MtprotoProxyServer(
            agent_manager=agent_manager,
            user_manager=mtproto_user_manager,
            host=mtproto_host,
            port=mtproto_port,
            secret=mtproto_secret,
            domain=mtproto_domain,
            tag=mtproto_tag,
            mask_host=mask_host,
            mask_port=mask_port,
            fast_timeout=fast_timeout,
            connect_timeout=connect_timeout,
        )

    admin_server = AdminWebServer(
        agent_manager=agent_manager,
        user_manager=user_manager,
        mtproto_user_manager=mtproto_user_manager,
        host=admin_host,
        port=admin_port,
        admin_user=admin_user,
        admin_pass=admin_pass,
        socks5_port=socks_port,
        mtproto_port=mtproto_port if mtproto_enabled else None,
        mtproto_secret=mtproto_server.fake_tls_secret if mtproto_server else None,
        mtproto_domain=mtproto_domain if mtproto_enabled else None,
        mtproto_tag=mtproto_tag if mtproto_enabled else None,
    )

    await control_server.start()
    await socks_server.start()
    if mtproto_server:
        await mtproto_server.start()
    await admin_server.start()

    # Graceful shutdown event
    stop_event = asyncio.Event()

    def request_shutdown(*args):
        if not stop_event.is_set():
            logger.info("Shutdown signal received, initiating graceful termination...")
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
        logger.info("Shutting down all proxy and control services...")
        stop_coros = []
        if mtproto_server:
            stop_coros.append(mtproto_server.stop())
        stop_coros.append(socks_server.stop())
        stop_coros.append(control_server.stop())
        stop_coros.append(admin_server.stop())

        try:
            await asyncio.wait_for(
                asyncio.gather(*stop_coros, return_exceptions=True),
                timeout=3.0,
            )
        except Exception as e:
            logger.warning(f"Shutdown timeout or exception: {e}")

        logger.info("All services successfully stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
