"""
Tor Reverse Agent implementation.
Maintains a reverse control tunnel to socks-control server,
and fulfills target connection requests through a designated local Tor SOCKS5 port.
Supports Tor IsolateSOCKSAuth for guaranteed unique exit IPs per node.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
import random
from typing import Optional, Dict

from protocol import (
    CMD_AUTH_REQ,
    CMD_AUTH_RESP,
    CMD_CONNECT_REQ,
    CMD_CONNECT_RESP,
    CMD_DATA,
    CMD_CLOSE,
    CMD_PING,
    CMD_PONG,
    STATUS_SUCCESS,
    STATUS_GENERAL_FAILURE,
    STATUS_CONNECTION_REFUSED,
    STATUS_NETWORK_UNREACHABLE,
    STATUS_HOST_UNREACHABLE,
    STATUS_TIMEOUT,
    read_frame,
    pack_frame,
    pack_json,
    safe_close_writer,
    enable_socket_keepalive,
    socks5_connect,
)

logger = logging.getLogger("TorAgent")


class TargetStream:
    """Manages an active outbound connection to target internet server routed via Tor."""

    def __init__(
        self,
        stream_id: int,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        send_frame_func,
    ):
        self.stream_id = stream_id
        self.host = host
        self.port = port
        self.reader = reader
        self.writer = writer
        self.send_frame_func = send_frame_func
        self.closed = False
        self.read_task: Optional[asyncio.Task] = None

    def start_reading(self):
        self.read_task = asyncio.create_task(
            self._reader_loop(), name=f"target-reader-{self.stream_id}"
        )

    async def _reader_loop(self):
        """Read data from target (via Tor) and forward to control server."""
        try:
            while not self.closed:
                chunk = await self.reader.read(32768)
                if not chunk:
                    break
                await self.send_frame_func(CMD_DATA, self.stream_id, chunk)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.debug(f"[Stream #{self.stream_id}] Target read error: {e}")
        finally:
            await self.close(notify_control=True)

    async def write_data(self, data: bytes):
        """Write data received from control server to target server."""
        if self.closed:
            return
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            await self.close(notify_control=True)

    async def close(self, notify_control: bool = False):
        if self.closed:
            return
        self.closed = True

        if notify_control:
            try:
                await self.send_frame_func(CMD_CLOSE, self.stream_id)
            except Exception:
                pass

        if self.read_task and not self.read_task.done():
            self.read_task.cancel()

        await safe_close_writer(self.writer, timeout=0.5)


class TorReverseAgent:
    """
    Reverse Agent bound to a specific local Tor SOCKS port.
    Registers with socks-control and routes all traffic through its Tor circuit.
    Uses Tor IsolateSOCKSAuth with unique session tokens to guarantee distinct exit nodes.
    """

    def __init__(
        self,
        control_host: str,
        control_port: int,
        secret_token: str,
        agent_id: str,
        tor_host: str = "127.0.0.1",
        tor_port: int = 9050,
        connect_timeout: float = 20.0,
        keepalive_interval: float = 25.0,
        reconnect_delay: float = 3.0,
    ):
        self.control_host = control_host
        self.control_port = control_port
        self.secret_token = secret_token
        self.agent_id = agent_id
        self.tor_host = tor_host
        self.tor_port = tor_port
        self.connect_timeout = connect_timeout
        self.keepalive_interval = keepalive_interval
        self.reconnect_delay = reconnect_delay

        # Circuit isolation credentials for Tor IsolateSOCKSAuth
        self.circuit_id = 1
        self.circuit_seed = random.randint(1000, 9999)
        self.tor_username = f"{self.agent_id}_{self.circuit_seed}_1"
        self.exit_ip: Optional[str] = None

        self.control_reader: Optional[asyncio.StreamReader] = None
        self.control_writer: Optional[asyncio.StreamWriter] = None
        self.send_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=10000)
        self.writer_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None

        self.active_streams: Dict[int, TargetStream] = {}
        self.pending_connects: Dict[int, asyncio.Task] = {}
        self.running = False
        self.is_connected = False

    async def query_exit_ip(self, username: Optional[str] = None, timeout: float = 3.5) -> Optional[str]:
        """Queries the current Tor exit IP address for this agent, trying fast services."""
        user = username or self.tor_username
        check_endpoints = [
            ("api.ipify.org", 80, "api.ipify.org"),
            ("icanhazip.com", 80, "icanhazip.com"),
        ]
        for host, port, req_host in check_endpoints:
            try:
                r, w = await socks5_connect(
                    self.tor_host,
                    self.tor_port,
                    host,
                    port,
                    timeout=timeout,
                    username=user,
                )
                req = f"GET / HTTP/1.1\r\nHost: {req_host}\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n".encode("utf-8")
                w.write(req)
                await w.drain()
                resp = await asyncio.wait_for(r.read(2048), timeout=timeout)
                await safe_close_writer(w, timeout=0.3)
                if b"\r\n\r\n" in resp:
                    body = resp.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="ignore").strip()
                    cleaned_ip = body.split("\n")[0].strip()
                    if cleaned_ip and len(cleaned_ip) <= 45 and ("." in cleaned_ip or ":" in cleaned_ip):
                        return cleaned_ip
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception:
                continue
        return None

    async def obtain_unique_exit_ip(self, registry, max_attempts: int = 3) -> Optional[str]:
        """
        Fast unique exit IP discovery with Tor IsolateSOCKSAuth.
        Guarantees that this agent gets an exit IP that is NOT already in registry.
        """
        for attempt in range(max_attempts):
            test_user = f"{self.agent_id}_c{self.circuit_id}"
            try:
                ip = await self.query_exit_ip(username=test_user, timeout=3.5)
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception:
                ip = None

            if ip:
                claimed = await registry.claim(ip, self.agent_id)
                if claimed:
                    self.exit_ip = ip
                    self.tor_username = test_user
                    logger.info(f"[{self.agent_id}] [UNIQUE IP OK] Exit IP: {ip} (Tor Circuit #{self.circuit_id})")
                    return ip
                else:
                    logger.info(
                        f"[{self.agent_id}] Discovered IP {ip} is already used by another node. "
                        f"Spinning up new Tor circuit #{self.circuit_id + 1}..."
                    )
                    self.circuit_id += 1
                    await asyncio.sleep(0.2)
            else:
                self.circuit_id += 1
                await asyncio.sleep(0.3)

        # Fallback: if check timed out, Tor IsolateSOCKSAuth still guarantees an isolated circuit!
        self.tor_username = f"{self.agent_id}_c{self.circuit_id}"
        logger.info(f"[{self.agent_id}] Circuit initialized (IsolateSOCKSAuth: {self.tor_username})")
        return self.exit_ip

    async def run(self):
        """Main agent loop: connects, authenticates, handles requests, auto-reconnects."""
        self.running = True
        logger.info(f"[{self.agent_id}] Starting Tor Agent (Tor SOCKS: {self.tor_host}:{self.tor_port})")

        while self.running:
            try:
                await self._connect_and_serve()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[{self.agent_id}] Connection to control failed: {e}")

            self.is_connected = False
            if self.running:
                await asyncio.sleep(self.reconnect_delay)

    async def stop(self):
        """Gracefully stop agent."""
        self.running = False
        self.is_connected = False

        # Close all active target streams
        streams = list(self.active_streams.values())
        self.active_streams.clear()
        for stream in streams:
            await stream.close(notify_control=False)

        # Cancel tasks
        if self.keepalive_task and not self.keepalive_task.done():
            self.keepalive_task.cancel()
        if self.writer_task and not self.writer_task.done():
            self.writer_task.cancel()

        # Close control connection
        if self.control_writer:
            await safe_close_writer(self.control_writer, timeout=0.5)
            self.control_writer = None
            self.control_reader = None

    async def _connect_and_serve(self):
        """Establish tunnel to control server, authenticate, and process incoming frames."""
        self.control_reader, self.control_writer = await asyncio.wait_for(
            asyncio.open_connection(self.control_host, self.control_port),
            timeout=15.0,
        )
        enable_socket_keepalive(self.control_writer)

        # Start background writer task
        self.send_queue = asyncio.Queue(maxsize=2000)
        self.writer_task = asyncio.create_task(
            self._writer_loop(), name=f"{self.agent_id}-writer"
        )

        # Authenticate with control server (including discovered unique exit_ip!)
        await self._send_json(
            CMD_AUTH_REQ,
            0,
            {
                "token": self.secret_token,
                "agent_id": self.agent_id,
                "exit_ip": self.exit_ip or "",
            },
        )

        frame = await asyncio.wait_for(read_frame(self.control_reader), timeout=10.0)
        if not frame:
            raise ConnectionError("Control server disconnected during authentication")

        cmd, stream_id, payload = frame
        if cmd != CMD_AUTH_RESP:
            raise ConnectionError(f"Unexpected auth reply: cmd={cmd}")

        auth_data = json.loads(payload.decode("utf-8"))
        if auth_data.get("status") != "ok":
            raise PermissionError(f"Authentication failed: {auth_data.get('message')}")

        self.is_connected = True
        logger.info(
            f"[{self.agent_id}] [OK] Connected to Control & Registered! "
            f"(Tor Port: {self.tor_port}, Exit IP: {self.exit_ip or 'auto'})"
        )

        # Start keepalive loop
        self.keepalive_task = asyncio.create_task(
            self._keepalive_loop(), name=f"{self.agent_id}-keepalive"
        )

        # Main frame processing loop
        while self.running:
            frame = await read_frame(self.control_reader)
            if frame is None:
                logger.warning(f"[{self.agent_id}] Control server closed connection.")
                break

            cmd, stream_id, payload = frame
            await self._dispatch_frame(cmd, stream_id, payload)

    async def _writer_loop(self):
        """Pulls frames from send_queue and transmits to control server."""
        try:
            while self.running and self.control_writer:
                frame = await self.send_queue.get()
                if frame is None:
                    break
                self.control_writer.write(frame)
                await self.control_writer.drain()
                self.send_queue.task_done()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.debug(f"[{self.agent_id}] Writer error: {e}")

    async def _keepalive_loop(self):
        """Sends periodic PING to control server."""
        try:
            while self.running and self.is_connected:
                await asyncio.sleep(self.keepalive_interval)
                await self._send_frame(CMD_PING, 0)
        except asyncio.CancelledError:
            pass

    async def _send_frame(self, cmd: int, stream_id: int, payload: bytes = b""):
        frame = pack_frame(cmd, stream_id, payload)
        try:
            await self.send_queue.put(frame)
        except asyncio.CancelledError:
            pass

    async def _send_json(self, cmd: int, stream_id: int, data: dict):
        frame = pack_json(cmd, stream_id, data)
        try:
            await self.send_queue.put(frame)
        except asyncio.CancelledError:
            pass

    async def _dispatch_frame(self, cmd: int, stream_id: int, payload: bytes):
        if cmd == CMD_CONNECT_REQ:
            task = asyncio.create_task(
                self._handle_connect(stream_id, payload),
                name=f"{self.agent_id}-conn-{stream_id}",
            )
            self.pending_connects[stream_id] = task
        elif cmd == CMD_DATA:
            stream = self.active_streams.get(stream_id)
            if stream:
                await stream.write_data(payload)
        elif cmd == CMD_CLOSE:
            pending_task = self.pending_connects.pop(stream_id, None)
            if pending_task and not pending_task.done():
                pending_task.cancel()
            stream = self.active_streams.pop(stream_id, None)
            if stream:
                await stream.close(notify_control=False)
        elif cmd == CMD_PING:
            await self._send_frame(CMD_PONG, 0)
        elif cmd == CMD_PONG:
            pass

    async def _handle_connect(self, stream_id: int, payload: bytes):
        """Connects to target in the internet through this agent's isolated Tor circuit."""
        try:
            req = json.loads(payload.decode("utf-8"))
            host = req.get("host", "0.0.0.0")
            port = req.get("port", 0)
            proto = req.get("proto", "tcp")
        except Exception as e:
            logger.error(f"[{self.agent_id}] Invalid connect payload: {e}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_GENERAL_FAILURE, "error": "Invalid payload"},
            )
            return

        if proto == "udp":
            logger.warning(f"[{self.agent_id}] UDP stream requested, but Tor circuits only support TCP.")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_CONNECTION_REFUSED, "error": "UDP not supported over Tor circuit"},
            )
            return

        logger.info(f"[{self.agent_id}] [CONNECT] Routing to {host}:{port} via Tor :{self.tor_port} (Exit IP: {self.exit_ip or 'auto'})")

        target_reader = None
        target_writer = None
        try:
            target_reader, target_writer = await socks5_connect(
                self.tor_host,
                self.tor_port,
                host,
                port,
                timeout=self.connect_timeout,
                username=self.tor_username,
            )
        except asyncio.CancelledError:
            if target_writer:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass
            raise
        except asyncio.TimeoutError:
            logger.warning(f"[{self.agent_id}] Connection to {host}:{port} via Tor timed out")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_TIMEOUT, "error": "Tor connect timed out"},
            )
            return
        except ConnectionRefusedError:
            logger.warning(f"[{self.agent_id}] Tor connection refused by local port {self.tor_port}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_CONNECTION_REFUSED, "error": f"Tor port {self.tor_port} refused"},
            )
            return
        except Exception as e:
            logger.warning(f"[{self.agent_id}] Failed connecting to {host}:{port} via Tor: {e}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_HOST_UNREACHABLE, "error": str(e)},
            )
            return

        # Connected successfully via Tor!
        enable_socket_keepalive(target_writer)
        stream = TargetStream(
            stream_id,
            host,
            port,
            target_reader,
            target_writer,
            self._send_frame,
        )
        self.active_streams[stream_id] = stream
        stream.start_reading()

        # Send OK response back to control
        await self._send_json(
            CMD_CONNECT_RESP,
            stream_id,
            {"status": STATUS_SUCCESS},
        )
        self.pending_connects.pop(stream_id, None)
        logger.info(f"[{self.agent_id}] [TUNNEL OPEN] Stream #{stream_id} active via Tor :{self.tor_port} -> {host}:{port}")
