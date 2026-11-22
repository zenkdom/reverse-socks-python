"""
Reverse SOCKS Agent implementation.
Connects to socks-control, receives target connection requests,
executes outbound requests to the internet, and tunnels data back to socks-control.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
import os
from typing import Optional
from protocol import (
    CMD_AUTH_REQ,
    CMD_AUTH_RESP,
    CMD_CONNECT_REQ,
    CMD_CONNECT_RESP,
    CMD_DATA,
    CMD_CLOSE,
    CMD_PING,
    CMD_PONG,
    CMD_UDP_DATA,
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
    perform_tls_client_handshake,
    perform_http_connect_tunnel,
    TargetUdpStream,
)

logger = logging.getLogger("ReverseAgent")


class TargetStream:
    """Manages an active outbound TCP connection to a target internet server."""

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
        self.read_task = asyncio.create_task(self._reader_loop(), name=f"target-reader-{self.stream_id}")

    async def _reader_loop(self):
        """Read data received from target internet server and forward to control server."""
        try:
            while not self.closed:
                chunk = await self.reader.read(32768)
                if not chunk:
                    # Target closed connection (EOF)
                    break
                await self.send_frame_func(CMD_DATA, self.stream_id, chunk)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.debug(f"[Stream #{self.stream_id}] Target read error: {e}")
        finally:
            await self.close(notify_control=True)

    async def write_data(self, data: bytes):
        """Write data received from control server (client) to target internet server."""
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


class ReverseAgent:
    """Agent that maintains a reverse tunnel connection to socks-control."""

    def __init__(
        self,
        control_host: str,
        control_port: int,
        secret_token: str,
        agent_id: str,
        use_faketls: bool = False,
        faketls_domain: str = "google.com",
        http_proxy: Optional[str] = None,
        connect_host: Optional[str] = None,
        connect_timeout: float = 15.0,
        keepalive_interval: float = 25.0,
        reconnect_delay: float = 3.0,
    ):
        self.control_host = control_host
        self.control_port = control_port
        self.secret_token = secret_token
        self.agent_id = agent_id
        self.use_faketls = use_faketls
        self.faketls_domain = faketls_domain or "google.com"
        self.http_proxy = http_proxy
        self.connect_host = connect_host
        self.connect_timeout = connect_timeout
        self.keepalive_interval = keepalive_interval
        self.reconnect_delay = reconnect_delay

        self.control_reader: Optional[asyncio.StreamReader] = None
        self.control_writer: Optional[asyncio.StreamWriter] = None
        self.send_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.writer_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None
        self.active_streams: dict[int, TargetStream] = {}
        self.pending_connects: dict[int, asyncio.Task] = {}
        self.running = False

    async def start(self):
        """Start the agent with an automatic reconnection loop."""
        self.running = True
        mode_str = f"Fake-TLS ({self.faketls_domain})" if self.use_faketls else "Plain TCP"
        logger.info(
            f"Starting Reverse Agent [{self.agent_id}] -> Control at {self.control_host}:{self.control_port} [{mode_str}]"
        )

        while self.running:
            try:
                await self._run_session()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Connection to control server failed or interrupted: {e}")

            if self.running:
                logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                await asyncio.sleep(self.reconnect_delay)

    async def stop(self):
        """Stop agent and terminate connections."""
        self.running = False
        await self._cleanup_session()
        logger.info("Reverse Agent stopped.")

    async def _run_session(self):
        """Establish connection, authenticate, and enter message loop."""
        # 1. Establish raw transport (Direct TCP or HTTP CONNECT through proxy like PythonAnywhere)
        proxy_url = self.http_proxy or os.environ.get("https_proxy") or os.environ.get("http_proxy")
        if proxy_url:
            logger.info(
                f"Connecting to control {self.control_host}:{self.control_port} via HTTP proxy {proxy_url} "
                f"(CONNECT Host: {self.connect_host or self.control_host})..."
            )
            raw_reader, raw_writer = await perform_http_connect_tunnel(
                proxy_url=proxy_url,
                target_host=self.control_host,
                target_port=self.control_port,
                timeout=self.connect_timeout,
                connect_host=self.connect_host,
            )
        else:
            logger.info(f"Connecting to control server {self.control_host}:{self.control_port}...")
            raw_reader, raw_writer = await asyncio.wait_for(
                asyncio.open_connection(self.control_host, self.control_port),
                timeout=self.connect_timeout,
            )

        enable_socket_keepalive(raw_writer)

        # 2. Negotiate Fake-TLS 1.3 handshake if requested
        if self.use_faketls:
            logger.info(f"Establishing Fake-TLS tunnel (SNI domain: {self.faketls_domain})...")
            self.control_reader, self.control_writer = await perform_tls_client_handshake(
                raw_reader,
                raw_writer,
                domain=self.faketls_domain,
                timeout=self.connect_timeout,
            )
            logger.info(f"[OK] Fake-TLS tunnel established with SNI: {self.faketls_domain}")
        else:
            self.control_reader, self.control_writer = raw_reader, raw_writer
            logger.info("Connected to control server via Plain TCP.")

        logger.info("Authenticating with control server...")

        # Start background writer task
        self.writer_task = asyncio.create_task(self._writer_loop(), name=f"agent-writer-{self.agent_id}")

        # Send authentication request
        await self._send_json(
            CMD_AUTH_REQ,
            0,
            {"token": self.secret_token, "agent_id": self.agent_id},
        )

        # Wait for authentication response
        frame = await asyncio.wait_for(read_frame(self.control_reader), timeout=10.0)
        if not frame:
            raise ConnectionError("Control server closed connection during auth")

        cmd, stream_id, payload = frame
        if cmd != CMD_AUTH_RESP:
            raise ConnectionError(f"Unexpected response cmd during auth: {cmd}")

        auth_resp = json.loads(payload.decode("utf-8"))
        if auth_resp.get("status") != "ok":
            raise PermissionError(f"Authentication rejected: {auth_resp.get('message')}")

        logger.info(f"[OK] Successfully registered and ready to handle proxy requests!")

        # Start periodic keepalive
        self.keepalive_task = asyncio.create_task(self._keepalive_loop(), name="agent-keepalive")

        # Main frame loop
        try:
            while self.running:
                frame = await read_frame(self.control_reader)
                if not frame:
                    logger.warning("Control server closed connection.")
                    break
                cmd, stream_id, payload = frame
                await self._handle_frame(cmd, stream_id, payload)
        finally:
            await self._cleanup_session()

    async def _handle_frame(self, cmd: int, stream_id: int, payload: bytes):
        """Dispatch incoming commands from socks-control."""
        if cmd == CMD_CONNECT_REQ:
            # Asynchronously handle target connection so message loop isn't blocked
            task = asyncio.create_task(self._handle_connect(stream_id, payload), name=f"connect-{stream_id}")
            self.pending_connects[stream_id] = task

        elif cmd == CMD_DATA:
            stream = self.active_streams.get(stream_id)
            if stream and hasattr(stream, "write_data"):
                await stream.write_data(payload)

        elif cmd == CMD_UDP_DATA:
            stream = self.active_streams.get(stream_id)
            if stream and hasattr(stream, "send_datagram"):
                asyncio.create_task(stream.send_datagram(payload))

        elif cmd == CMD_CLOSE:
            # Cancel in-flight connect task if still attempting connection
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
        """Connect to target in the internet and notify control server."""
        target_reader = None
        target_writer = None
        try:
            req = json.loads(payload.decode("utf-8"))
            host = req.get("host", "0.0.0.0")
            port = req.get("port", 0)
            proto = req.get("proto", "tcp")
        except Exception as e:
            logger.error(f"[Stream #{stream_id}] Invalid connect payload: {e}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_GENERAL_FAILURE, "error": "Invalid payload"},
            )
            return

        # Handle UDP Relay request
        if proto == "udp":
            try:
                udp_stream = TargetUdpStream(stream_id, self.send_frame_nowait)
                await udp_stream.start()
                self.active_streams[stream_id] = udp_stream
                logger.info(f"[TUNNEL] [Stream #{stream_id}] Outbound UDP relay initialized on reverse agent.")
                await self._send_json(
                    CMD_CONNECT_RESP,
                    stream_id,
                    {"status": STATUS_SUCCESS},
                )
            except Exception as e:
                logger.error(f"[Stream #{stream_id}] Failed to init UDP relay: {e}")
                await self._send_json(
                    CMD_CONNECT_RESP,
                    stream_id,
                    {"status": STATUS_GENERAL_FAILURE, "error": str(e)},
                )
            finally:
                self.pending_connects.pop(stream_id, None)
            return

        logger.info(f"[CONNECT] [Stream #{stream_id}] Connecting to target in internet: {host}:{port}")

        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.connect_timeout,
            )
        except asyncio.CancelledError:
            logger.info(f"[Stream #{stream_id}] Connect attempt cancelled (timed out on control server or failed over)")
            if target_writer:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass
            raise
        except asyncio.TimeoutError:
            logger.warning(f"[Stream #{stream_id}] Connection to {host}:{port} timed out")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_TIMEOUT, "error": "Connection timed out"},
            )
            return
        except ConnectionRefusedError:
            logger.warning(f"[Stream #{stream_id}] Connection refused by {host}:{port}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_CONNECTION_REFUSED, "error": "Connection refused"},
            )
            return
        except socket.gaierror as e:
            logger.warning(f"[Stream #{stream_id}] DNS resolution failed for {host}: {e}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_HOST_UNREACHABLE, "error": f"DNS error: {e}"},
            )
            return
        except Exception as e:
            logger.warning(f"[Stream #{stream_id}] Failed connecting to {host}:{port}: {e}")
            await self._send_json(
                CMD_CONNECT_RESP,
                stream_id,
                {"status": STATUS_NETWORK_UNREACHABLE, "error": str(e)},
            )
            return
        finally:
            self.pending_connects.pop(stream_id, None)

        # Target connected successfully
        enable_socket_keepalive(target_writer)
        logger.info(f"[TUNNEL] [Stream #{stream_id}] Connected to {host}:{port} successfully! Tunnel open.")
        target_stream = TargetStream(
            stream_id=stream_id,
            host=host,
            port=port,
            reader=target_reader,
            writer=target_writer,
            send_frame_func=self._send_frame,
        )
        self.active_streams[stream_id] = target_stream
        target_stream.start_reading()

        # Send success response to control
        await self._send_json(
            CMD_CONNECT_RESP,
            stream_id,
            {"status": STATUS_SUCCESS},
        )

    async def _writer_loop(self):
        """Pulls frames from send_queue and transmits over control socket."""
        try:
            while True:
                frame = await self.send_queue.get()
                if frame is None:
                    break
                if self.control_writer:
                    self.control_writer.write(frame)
                    await self.control_writer.drain()
                self.send_queue.task_done()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.warning(f"Error in control writer: {e}")

    async def _keepalive_loop(self):
        """Sends periodic PING to control server."""
        try:
            while True:
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

    def send_frame_nowait(self, cmd: int, stream_id: int, payload: bytes = b""):
        frame = pack_frame(cmd, stream_id, payload)
        try:
            self.send_queue.put_nowait(frame)
        except Exception:
            pass

    async def _send_json(self, cmd: int, stream_id: int, data: dict):
        frame = pack_json(cmd, stream_id, data)
        try:
            await self.send_queue.put(frame)
        except asyncio.CancelledError:
            pass

    async def _cleanup_session(self):
        """Close all target streams, pending connects, and reset connection state."""
        if self.keepalive_task and not self.keepalive_task.done():
            self.keepalive_task.cancel()

        for task in list(self.pending_connects.values()):
            if not task.done():
                task.cancel()
        self.pending_connects.clear()

        # Close all active target streams concurrently with timeout
        stream_closes = [stream.close(notify_control=False) for stream in list(self.active_streams.values())]
        self.active_streams.clear()
        if stream_closes:
            try:
                await asyncio.wait_for(asyncio.gather(*stream_closes, return_exceptions=True), timeout=1.0)
            except Exception:
                pass

        try:
            self.send_queue.put_nowait(None)
        except Exception:
            pass

        if self.writer_task and not self.writer_task.done():
            self.writer_task.cancel()

        if self.control_writer:
            await safe_close_writer(self.control_writer, timeout=0.5)
            self.control_writer = None
            self.control_reader = None
