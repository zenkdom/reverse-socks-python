"""
Universal Proxy Server implementation for socks-control.
Supports ALL protocols and proxy methods on a single port:
- SOCKS5 (RFC 1928): TCP CONNECT (0x01), TCP BIND (0x02), UDP ASSOCIATE (0x03)
- SOCKS4 / SOCKS4a: TCP CONNECT & Domain resolution
- HTTP / HTTPS Proxy: HTTP CONNECT tunneling (RFC 2817) and plain HTTP forward proxying
- Strict authentication: RFC 1929 Username/Password, SOCKS4 UserID, HTTP Basic Proxy-Authorization
- Multi-protocol reverse tunnel multiplexing through socks-reverse agents pool
"""
from __future__ import annotations

import asyncio
import struct
import socket
import logging
import base64
import ipaddress
import urllib.parse
from typing import Optional
from agent_manager import AgentManager, StreamContext
from socks_users import UserManager
from protocol import (
    CMD_CONNECT_REQ,
    CMD_DATA,
    CMD_CLOSE,
    CMD_UDP_DATA,
    STATUS_SUCCESS,
    STATUS_CONNECTION_REFUSED,
    STATUS_NETWORK_UNREACHABLE,
    STATUS_HOST_UNREACHABLE,
    STATUS_TIMEOUT,
    safe_close_writer,
    enable_socket_keepalive,
    pack_socks5_udp_packet,
    parse_socks5_udp_packet,
    TargetUdpStream,
)

logger = logging.getLogger("ProxyServer")

# SOCKS5 constants
SOCKS_VERSION = 0x05

# Auth methods
AUTH_NO_AUTH = 0x00
AUTH_USER_PASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


class Socks5Server:
    """
    Universal Multi-Protocol Proxy Server.
    Auto-detects and serves SOCKS5 (TCP, UDP, BIND), SOCKS4/4a, and HTTP/HTTPS CONNECT.
    """

    def __init__(
        self,
        agent_manager: AgentManager,
        user_manager: UserManager,
        host: str = "0.0.0.0",
        port: int = 1080,
        fast_timeout: float = 2.0,
        connect_timeout: float = 15.0,
    ):
        self.agent_manager = agent_manager
        self.user_manager = user_manager
        self.host = host
        self.port = port
        self.fast_timeout = fast_timeout
        self.connect_timeout = connect_timeout
        self.server: Optional[asyncio.Server] = None
        self.active_tasks: set[asyncio.Task] = set()
        self.active_writers: set[asyncio.StreamWriter] = set()
        self.closed = False

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
            backlog=2048,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(
            f"[*] Universal Proxy Server listening on {addrs} "
            f"(Supported: SOCKS5 [TCP, UDP, BIND], SOCKS4/4a, HTTP/HTTPS CONNECT)"
        )

    async def stop(self):
        self.closed = True
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
            except Exception:
                pass

        # Close all active client connections immediately
        for writer in list(self.active_writers):
            try:
                writer.close()
            except Exception:
                pass
        self.active_writers.clear()

        # Cancel remaining active tasks
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
        logger.info("Universal Proxy Server stopped.")

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        if self.closed:
            try:
                client_writer.close()
            except Exception:
                pass
            return

        current_task = asyncio.current_task()
        if current_task:
            self.active_tasks.add(current_task)
        self.active_writers.add(client_writer)

        client_addr = client_writer.get_extra_info("peername")
        client_ip = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "unknown"

        enable_socket_keepalive(client_writer)

        try:
            # 1. Peek first byte to auto-detect protocol:
            # 0x05 -> SOCKS5
            # 0x04 -> SOCKS4 / SOCKS4a
            # ASCII letters -> HTTP / HTTPS proxy (CONNECT, GET, POST, ...)
            try:
                first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=10.0)
            except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
                return

            if first_byte == b"\x05":
                # === SOCKS5 (RFC 1928) ===
                try:
                    nmethods = (await asyncio.wait_for(client_reader.readexactly(1), timeout=10.0))[0]
                except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
                    return

                username = await asyncio.wait_for(
                    self._authenticate_socks5(client_reader, client_writer, client_ip, nmethods),
                    timeout=10.0,
                )
                if not username:
                    return

                cmd, target_host, target_port = await asyncio.wait_for(
                    self._parse_socks5_request(client_reader, client_writer, client_ip),
                    timeout=10.0,
                )
                if cmd is None:
                    return

                if cmd == CMD_CONNECT:
                    # SOCKS5 TCP CONNECT
                    user_key = f"socks:{username}"
                    agent, stream, status = await self.agent_manager.establish_stream(
                        target_host,
                        target_port,
                        user_key=user_key,
                        client_ip=client_ip,
                        fast_timeout=self.fast_timeout,
                        total_timeout=self.connect_timeout,
                        proto="tcp",
                    )
                    if not agent or not stream:
                        logger.warning(
                            f"[{client_ip}] [{user_key}] Request to {target_host}:{target_port} failed: "
                            f"No reverse agent could establish connection (status code: {status})"
                        )
                        rep_code = self._map_status_to_reply(status)
                        await self._send_reply(client_writer, rep_code)
                        return

                    logger.info(
                        f"[ROUTE TCP] [{client_ip}] [{user_key}] -> Routing request to {target_host}:{target_port} "
                        f"via Reverse Agent [{agent.agent_id}] (Stream #{stream.stream_id})"
                    )
                    await self._send_reply(client_writer, REP_SUCCESS)
                    await self._pipe_data(client_reader, client_writer, agent, stream, client_ip)

                elif cmd == CMD_UDP_ASSOCIATE:
                    # SOCKS5 UDP ASSOCIATE (RFC 1928)
                    await self._handle_udp_associate(client_reader, client_writer, client_ip, username)

                elif cmd == CMD_BIND:
                    # SOCKS5 TCP BIND (RFC 1928)
                    await self._handle_bind(client_reader, client_writer, client_ip, target_host, target_port, username)

            elif first_byte == b"\x04":
                # === SOCKS4 / SOCKS4a ===
                await self._handle_socks4(client_reader, client_writer, client_ip)

            elif first_byte in (b"C", b"G", b"P", b"H", b"D", b"O", b"T"):
                # === HTTP / HTTPS Proxy (CONNECT / GET / POST ...) ===
                await self._handle_http_proxy(client_reader, client_writer, client_ip, first_byte)

            else:
                logger.warning(f"[{client_ip}] Unsupported protocol prefix: {first_byte.hex()}")
                return

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except Exception as e:
            logger.error(f"[{client_ip}] Unexpected error in Proxy handler: {e}", exc_info=True)
        finally:
            if current_task:
                self.active_tasks.discard(current_task)
            self.active_writers.discard(client_writer)
            await safe_close_writer(client_writer, timeout=0.5)

    async def _authenticate_socks5(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str, nmethods: int
    ) -> Optional[str]:
        """Handle SOCKS5 greeting and enforce username/password authentication."""
        try:
            methods = await reader.readexactly(nmethods)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

        # Strictly reject unauthenticated connections (Authentication: STRICTLY REQUIRED)
        if AUTH_USER_PASS not in methods:
            logger.warning(f"[{client_ip}] SOCKS5 rejected: unauthenticated requests not allowed (requires user/pass)")
            writer.write(bytes([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
            await writer.drain()
            return None

        writer.write(bytes([SOCKS_VERSION, AUTH_USER_PASS]))
        await writer.drain()

        # RFC 1929 Auth subnegotiation
        try:
            auth_ver = (await reader.readexactly(1))[0]
            if auth_ver != 0x01:
                return None

            ulen = (await reader.readexactly(1))[0]
            uname = (await reader.readexactly(ulen)).decode("utf-8", errors="ignore")

            plen = (await reader.readexactly(1))[0]
            passwd = (await reader.readexactly(plen)).decode("utf-8", errors="ignore")
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return None

        if self.user_manager.authenticate(uname, passwd):
            writer.write(b"\x01\x00")  # Auth success
            await writer.drain()
            logger.info(f"[AUTH OK] [{client_ip}] SOCKS5 authenticated as user '{uname}'")
            return uname
        else:
            writer.write(b"\x01\x01")  # Auth failure
            await writer.drain()
            logger.warning(f"[AUTH FAIL] [{client_ip}] SOCKS5 failed auth for user '{uname}'")
            return None

    async def _parse_socks5_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str
    ) -> tuple[Optional[int], Optional[str], Optional[int]]:
        """Parse SOCKS5 request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)."""
        try:
            header = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            logger.info(f"[{client_ip}] Client closed connection after auth (Telegram ping / availability check)")
            return None, None, None
        except ConnectionResetError:
            logger.info(f"[{client_ip}] Connection reset by client after auth")
            return None, None, None

        ver, cmd, _, atyp = header
        if ver != SOCKS_VERSION:
            logger.warning(f"[{client_ip}] Invalid SOCKS version in request: {ver}")
            return None, None, None

        if cmd not in (CMD_CONNECT, CMD_UDP_ASSOCIATE, CMD_BIND):
            cmd_name = {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}.get(cmd, f"CMD_{cmd}")
            logger.warning(f"[{client_ip}] Unsupported SOCKS5 command: {cmd_name} ({cmd})")
            await self._send_reply(writer, REP_CMD_NOT_SUPPORTED)
            return None, None, None

        target_host: Optional[str] = None
        if atyp == ATYP_IPV4:
            data = await reader.readexactly(4)
            target_host = socket.inet_ntoa(data)
        elif atyp == ATYP_DOMAIN:
            dlen = (await reader.readexactly(1))[0]
            data = await reader.readexactly(dlen)
            target_host = data.decode("utf-8", errors="ignore")
        elif atyp == ATYP_IPV6:
            data = await reader.readexactly(16)
            target_host = socket.inet_ntop(socket.AF_INET6, data)
            logger.info(f"[{client_ip}] IPv6 destination requested: [{target_host}]")
        else:
            logger.warning(f"[{client_ip}] Unsupported address type ATYP: {atyp}")
            await self._send_reply(writer, REP_ATYP_NOT_SUPPORTED)
            return None, None, None

        port_data = await reader.readexactly(2)
        target_port = struct.unpack("!H", port_data)[0]

        return cmd, target_host, target_port

    async def _handle_udp_associate(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
        username: str,
    ):
        """Handle SOCKS5 UDP ASSOCIATE command (RFC 1928 Section 4, 6, 7)."""
        user_key = f"socks:{username}"
        loop = asyncio.get_running_loop()
        client_udp_endpoint: list[Optional[tuple[str, int]]] = [None]
        udp_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
        direct_handler: Optional[TargetUdpStream] = None

        class ClientUdpProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]):
                client_udp_endpoint[0] = addr
                try:
                    udp_queue.put_nowait(data)
                except asyncio.QueueFull:
                    pass

            def error_received(self, exc):
                pass

        # 1. Bind local UDP socket for SOCKS5 client datagram relay
        bind_host = self.host if self.host not in ("0.0.0.0", "::") else "0.0.0.0"
        transport, _ = await loop.create_datagram_endpoint(
            ClientUdpProtocol,
            local_addr=(bind_host, 0),
        )
        bnd_port = transport.get_extra_info("sockname")[1]

        # Determine BND.ADDR to report to client
        sockname = client_writer.get_extra_info("sockname")
        reported_ip = "127.0.0.1"
        if sockname and len(sockname) >= 2 and isinstance(sockname[0], str):
            candidate_ip = sockname[0].split("%")[0]
            if candidate_ip not in ("0.0.0.0", "::"):
                reported_ip = candidate_ip
            else:
                peername = client_writer.get_extra_info("peername")
                if peername and peername[0] in ("127.0.0.1", "::1"):
                    reported_ip = "127.0.0.1"
                elif self.host not in ("0.0.0.0", "::"):
                    reported_ip = self.host

        # 2. Establish UDP stream via reverse agent
        agent, stream, status = await self.agent_manager.establish_stream(
            "0.0.0.0",
            0,
            user_key=user_key,
            client_ip=client_ip,
            fast_timeout=self.fast_timeout,
            total_timeout=self.connect_timeout,
            proto="udp",
        )

        if not agent or not stream:
            logger.info(f"[{client_ip}] [{user_key}] No reverse agents for UDP; activating local direct UDP relay")
            direct_handler = TargetUdpStream(0, None)

            def direct_on_recv(data: bytes, addr: tuple[str, int]):
                if client_udp_endpoint[0] and transport:
                    pkt = pack_socks5_udp_packet(addr[0], addr[1], data)
                    transport.sendto(pkt, client_udp_endpoint[0])

            await direct_handler.start(on_datagram_cb=direct_on_recv)

        # 3. Send SOCKS5 success reply with BND.ADDR & BND.PORT
        try:
            ip_bytes = socket.inet_aton(reported_ip)
            reply = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4]) + ip_bytes + struct.pack("!H", bnd_port)
        except Exception:
            reply = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4, 127, 0, 0, 1]) + struct.pack("!H", bnd_port)
        client_writer.write(reply)
        await client_writer.drain()

        target_node = f"Reverse Agent [{agent.agent_id}]" if agent else "Direct Local Relay"
        logger.info(f"[UDP ASSOCIATE OK] [{client_ip}] [{user_key}] Relay on {reported_ip}:{bnd_port} -> {target_node}")

        # 4. Bidirectional UDP datagram pumping
        udp_active = True

        async def client_udp_pump():
            while udp_active:
                try:
                    data = await udp_queue.get()
                    if agent and stream:
                        agent.send_frame_nowait(CMD_UDP_DATA, stream.stream_id, data)
                    elif direct_handler:
                        await direct_handler.send_datagram(data)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"Error in client_udp_pump: {e}")

        async def agent_udp_pump():
            if not stream:
                return
            while udp_active:
                try:
                    packet = await stream.udp_queue.get()
                    if packet is None:
                        break
                    if client_udp_endpoint[0] and transport:
                        transport.sendto(packet, client_udp_endpoint[0])
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"Error in agent_udp_pump: {e}")

        async def tcp_monitor():
            """Monitors the controlling TCP connection. Terminating TCP closes the UDP association."""
            try:
                while not self.closed:
                    chunk = await client_reader.read(4096)
                    if not chunk:
                        break
            except Exception:
                pass

        t_pump = asyncio.create_task(client_udp_pump(), name=f"udp-pump-c2a-{client_ip}")
        t_agent = asyncio.create_task(agent_udp_pump(), name=f"udp-pump-a2c-{client_ip}")
        t_mon = asyncio.create_task(tcp_monitor(), name=f"udp-mon-{client_ip}")

        try:
            await t_mon
        finally:
            udp_active = False
            for t in (t_pump, t_agent, t_mon):
                if not t.done():
                    t.cancel()
            try:
                transport.close()
            except Exception:
                pass
            if direct_handler:
                await direct_handler.close()
            if agent and stream:
                await agent.send_frame(CMD_CLOSE, stream.stream_id)
                agent.remove_stream(stream.stream_id)
            logger.info(f"[UDP CLOSED] [{client_ip}] [{user_key}] UDP association terminated.")

    async def _handle_bind(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
        target_host: Optional[str],
        target_port: Optional[int],
        username: str,
    ):
        """Handle SOCKS5 BIND command (RFC 1928 Section 4/6)."""
        user_key = f"socks:{username}"
        loop = asyncio.get_running_loop()
        incoming_conn: asyncio.Future = loop.create_future()

        def on_connect(r, w):
            if not incoming_conn.done():
                incoming_conn.set_result((r, w))
            else:
                try:
                    w.close()
                except Exception:
                    pass

        try:
            bind_server = await asyncio.start_server(on_connect, host="0.0.0.0", port=0)
            bnd_port = bind_server.sockets[0].getsockname()[1]
            sockname = client_writer.get_extra_info("sockname")
            bnd_ip = sockname[0].split("%")[0] if sockname and isinstance(sockname[0], str) else "127.0.0.1"
            if bnd_ip in ("0.0.0.0", "::"):
                bnd_ip = "127.0.0.1"

            # First reply: inform client of bound port
            reply1 = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4]) + socket.inet_aton(bnd_ip) + struct.pack("!H", bnd_port)
            client_writer.write(reply1)
            await client_writer.drain()
            logger.info(f"[BIND] [{client_ip}] [{user_key}] Listening on {bnd_ip}:{bnd_port} for incoming peer")

            # Wait for incoming connection (timeout 30s)
            in_r, in_w = await asyncio.wait_for(incoming_conn, timeout=30.0)
            peer = in_w.get_extra_info("peername")
            peer_ip = peer[0].split("%")[0] if peer else "127.0.0.1"
            peer_port = peer[1] if peer else 0

            # Second reply: inform client of incoming peer address
            reply2 = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4]) + socket.inet_aton(peer_ip) + struct.pack("!H", peer_port)
            client_writer.write(reply2)
            await client_writer.drain()
            logger.info(f"[BIND CONNECTED] [{client_ip}] Incoming peer connected from {peer_ip}:{peer_port}")

            # Pipe between client and incoming connection
            async def pipe(r, w):
                try:
                    while not self.closed:
                        chunk = await r.read(32768)
                        if not chunk:
                            break
                        w.write(chunk)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    await safe_close_writer(w)

            t1 = asyncio.create_task(pipe(client_reader, in_w))
            t2 = asyncio.create_task(pipe(in_r, client_writer))
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in (t1, t2):
                if not t.done():
                    t.cancel()

        except asyncio.TimeoutError:
            logger.warning(f"[BIND TIMEOUT] [{client_ip}] Timed out waiting for incoming connection")
            await self._send_reply(client_writer, REP_TTL_EXPIRED)
        except Exception as e:
            logger.error(f"[BIND ERROR] [{client_ip}]: {e}")
            await self._send_reply(client_writer, REP_GENERAL_FAILURE)
        finally:
            bind_server.close()
            try:
                await bind_server.wait_closed()
            except Exception:
                pass

    async def _handle_socks4(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
    ):
        """Handle SOCKS4 and SOCKS4a requests."""
        try:
            cmd_data = await asyncio.wait_for(client_reader.readexactly(1), timeout=10.0)
            cmd = cmd_data[0]

            port_data = await asyncio.wait_for(client_reader.readexactly(2), timeout=10.0)
            target_port = struct.unpack("!H", port_data)[0]

            ip_bytes = await asyncio.wait_for(client_reader.readexactly(4), timeout=10.0)

            # Read USERID (null terminated)
            userid_bytes = bytearray()
            while len(userid_bytes) < 256:
                b = await client_reader.readexactly(1)
                if b == b"\x00":
                    break
                userid_bytes.extend(b)
            userid = userid_bytes.decode("utf-8", errors="ignore")

            # Check if SOCKS4a (IP 0.0.0.x with x != 0)
            is_socks4a = (ip_bytes[:3] == b"\x00\x00\x00" and ip_bytes[3] != 0)
            if is_socks4a:
                domain_bytes = bytearray()
                while len(domain_bytes) < 256:
                    b = await client_reader.readexactly(1)
                    if b == b"\x00":
                        break
                    domain_bytes.extend(b)
                target_host = domain_bytes.decode("utf-8", errors="ignore")
            else:
                target_host = socket.inet_ntoa(ip_bytes)

            # Auth check: if users are configured, enforce valid userid
            users = self.user_manager.get_all_users()
            if users and not self.user_manager.has_user(userid):
                logger.warning(f"[{client_ip}] SOCKS4 auth failed: user '{userid}' not allowed")
                client_writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                return

            if cmd != 0x01:  # Only CONNECT supported in SOCKS4
                logger.warning(f"[{client_ip}] Unsupported SOCKS4 command: {cmd}")
                client_writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                return

            user_key = f"socks4:{userid}" if userid else "socks4:anon"
            agent, stream, status = await self.agent_manager.establish_stream(
                target_host,
                target_port,
                user_key=user_key,
                client_ip=client_ip,
                fast_timeout=self.fast_timeout,
                total_timeout=self.connect_timeout,
                proto="tcp",
            )
            if not agent or not stream:
                client_writer.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                return

            # SOCKS4 success response: 0x00, 0x5A (granted), port, ip
            client_writer.write(b"\x00\x5a" + port_data + ip_bytes)
            await client_writer.drain()
            logger.info(f"[SOCKS4 OK] [{client_ip}] [{user_key}] Connected to {target_host}:{target_port}")

            await self._pipe_data(client_reader, client_writer, agent, stream, client_ip)

        except Exception as e:
            logger.warning(f"[{client_ip}] SOCKS4 error: {e}")

    async def _handle_http_proxy(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        client_ip: str,
        first_byte: bytes,
    ):
        """Handle HTTP and HTTPS (CONNECT) proxy requests."""
        try:
            line_bytes = await asyncio.wait_for(client_reader.readline(), timeout=10.0)
            full_line = (first_byte + line_bytes).decode("utf-8", errors="ignore").strip()
            parts = full_line.split()
            if len(parts) < 2:
                return
            method, url = parts[0].upper(), parts[1]

            # Read headers
            headers: dict[str, str] = {}
            while True:
                h_line = await asyncio.wait_for(client_reader.readline(), timeout=5.0)
                if not h_line or h_line in (b"\r\n", b"\n"):
                    break
                h_str = h_line.decode("utf-8", errors="ignore").strip()
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Auth check
            username = "anon"
            authenticated = False
            all_users = self.user_manager.get_all_users()
            if not all_users:
                authenticated = True
            else:
                p_auth = headers.get("proxy-authorization", "")
                if p_auth.lower().startswith("basic "):
                    try:
                        raw = base64.b64decode(p_auth[6:].strip()).decode("utf-8", errors="ignore")
                        if ":" in raw:
                            u, p = raw.split(":", 1)
                            if self.user_manager.authenticate(u, p):
                                username = u
                                authenticated = True
                    except Exception:
                        pass

            if not authenticated:
                logger.warning(f"[{client_ip}] HTTP proxy auth required")
                resp = (
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"Reverse SOCKS Universal Proxy\"\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                client_writer.write(resp)
                await client_writer.drain()
                return

            user_key = f"http:{username}"

            if method == "CONNECT":
                # HTTPS Tunnel
                if ":" in url:
                    thost, tport_str = url.split(":", 1)
                    tport = int(tport_str)
                else:
                    thost = url
                    tport = 443

                agent, stream, status = await self.agent_manager.establish_stream(
                    thost,
                    tport,
                    user_key=user_key,
                    client_ip=client_ip,
                    fast_timeout=self.fast_timeout,
                    total_timeout=self.connect_timeout,
                    proto="tcp",
                )
                if not agent or not stream:
                    client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    await client_writer.drain()
                    return

                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
                logger.info(f"[HTTP CONNECT OK] [{client_ip}] [{user_key}] Tunnel to {thost}:{tport}")
                await self._pipe_data(client_reader, client_writer, agent, stream, client_ip)

            else:
                # Standard HTTP GET/POST/etc.
                parsed = urllib.parse.urlparse(url)
                thost = parsed.hostname or headers.get("host", "").split(":")[0]
                tport = parsed.port or (443 if parsed.scheme == "https" else 80)
                if not thost:
                    client_writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    await client_writer.drain()
                    return

                agent, stream, status = await self.agent_manager.establish_stream(
                    thost,
                    tport,
                    user_key=user_key,
                    client_ip=client_ip,
                    fast_timeout=self.fast_timeout,
                    total_timeout=self.connect_timeout,
                    proto="tcp",
                )
                if not agent or not stream:
                    client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    await client_writer.drain()
                    return

                # Forward modified request line and headers (strip Proxy-Authorization)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                http_ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
                req_lines = [f"{method} {path} {http_ver}"]
                for hk, hv in headers.items():
                    if hk in ("proxy-authorization", "proxy-connection"):
                        continue
                    req_lines.append(f"{hk.title()}: {hv}")
                req_lines.append("\r\n")
                req_bytes = "\r\n".join(req_lines).encode("utf-8")

                await agent.send_frame(CMD_DATA, stream.stream_id, req_bytes)
                logger.info(f"[HTTP FORWARD OK] [{client_ip}] [{user_key}] {method} http://{thost}:{tport}{path}")
                await self._pipe_data(client_reader, client_writer, agent, stream, client_ip)

        except Exception as e:
            logger.warning(f"[{client_ip}] HTTP proxy error: {e}")

    async def _send_reply(self, writer: asyncio.StreamWriter, rep_code: int):
        """Send SOCKS5 response frame to client with bound socket info."""
        try:
            sockname = writer.get_extra_info("sockname")
            if sockname and len(sockname) >= 2 and isinstance(sockname[0], str):
                ip_parts = sockname[0].split("%")[0]
                try:
                    ip_bytes = socket.inet_aton(ip_parts)
                    port_bytes = struct.pack("!H", sockname[1])
                    reply = bytes([SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4]) + ip_bytes + port_bytes
                except Exception:
                    reply = bytes([SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            else:
                reply = bytes([SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        except Exception:
            reply = bytes([SOCKS_VERSION, rep_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])

        try:
            writer.write(reply)
            await writer.drain()
        except Exception:
            pass

    def _map_status_to_reply(self, status: int) -> int:
        if status == STATUS_CONNECTION_REFUSED:
            return REP_CONNECTION_REFUSED
        elif status == STATUS_NETWORK_UNREACHABLE:
            return REP_NETWORK_UNREACHABLE
        elif status == STATUS_HOST_UNREACHABLE:
            return REP_HOST_UNREACHABLE
        elif status == STATUS_TIMEOUT:
            return REP_TTL_EXPIRED
        return REP_GENERAL_FAILURE

    async def _pipe_data(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        agent,
        stream: StreamContext,
        client_ip: str,
    ):
        """
        Bidirectionally stream data between the client and Reverse Agent.
        """
        stream_id = stream.stream_id
        bytes_up = 0
        bytes_down = 0
        IDLE_TIMEOUT = 300.0  # 5 minutes idle timeout to prevent leaking abandoned client sockets

        async def client_to_agent():
            nonlocal bytes_up
            try:
                while not agent.closed:
                    chunk = await asyncio.wait_for(client_reader.read(32768), timeout=IDLE_TIMEOUT)
                    if not chunk:
                        break
                    bytes_up += len(chunk)
                    await agent.send_frame(CMD_DATA, stream_id, chunk)
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            finally:
                agent.send_frame_nowait(CMD_CLOSE, stream_id)

        async def agent_to_client():
            nonlocal bytes_down
            try:
                while True:
                    chunk = await stream.data_queue.get()
                    if chunk is None:
                        break
                    bytes_down += len(chunk)
                    client_writer.write(chunk)
                    await client_writer.drain()
                    stream.data_queue.task_done()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, asyncio.IncompleteReadError):
                pass

        try:
            logger.info(f"[TUNNEL OPEN] Stream #{stream_id} active: {client_ip} <-> {stream.host}:{stream.port}")
            t1 = asyncio.create_task(client_to_agent(), name=f"up-{stream_id}")
            t2 = asyncio.create_task(agent_to_client(), name=f"down-{stream_id}")
            done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for t in done:
                try:
                    t.exception()
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            agent.remove_stream(stream_id, notify_agent=True)
            agent.send_frame_nowait(CMD_CLOSE, stream_id)
            logger.info(
                f"[TUNNEL CLOSED] Stream #{stream_id} ({stream.host}:{stream.port}) finished. "
                f"Client sent: {bytes_up} bytes, Target returned: {bytes_down} bytes"
            )


# Alias for backwards compatibility
UniversalProxyServer = Socks5Server
