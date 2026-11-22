"""
Multiplexing Protocol for Reverse SOCKS5
Used for bidirectional communication between socks-control and socks-reverse.
"""
from __future__ import annotations

import struct
import json
import asyncio
import logging
import socket
import ipaddress
from typing import Optional

logger = logging.getLogger("Protocol")

# Magic bytes identifying reverse socks protocol packets
MAGIC = b"RSX5"  # 4 bytes
HEADER_FORMAT = "!4sBII"  # Magic (4B), Command (1B), Stream ID (4B), Length (4B)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 13 bytes

# Command IDs
CMD_AUTH_REQ     = 0x01  # Reverse -> Control: {"token": "...", "agent_id": "..."}
CMD_AUTH_RESP    = 0x02  # Control -> Reverse: {"status": "ok"|"error", "message": "..."}
CMD_CONNECT_REQ  = 0x03  # Control -> Reverse: {"host": "...", "port": int}
CMD_CONNECT_RESP = 0x04  # Reverse -> Control: {"status": 0|code, "error": "..."}
CMD_DATA         = 0x05  # Bi-directional: raw bytes
CMD_CLOSE        = 0x06  # Bi-directional: empty or reason
CMD_PING         = 0x07  # Bi-directional: keepalive ping
CMD_PONG         = 0x08  # Bi-directional: keepalive pong
CMD_UDP_DATA     = 0x09  # Bi-directional: SOCKS5 encapsulated UDP datagram

# Status codes for CMD_CONNECT_RESP
STATUS_SUCCESS = 0
STATUS_GENERAL_FAILURE = 1
STATUS_CONNECTION_REFUSED = 2
STATUS_NETWORK_UNREACHABLE = 3
STATUS_HOST_UNREACHABLE = 4
STATUS_TIMEOUT = 5

COMMAND_NAMES = {
    CMD_AUTH_REQ: "AUTH_REQ",
    CMD_AUTH_RESP: "AUTH_RESP",
    CMD_CONNECT_REQ: "CONNECT_REQ",
    CMD_CONNECT_RESP: "CONNECT_RESP",
    CMD_DATA: "DATA",
    CMD_CLOSE: "CLOSE",
    CMD_PING: "PING",
    CMD_PONG: "PONG",
    CMD_UDP_DATA: "UDP_DATA",
}

def pack_frame(cmd: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Pack command, stream_id and payload into a binary frame."""
    header = struct.pack(HEADER_FORMAT, MAGIC, cmd, stream_id, len(payload))
    return header + payload

def pack_json(cmd: int, stream_id: int, data: dict) -> bytes:
    """Pack a JSON dictionary as frame payload."""
    payload = json.dumps(data).encode("utf-8")
    return pack_frame(cmd, stream_id, payload)

async def read_frame(reader: asyncio.StreamReader) -> Optional[tuple[int, int, bytes]]:
    """
    Read a complete frame from the stream.
    Returns (cmd, stream_id, payload) or None if EOF reached.
    """
    try:
        header = await reader.readexactly(HEADER_SIZE)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None

    magic, cmd, stream_id, length = struct.unpack(HEADER_FORMAT, header)
    if magic != MAGIC:
        raise ValueError(f"Invalid protocol magic: {magic!r}, expected {MAGIC!r}")

    if length > 0:
        try:
            payload = await reader.readexactly(length)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return None
    else:
        payload = b""

    return cmd, stream_id, payload


def pack_socks5_udp_packet(ip_str: str, port: int, data: bytes) -> bytes:
    """Packs SOCKS5 UDP datagram header (RFC 1928 Section 7): RSV(2B) + FRAG(1B) + ATYP + ADDR + PORT + DATA"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            header = b"\x00\x00\x00\x01" + ip_obj.packed + struct.pack("!H", port)
        else:
            header = b"\x00\x00\x00\x04" + ip_obj.packed + struct.pack("!H", port)
    except Exception:
        # Fallback to domain type
        domain_b = ip_str.encode("utf-8")
        header = b"\x00\x00\x00\x03" + bytes([len(domain_b)]) + domain_b + struct.pack("!H", port)
    return header + data


def parse_socks5_udp_packet(payload: bytes) -> tuple[Optional[str], Optional[int], bytes, int]:
    """
    Parses SOCKS5 UDP datagram header (RFC 1928 Section 7).
    Returns (target_host, target_port, data, atyp).
    """
    if len(payload) < 7:
        return None, None, b"", 0
    frag = payload[2]
    if frag != 0:
        # Per RFC 1928 Section 7: Drop any datagram whose FRAG field is other than X'00'
        return None, None, b"", 0
    atyp = payload[3]
    offset = 4
    try:
        if atyp == 0x01:  # IPv4
            target_host = socket.inet_ntoa(payload[offset : offset + 4])
            offset += 4
        elif atyp == 0x03:  # Domain
            dlen = payload[offset]
            offset += 1
            target_host = payload[offset : offset + dlen].decode("utf-8", errors="ignore")
            offset += dlen
        elif atyp == 0x04:  # IPv6
            target_host = socket.inet_ntop(socket.AF_INET6, payload[offset : offset + 16])
            offset += 16
        else:
            return None, None, b"", atyp

        target_port = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        data = payload[offset:]
        return target_host, target_port, data, atyp
    except Exception:
        return None, None, b"", 0


class TargetUdpStream:
    """Manages an active outbound UDP relay endpoint."""

    def __init__(self, stream_id: int, send_frame_func=None):
        self.stream_id = stream_id
        self.send_frame_func = send_frame_func
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.closed = False

    async def start(self, on_datagram_cb=None):
        loop = asyncio.get_running_loop()
        callback = on_datagram_cb or self._on_datagram_received

        class _UdpProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]):
                callback(data, addr)

            def error_received(self, exc):
                pass

        self.transport, _ = await loop.create_datagram_endpoint(
            _UdpProtocol,
            local_addr=("0.0.0.0", 0),
        )

    def _on_datagram_received(self, data: bytes, addr: tuple[str, int]):
        if self.closed or not self.send_frame_func:
            return
        ip_str, port = addr
        try:
            packet = pack_socks5_udp_packet(ip_str, port, data)
            res = self.send_frame_func(CMD_UDP_DATA, self.stream_id, packet)
            if asyncio.iscoroutine(res):
                asyncio.create_task(res)
        except Exception as e:
            logger.debug(f"[Stream #{self.stream_id}] UDP packaging error: {e}")

    async def send_datagram(self, payload: bytes):
        if self.closed or not self.transport:
            return
        target_host, target_port, data, atyp = parse_socks5_udp_packet(payload)
        if not target_host or not target_port:
            return
        try:
            if atyp == 0x03:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(target_host, target_port, type=socket.SOCK_DGRAM)
                if not infos:
                    return
                dest_addr = infos[0][4]
                self.transport.sendto(data, (dest_addr[0], dest_addr[1]))
            else:
                self.transport.sendto(data, (target_host, target_port))
        except Exception as e:
            logger.debug(f"[Stream #{self.stream_id}] UDP send error to {target_host}:{target_port}: {e}")

    async def close(self, notify_control: bool = False):
        if self.closed:
            return
        self.closed = True
        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None
        if notify_control and self.send_frame_func:
            try:
                res = self.send_frame_func(CMD_CLOSE, self.stream_id)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass


async def safe_close_writer(writer: Optional[asyncio.StreamWriter], timeout: float = 0.5):
    """
    Safely closes a StreamWriter without hanging indefinitely.
    Guards wait_closed() with a short timeout to prevent termination hangs.
    """
    if not writer:
        return
    try:
        if not writer.is_closing():
            writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except Exception:
        pass


def enable_socket_keepalive(writer: Optional[asyncio.StreamWriter], idle: int = 60, interval: int = 10, count: int = 3):
    """
    Enables TCP Keepalive on the socket to clean up dead/zombie connections automatically.
    Reaps silent mobile disconnects after 60s idle + 30s probes instead of keeping open forever.
    Supports both Linux TCP socket options and Windows SIO_KEEPALIVE_VALS.
    """
    if not writer:
        return
    try:
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Windows WSAIoctl SIO_KEEPALIVE_VALS (idle_ms, interval_ms)
            if hasattr(socket, "SIO_KEEPALIVE_VALS"):
                try:
                    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, idle * 1000, interval * 1000))
                except Exception:
                    pass
            # Linux / POSIX keepalive options
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except Exception:
        pass


def raise_nofile_limit(target: int = 65535):
    """
    Attempts to raise the open file descriptor limit (RLIMIT_NOFILE)
    up to target (default 65535) or system maximum.
    Prevents 'Too many open files' (Errno 24) under high connection loads.
    """
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Try raising both hard and soft if target > hard (succeeds if root/CAP_SYS_RESOURCE)
        new_hard = max(hard, target)
        new_soft = max(soft, target)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, new_hard))
        except (ValueError, OSError, PermissionError):
            # If not root or system hard limit prevents it, raise soft up to existing hard
            new_soft = min(target, hard) if hard > 0 else target
            if new_soft > soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        logger.info(f"Open file descriptors limit (RLIMIT_NOFILE): soft={soft}, hard={hard}")
    except Exception as e:
        logger.debug(f"Could not adjust RLIMIT_NOFILE: {e}")


# ==============================================================================
# Fake-TLS 1.3 & HTTP CONNECT Support
# Allows reverse agents to tunnel connection via HTTPS Fake-TLS (whitelisted SNI)
# and through HTTP proxies (e.g. PythonAnywhere Squid proxy on proxy.server:3128).
# ==============================================================================
import os
import urllib.parse


class FakeTLSStreamReader:
    """
    Unwraps TLS 1.3 Application Data records (\x17\x03\x03),
    providing a transparent byte stream for reverse socks protocol frames.
    """

    def __init__(self, reader: asyncio.StreamReader):
        self.reader = reader
        self.buf = bytearray()

    async def _read_record(self) -> bytes:
        while True:
            try:
                hdr = await self.reader.readexactly(5)
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                return b""

            rec_type, v1, v2, rec_len = struct.unpack("!BBBH", hdr)
            try:
                data = await self.reader.readexactly(rec_len)
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                return b""

            if rec_type == 0x14:  # ChangeCipherSpec - ignore in TLS 1.3
                continue
            if rec_type != 0x17:  # Application Data
                logger.warning(f"Unexpected TLS record type in stream: {rec_type:#x}")
                return b""
            return data

    async def read(self, n: int = -1) -> bytes:
        if not self.buf:
            record = await self._read_record()
            if not record:
                return b""
            self.buf.extend(record)

        if n <= 0 or len(self.buf) <= n:
            res = bytes(self.buf)
            self.buf.clear()
            return res

        res = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return res

    async def readexactly(self, n: int) -> bytes:
        while len(self.buf) < n:
            record = await self._read_record()
            if not record:
                raise asyncio.IncompleteReadError(bytes(self.buf), n)
            self.buf.extend(record)

        res = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return res

    async def readline(self) -> bytes:
        while b"\n" not in self.buf:
            record = await self._read_record()
            if not record:
                break
            self.buf.extend(record)
        if b"\n" in self.buf:
            idx = self.buf.index(b"\n") + 1
            res = bytes(self.buf[:idx])
            self.buf = self.buf[idx:]
            return res
        res = bytes(self.buf)
        self.buf.clear()
        return res

    def at_eof(self) -> bool:
        return not self.buf and self.reader.at_eof()


class FakeTLSStreamWriter:
    """
    Wraps outgoing stream data into TLS 1.3 Application Data records (\x17\x03\x03).
    """
    MAX_RECORD_LEN = 16384

    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer

    def write(self, data: bytes):
        for start in range(0, len(data), self.MAX_RECORD_LEN):
            chunk = data[start : start + self.MAX_RECORD_LEN]
            record = b"\x17\x03\x03" + struct.pack("!H", len(chunk)) + chunk
            self.writer.write(record)

    def writelines(self, data_list):
        for data in data_list:
            self.write(data)

    async def drain(self):
        await self.writer.drain()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def is_closing(self) -> bool:
        return self.writer.is_closing()

    def get_extra_info(self, name, default=None):
        return self.writer.get_extra_info(name, default)


def build_tls_client_hello(domain: str = "google.com") -> tuple[bytes, bytes]:
    """
    Constructs an authentic TLS 1.3 ClientHello record with SNI set to domain.
    Returns (record_bytes, session_id).
    """
    domain_b = domain.encode("utf-8")
    sni_entry = b"\x00" + struct.pack("!H", len(domain_b)) + domain_b
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_sni = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list

    groups = struct.pack("!H", 4) + b"\x00\x1d\x00\x17"
    ext_groups = b"\x00\x0a" + struct.pack("!H", len(groups)) + groups

    versions = bytes([4]) + b"\x03\x04\x03\x03"
    ext_versions = b"\x00\x2b" + struct.pack("!H", len(versions)) + versions

    pub_key = os.urandom(32)
    ks_entry = b"\x00\x1d" + struct.pack("!H", 32) + pub_key
    ks_list = struct.pack("!H", len(ks_entry)) + ks_entry
    ext_ks = b"\x00\x33" + struct.pack("!H", len(ks_list)) + ks_list

    sigs = struct.pack("!H", 8) + b"\x04\x03\x08\x04\x04\x01\x05\x01"
    ext_sigs = b"\x00\x0d" + struct.pack("!H", len(sigs)) + sigs

    all_exts = ext_sni + ext_groups + ext_versions + ext_ks + ext_sigs
    ext_section = struct.pack("!H", len(all_exts)) + all_exts

    random_bytes = os.urandom(32)
    session_id = os.urandom(32)
    cipher_suites = struct.pack("!H", 6) + b"\x13\x01\x13\x02\x13\x03"
    compression = b"\x01\x00"

    body = (
        b"\x03\x03"
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + cipher_suites
        + compression
        + ext_section
    )
    handshake = b"\x01" + int.to_bytes(len(body), 3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record, session_id


def extract_sni_from_client_hello(data: bytes) -> str:
    """Extracts SNI hostname from TLS ClientHello data if present."""
    try:
        offset = 0
        if len(data) > 5 and data[0] == 0x16:
            offset = 5
        if offset + 4 > len(data) or data[offset] != 0x01:
            return ""
        offset += 4 + 2 + 32
        if offset >= len(data):
            return ""
        sess_id_len = data[offset]
        offset += 1 + sess_id_len
        if offset + 2 > len(data):
            return ""
        cs_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2 + cs_len
        if offset + 1 > len(data):
            return ""
        comp_len = data[offset]
        offset += 1 + comp_len
        if offset + 2 > len(data):
            return ""
        ext_total_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        end_ext = offset + ext_total_len
        while offset + 4 <= min(len(data), end_ext):
            ext_type = int.from_bytes(data[offset : offset + 2], "big")
            ext_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == 0:
                if offset + 5 <= len(data):
                    name_len = int.from_bytes(data[offset + 3 : offset + 5], "big")
                    return data[offset + 5 : offset + 5 + name_len].decode("utf-8", errors="ignore")
            offset += ext_len
    except Exception:
        pass
    return ""


def build_tls_server_hello(session_id: bytes = b"") -> bytes:
    """Constructs valid TLS 1.3 ServerHello response."""
    TLS_VERS = b"\x03\x03"
    srv_random = os.urandom(32)
    sess_id = session_id or os.urandom(32)
    exts = b"\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20" + os.urandom(32)
    srv_hello_body = (
        TLS_VERS
        + srv_random
        + bytes([len(sess_id)]) + sess_id
        + b"\x13\x01\x00"
        + struct.pack("!H", len(exts)) + exts
    )
    handshake = b"\x02" + int.to_bytes(len(srv_hello_body), 3, "big") + srv_hello_body
    rec_sh = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    rec_ccs = b"\x14\x03\x03\x00\x01\x01"
    dummy_app = os.urandom(64)
    rec_app = b"\x17\x03\x03" + struct.pack("!H", len(dummy_app)) + dummy_app
    return rec_sh + rec_ccs + rec_app


async def read_tls_server_hello(reader: asyncio.StreamReader, timeout: float = 10.0) -> None:
    """Reads and validates TLS ServerHello response sequence."""
    hdr = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
    rec_type, v1, v2, rec_len = struct.unpack("!BBBH", hdr)
    if rec_type != 0x16:
        raise ConnectionError(f"Expected TLS ServerHello (0x16), got record type {rec_type:#x}")
    await asyncio.wait_for(reader.readexactly(rec_len), timeout=timeout)

    # Next records: ChangeCipherSpec (0x14) and dummy ApplicationData (0x17)
    try:
        hdr2 = await asyncio.wait_for(reader.readexactly(5), timeout=2.0)
        rec_type2, _, _, rec_len2 = struct.unpack("!BBBH", hdr2)
        if rec_type2 == 0x14:
            await asyncio.wait_for(reader.readexactly(rec_len2), timeout=2.0)
            hdr3 = await asyncio.wait_for(reader.readexactly(5), timeout=2.0)
            rec_type3, _, _, rec_len3 = struct.unpack("!BBBH", hdr3)
            if rec_type3 == 0x17:
                await asyncio.wait_for(reader.readexactly(rec_len3), timeout=2.0)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass


async def perform_tls_client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    domain: str = "google.com",
    timeout: float = 10.0,
) -> tuple[FakeTLSStreamReader, FakeTLSStreamWriter]:
    """Client-side: sends TLS ClientHello with SNI, awaits ServerHello, wraps streams."""
    chello, sess_id = build_tls_client_hello(domain)
    writer.write(chello)
    await writer.drain()

    await read_tls_server_hello(reader, timeout=timeout)
    return FakeTLSStreamReader(reader), FakeTLSStreamWriter(writer)


async def perform_tls_server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    first_bytes: bytes = b"",
    timeout: float = 10.0,
) -> tuple[FakeTLSStreamReader, FakeTLSStreamWriter, str]:
    """Server-side: receives TLS ClientHello, sends ServerHello, wraps streams. Returns (reader, writer, sni_domain)."""
    needed_hdr = 5 - len(first_bytes)
    hdr_rest = await asyncio.wait_for(reader.readexactly(needed_hdr), timeout=timeout) if needed_hdr > 0 else b""
    hdr = first_bytes + hdr_rest
    rec_type, v1, v2, rec_len = struct.unpack("!BBBH", hdr[:5])
    if rec_type != 0x16:
        raise ConnectionError(f"Expected TLS ClientHello (0x16), got record type {rec_type:#x}")

    body = await asyncio.wait_for(reader.readexactly(rec_len), timeout=timeout)
    client_hello_data = hdr + body
    sni_domain = extract_sni_from_client_hello(client_hello_data) or "unknown"

    sess_id = b""
    try:
        if len(body) > 39:
            s_len = body[38]
            sess_id = body[39 : 39 + s_len]
    except Exception:
        sess_id = os.urandom(32)

    srv_hello = build_tls_server_hello(sess_id)
    writer.write(srv_hello)
    await writer.drain()

    return FakeTLSStreamReader(reader), FakeTLSStreamWriter(writer), sni_domain


async def perform_http_connect_tunnel(
    proxy_url: str,
    target_host: str,
    target_port: int,
    timeout: float = 15.0,
    connect_host: Optional[str] = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connects through an HTTP forward proxy (e.g. Squid on PythonAnywhere proxy.server:3128)
    using the HTTP CONNECT method to create a raw TCP tunnel to target_host:target_port.
    """
    cleaned_url = proxy_url.strip()
    if "://" not in cleaned_url:
        cleaned_url = f"http://{cleaned_url}"
    parsed = urllib.parse.urlparse(cleaned_url)

    proxy_host = parsed.hostname or "proxy.server"
    proxy_port = parsed.port or 3128

    dest_host = (connect_host or target_host).strip()

    logger.info(f"Opening HTTP CONNECT tunnel via {proxy_host}:{proxy_port} -> {dest_host}:{target_port}...")
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    req_lines = [
        f"CONNECT {dest_host}:{target_port} HTTP/1.1",
        f"Host: {dest_host}:{target_port}",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Proxy-Connection: Keep-Alive",
    ]
    if parsed.username and parsed.password:
        import base64
        creds = base64.b64encode(f"{parsed.username}:{parsed.password}".encode()).decode()
        req_lines.append(f"Proxy-Authorization: Basic {creds}")
    req_lines.append("\r\n")

    writer.write("\r\n".join(req_lines).encode("utf-8"))
    await writer.drain()

    status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not status_line:
        writer.close()
        raise ConnectionError("Proxy closed connection before sending HTTP response")

    status_str = status_line.decode("utf-8", errors="ignore").strip()
    parts = status_str.split()
    if len(parts) < 2 or parts[1] != "200":
        writer.close()
        raise ConnectionError(f"HTTP Proxy CONNECT tunnel rejected: {status_str}")

    # Consume remaining proxy headers
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line or line in (b"\r\n", b"\n"):
            break

    logger.info(f"[OK] HTTP CONNECT tunnel established through {proxy_host}:{proxy_port}!")
    return reader, writer



# ==============================================================================
import ipaddress


async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 15.0,
    username: Optional[str] = None,
    password: str = "pass",
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )
    try:
        # Step 1: Client Greeting (Offer 0x00 No Auth and 0x02 User/Pass for Tor IsolateSOCKSAuth)
        if username:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await writer.drain()

        # Step 2: Server Method Selection Response
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        ver, selected_method = resp
        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version: {ver:#x}")

        # Step 2b: Sub-negotiation if User/Password chosen (RFC 1929)
        # Enables Tor IsolateSOCKSAuth for guaranteed unique circuits per username!
        if selected_method == 0x02:
            u_bytes = (username or "").encode("utf-8")
            p_bytes = (password or "").encode("utf-8")
            auth_frame = (
                b"\x01"
                + bytes([len(u_bytes)])
                + u_bytes
                + bytes([len(p_bytes)])
                + p_bytes
            )
            writer.write(auth_frame)
            await writer.drain()

            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth_resp[1] != 0x00:
                raise ConnectionError(f"SOCKS5 authentication rejected: {auth_resp.hex()}")
        elif selected_method != 0x00:
            raise ConnectionError(f"SOCKS5 proxy rejected authentication methods: {selected_method:#x}")

        # Step 3: Send CONNECT request
        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version == 4:
                addr_bytes = b"\x01" + ip_obj.packed
            else:
                addr_bytes = b"\x04" + ip_obj.packed
        except ValueError:
            # Domain name -> ATYP 0x03 (remote DNS via Tor exit node!)
            host_b = target_host.encode("idna")
            if len(host_b) > 255:
                raise ValueError(f"Domain name exceeds 255 bytes: {target_host}")
            addr_bytes = b"\x03" + bytes([len(host_b)]) + host_b

        port_bytes = struct.pack("!H", target_port)
        writer.write(b"\x05\x01\x00" + addr_bytes + port_bytes)
        await writer.drain()

        # Step 4: Receive SOCKS5 Server Response
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        ver, rep, rsv, atyp = hdr
        if ver != 0x05:
            raise ConnectionError(f"Invalid SOCKS version in response: {ver:#x}")

        if rep != 0x00:
            error_map = {
                0x01: "General SOCKS server failure",
                0x02: "Connection not allowed by ruleset",
                0x03: "Network unreachable",
                0x04: "Host unreachable",
                0x05: "Connection refused",
                0x06: "TTL expired",
                0x07: "Command not supported",
                0x08: "Address type not supported",
            }
            err_desc = error_map.get(rep, f"Unknown error code {rep}")
            raise ConnectionError(f"Tor SOCKS5 connect failed: {err_desc} (code {rep})")

        # Step 5: Consume BND.ADDR and BND.PORT
        if atyp == 0x01:  # IPv4
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == 0x03:  # Domain
            dlen = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(dlen[0] + 2), timeout=timeout)
        elif atyp == 0x04:  # IPv6
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        else:
            raise ConnectionError(f"Unknown ATYP in SOCKS response: {atyp:#x}")

        return reader, writer
    except Exception:
        await safe_close_writer(writer, timeout=0.5)
        raise
