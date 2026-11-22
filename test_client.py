"""
Interactive Universal Test Client for Multi-Protocol Reverse Proxy.
Supports:
- SOCKS5 TCP (default)
- SOCKS5 UDP (UDP ASSOCIATE via DNS query or custom target)
- SOCKS4 / SOCKS4a (TCP)
- HTTP / HTTPS Proxy (HTTP GET & HTTP CONNECT tunneling)
"""
import asyncio
import struct
import socket
import argparse
import base64
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "socks-control"))
from protocol import pack_socks5_udp_packet, parse_socks5_udp_packet, safe_close_writer


def build_dns_query(domain: str) -> bytes:
    """Build a standard DNS A-record query packet."""
    tx_id = b"\xaa\xbb"
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for part in domain.split("."):
        if part:
            qname += bytes([len(part)]) + part.encode("utf-8")
    qname += b"\x00"
    qtype_class = b"\x00\x01\x00\x01"
    return tx_id + flags + counts + qname + qtype_class


async def socks5_http_get(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    username: str,
    password: str,
    path: str = "/",
) -> str:
    """Connect to target through SOCKS5 TCP proxy with authentication and send HTTP GET."""
    reader, writer = await asyncio.open_connection(socks_host, socks_port)

    # 1. SOCKS5 Greeting (User/Pass Auth method 0x02)
    writer.write(b"\x05\x01\x02")
    await writer.drain()

    ver, method = await reader.readexactly(2)
    if ver != 5 or method != 2:
        await safe_close_writer(writer)
        raise ConnectionError(f"SOCKS5 auth negotiation failed: ver={ver}, method={method}")

    # RFC 1929 subnegotiation
    u_bytes = username.encode("utf-8")
    p_bytes = password.encode("utf-8")
    auth_req = b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
    writer.write(auth_req)
    await writer.drain()

    auth_ver, auth_status = await reader.readexactly(2)
    if auth_status != 0:
        await safe_close_writer(writer)
        raise PermissionError(f"SOCKS5 authentication failed for user '{username}' (code: {auth_status})")

    # 2. SOCKS5 CONNECT (Domain name)
    host_bytes = target_host.encode("utf-8")
    port_bytes = struct.pack("!H", target_port)
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port_bytes
    writer.write(req)
    await writer.drain()

    # 3. Read Reply
    reply = await reader.readexactly(4)
    rep_ver, rep_code, _, atyp = reply
    if rep_code != 0:
        await safe_close_writer(writer)
        raise ConnectionError(f"SOCKS5 connect rejected with status code: {rep_code}")

    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 3:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)

    # 4. HTTP GET Request
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"User-Agent: curl/7.88.1\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    writer.write(request)
    await writer.drain()

    # 5. Read response
    response_data = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        response_data += chunk

    await safe_close_writer(writer)

    text = response_data.decode("utf-8", errors="ignore")
    parts = text.split("\r\n\r\n", 1)
    body = parts[1].strip() if len(parts) > 1 else text.strip()
    return body


async def socks5_udp_test(
    socks_host: str,
    socks_port: int,
    username: str,
    password: str,
    target_host: str = "8.8.8.8",
    target_port: int = 53,
) -> str:
    """Test SOCKS5 UDP ASSOCIATE by querying DNS or sending UDP datagram."""
    reader, writer = await asyncio.open_connection(socks_host, socks_port)

    # 1. Handshake & Auth
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    await reader.readexactly(2)

    u_bytes = username.encode("utf-8")
    p_bytes = password.encode("utf-8")
    writer.write(b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
    await writer.drain()
    auth_status = await reader.readexactly(2)
    if auth_status[1] != 0:
        await safe_close_writer(writer)
        raise PermissionError(f"Authentication failed: {auth_status[1]}")

    # 2. UDP ASSOCIATE Request
    writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()

    reply = await reader.readexactly(4)
    if reply[1] != 0:
        await safe_close_writer(writer)
        raise ConnectionError(f"UDP ASSOCIATE rejected with code: {reply[1]}")

    atyp = reply[3]
    if atyp == 1:
        ip_bytes = await reader.readexactly(4)
        relay_host = socket.inet_ntoa(ip_bytes)
    elif atyp == 3:
        dlen = (await reader.readexactly(1))[0]
        relay_host = (await reader.readexactly(dlen)).decode("utf-8")
    else:
        relay_host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))

    relay_port = struct.unpack("!H", await reader.readexactly(2))[0]
    if relay_host in ("0.0.0.0", "127.0.0.1"):
        relay_host = socks_host

    # 3. Create UDP socket & send DNS query to 8.8.8.8:53
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", 0))
    udp_sock.setblocking(False)

    dns_payload = build_dns_query("api.ipify.org")
    pkt = pack_socks5_udp_packet(target_host, target_port, dns_payload)
    udp_sock.sendto(pkt, (relay_host, relay_port))

    # 4. Wait for response
    recv_pkt = None
    for _ in range(30):
        try:
            recv_pkt, _ = udp_sock.recvfrom(65535)
            break
        except BlockingIOError:
            await asyncio.sleep(0.1)

    udp_sock.close()
    await safe_close_writer(writer)

    if not recv_pkt:
        raise TimeoutError("No UDP response received from relay")

    src_host, src_port, data, _ = parse_socks5_udp_packet(recv_pkt)
    return f"UDP SUCCESS from {src_host}:{src_port} ({len(data)} bytes received)"


async def socks4_http_get(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    username: str,
    path: str = "/",
    use_socks4a: bool = False,
) -> str:
    """Connect through SOCKS4 / SOCKS4a."""
    reader, writer = await asyncio.open_connection(socks_host, socks_port)

    port_b = struct.pack("!H", target_port)
    u_b = username.encode()

    if use_socks4a:
        # SOCKS4a
        req = b"\x04\x01" + port_b + b"\x00\x00\x00\x01" + u_b + b"\x00" + target_host.encode() + b"\x00"
    else:
        # SOCKS4
        target_ip = socket.gethostbyname(target_host)
        req = b"\x04\x01" + port_b + socket.inet_aton(target_ip) + u_b + b"\x00"

    writer.write(req)
    await writer.drain()

    rep = await reader.readexactly(8)
    if rep[1] != 0x5A:
        await safe_close_writer(writer)
        raise ConnectionError(f"SOCKS4 request rejected (code {rep[1]:#x})")

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"User-Agent: curl/7.88.1\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    writer.write(request)
    await writer.drain()

    response_data = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        response_data += chunk

    await safe_close_writer(writer)
    text = response_data.decode("utf-8", errors="ignore")
    parts = text.split("\r\n\r\n", 1)
    return parts[1].strip() if len(parts) > 1 else text.strip()


async def http_proxy_get(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: str,
    password: str,
    path: str = "/",
    connect_mode: bool = False,
) -> str:
    """Connect through HTTP proxy (GET or CONNECT tunnel)."""
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()

    if connect_mode:
        req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Authorization: Basic {creds}\r\n\r\n"
        ).encode()
        writer.write(req)
        await writer.drain()

        status_line = await reader.readline()
        if b"200" not in status_line:
            await safe_close_writer(writer)
            raise ConnectionError(f"HTTP CONNECT failed: {status_line.decode().strip()}")
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break

        # Send raw request inside tunnel
        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(http_req)
        await writer.drain()
    else:
        req = (
            f"GET http://{target_host}:{target_port}{path} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Authorization: Basic {creds}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(req)
        await writer.drain()

    response_data = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        response_data += chunk

    await safe_close_writer(writer)
    text = response_data.decode("utf-8", errors="ignore")
    parts = text.split("\r\n\r\n", 1)
    return parts[1].strip() if len(parts) > 1 else text.strip()


async def main():
    parser = argparse.ArgumentParser(description="Multi-Protocol Test Client for Reverse SOCKS")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy host (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=1080, help="Proxy port (default: 1080)")
    parser.add_argument(
        "--protocol",
        choices=["socks5", "socks5-udp", "socks4", "socks4a", "http", "http-connect"],
        default="socks5",
        help="Proxy protocol to test (default: socks5)",
    )
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", default="pass", help="Password")
    parser.add_argument("--target-host", default="api.ipify.org", help="Target host")
    parser.add_argument("--target-port", type=int, default=80, help="Target port")
    parser.add_argument("--count", type=int, default=3, help="Number of test requests to send")
    args = parser.parse_args()

    print("=" * 65)
    print(f"  Testing Multi-Protocol Proxy at {args.proxy_host}:{args.proxy_port}")
    print(f"  Protocol: {args.protocol.upper()}")
    print(f"  User: {args.username}")
    print(f"  Target: {args.target_host}:{args.target_port}")
    print(f"  Sending {args.count} request(s)...")
    print("=" * 65)

    ip_counter = {}

    for i in range(1, args.count + 1):
        try:
            print(f"[{i}/{args.count}] Sending request...", end="", flush=True)
            if args.protocol == "socks5":
                result = await socks5_http_get(
                    args.proxy_host, args.proxy_port, args.target_host, args.target_port, args.username, args.password
                )
            elif args.protocol == "socks5-udp":
                result = await socks5_udp_test(
                    args.proxy_host, args.proxy_port, args.username, args.password
                )
            elif args.protocol == "socks4":
                result = await socks4_http_get(
                    args.proxy_host, args.proxy_port, args.target_host, args.target_port, args.username, use_socks4a=False
                )
            elif args.protocol == "socks4a":
                result = await socks4_http_get(
                    args.proxy_host, args.proxy_port, args.target_host, args.target_port, args.username, use_socks4a=True
                )
            elif args.protocol == "http":
                result = await http_proxy_get(
                    args.proxy_host, args.proxy_port, args.target_host, args.target_port, args.username, args.password, connect_mode=False
                )
            elif args.protocol == "http-connect":
                result = await http_proxy_get(
                    args.proxy_host, args.proxy_port, args.target_host, args.target_port, args.username, args.password, connect_mode=True
                )
            print(f" -> Result: {result}")
            ip_counter[result] = ip_counter.get(result, 0) + 1
        except Exception as e:
            print(f" -> Error: {e}")
        await asyncio.sleep(0.3)

    print("\n" + "=" * 65)
    print("  Results Summary:")
    for res, count in ip_counter.items():
        percentage = (count / args.count) * 100
        print(f"    {res:<35} Count: {count:>2} ({percentage:>5.1f}%)")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
