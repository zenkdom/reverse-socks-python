"""
Comprehensive Integration Tests for Universal Multi-Protocol Proxy.
Tests:
1. SOCKS5 UDP ASSOCIATE (UDP Datagram relaying to Internet targets via Reverse Agent)
2. SOCKS5 TCP CONNECT (Standard TCP tunnel via Reverse Agent)
3. SOCKS5 TCP BIND (Incoming TCP binding per RFC 1928)
4. SOCKS4 TCP CONNECT (Legacy SOCKS4 protocol)
5. SOCKS4a Domain Name CONNECT (SOCKS4a domain resolution)
6. HTTP CONNECT (HTTPS tunneling through proxy with Basic Auth)
7. HTTP GET Forward Proxy (Standard HTTP proxy with Basic Auth)
8. Strict Authentication enforcement on all protocols
9. Local Direct UDP Fallback (when zero reverse agents are connected)
"""
import sys
import os
import asyncio
import socket
import struct
import base64
import time

# Guarantee socks-control and socks-reverse can be imported
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "socks-control"))
sys.path.insert(0, os.path.join(BASE_DIR, "socks-reverse"))

from agent_manager import AgentManager
from socks_users import UserManager
from socks5 import Socks5Server
from server import ControlBridgeServer
from agent import ReverseAgent
from protocol import (
    pack_socks5_udp_packet,
    parse_socks5_udp_packet,
    safe_close_writer,
)

TEST_CONTROL_PORT = 29090
TEST_PROXY_PORT = 21080
TEST_TARGET_TCP_PORT = 28888
TEST_TARGET_UDP_PORT = 28889
TEST_TOKEN = "ProtocolSecretToken2026!"
TEST_USER = "testuser"
TEST_PASS = "testpass"


class MockUdpEchoServer(asyncio.DatagramProtocol):
    """Echoes received UDP datagrams back with ECHO_UDP: prefix."""

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        reply = b"ECHO_UDP:" + data
        self.transport.sendto(reply, addr)


async def start_mock_servers():
    """Start mock TCP and UDP target servers."""
    loop = asyncio.get_running_loop()

    # Target UDP Echo Server
    udp_transport, _ = await loop.create_datagram_endpoint(
        MockUdpEchoServer,
        local_addr=("127.0.0.1", TEST_TARGET_UDP_PORT),
    )

    # Target TCP Echo Server
    async def handle_tcp(r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            while True:
                line = await r.readline()
                if not line:
                    break
                if line.startswith(b"GET ") or line.startswith(b"POST "):
                    # HTTP response
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: 17\r\n"
                        b"Connection: close\r\n\r\n"
                        b"HTTP_TARGET_HELLO"
                    )
                    w.write(resp)
                    await w.drain()
                    break
                w.write(b"ECHO_TCP:" + line)
                await w.drain()
        except Exception:
            pass
        finally:
            await safe_close_writer(w)

    tcp_server = await asyncio.start_server(handle_tcp, host="127.0.0.1", port=TEST_TARGET_TCP_PORT)
    return udp_transport, tcp_server


async def main():
    print("=" * 70)
    print("   UNIVERSAL MULTI-PROTOCOL PROXY COMPREHENSIVE TEST SUITE")
    print("=" * 70)

    # 1. Start mock internet targets
    udp_target_transport, tcp_target_server = await start_mock_servers()
    print(f"[+] Mock UDP target listening on 127.0.0.1:{TEST_TARGET_UDP_PORT}")
    print(f"[+] Mock TCP target listening on 127.0.0.1:{TEST_TARGET_TCP_PORT}")

    # 2. Setup user database
    users_file = os.path.join(BASE_DIR, "socks-control", "test_protocols_users.json")
    if os.path.exists(users_file):
        os.remove(users_file)
    user_manager = UserManager(filepath=users_file)
    await user_manager.add_user(TEST_USER, TEST_PASS)

    # 3. Setup control bridge and universal proxy server
    agent_manager = AgentManager(strategy="rotation", fast_timeout=2.0)
    control_server = ControlBridgeServer(
        agent_manager=agent_manager,
        host="127.0.0.1",
        port=TEST_CONTROL_PORT,
        secret_token=TEST_TOKEN,
    )
    await control_server.start()

    proxy_server = Socks5Server(
        agent_manager=agent_manager,
        user_manager=user_manager,
        host="127.0.0.1",
        port=TEST_PROXY_PORT,
    )
    await proxy_server.start()

    # 4. Start Reverse Agent
    agent = ReverseAgent(
        control_host="127.0.0.1",
        control_port=TEST_CONTROL_PORT,
        secret_token=TEST_TOKEN,
        agent_id="test-reverse-agent-1",
    )
    agent_task = asyncio.create_task(agent.start())

    # Wait for reverse agent to connect
    for _ in range(50):
        if agent_manager.get_agent_count() > 0:
            break
        await asyncio.sleep(0.1)
    assert agent_manager.get_agent_count() == 1, "Reverse agent failed to register"
    print(f"[+] Reverse Agent connected and registered successfully!")

    loop = asyncio.get_running_loop()

    try:
        # ======================================================================
        # TEST 1: SOCKS5 UDP ASSOCIATE (UDP Datagram relaying via Reverse Agent)
        # ======================================================================
        print("\n[*] TEST 1: SOCKS5 UDP ASSOCIATE (UDP Datagram Relaying)...")

        # 1. Connect TCP to proxy
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)

        # 2. Handshake: offer User/Pass (0x02)
        pr_w.write(b"\x05\x01\x02")
        await pr_w.drain()
        auth_resp = await pr_r.readexactly(2)
        assert auth_resp == b"\x05\x02", f"Unexpected auth selection: {auth_resp}"

        # 3. Authenticate
        u_b = TEST_USER.encode()
        p_b = TEST_PASS.encode()
        pr_w.write(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
        await pr_w.drain()
        auth_status = await pr_r.readexactly(2)
        assert auth_status == b"\x01\x00", f"Authentication failed: {auth_status}"

        # 4. Send UDP ASSOCIATE request: CMD 0x03, 0.0.0.0:0
        pr_w.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        await pr_w.drain()

        # 5. Read reply with BND.ADDR and BND.PORT
        reply_hdr = await pr_r.readexactly(4)
        ver, rep, rsv, atyp = reply_hdr
        assert ver == 0x05 and rep == 0x00, f"UDP ASSOCIATE request rejected: {rep}"
        assert atyp == 0x01, f"Expected IPv4 address type, got {atyp}"
        bnd_ip_b = await pr_r.readexactly(4)
        bnd_port_b = await pr_r.readexactly(2)
        relay_ip = socket.inet_ntoa(bnd_ip_b)
        relay_port = struct.unpack("!H", bnd_port_b)[0]
        print(f"  [+] Proxy allocated UDP relay endpoint: {relay_ip}:{relay_port}")

        # 6. Send UDP datagram to relay endpoint
        client_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_udp_sock.bind(("127.0.0.1", 0))
        client_udp_sock.setblocking(False)

        # Datagram payload directed to mock UDP target (127.0.0.1:TEST_TARGET_UDP_PORT)
        test_payload = b"HELLO_UDP_WORLD_2026"
        udp_packet = pack_socks5_udp_packet("127.0.0.1", TEST_TARGET_UDP_PORT, test_payload)

        # Send to relay
        client_udp_sock.sendto(udp_packet, (relay_ip, relay_port))

        # 7. Receive reply from relay
        received_data = None
        for _ in range(30):
            try:
                data, from_addr = client_udp_sock.recvfrom(65535)
                received_data = data
                break
            except BlockingIOError:
                await asyncio.sleep(0.1)

        assert received_data is not None, "Did not receive UDP reply from relay within 3s"

        # Parse SOCKS5 UDP header in reply
        src_host, src_port, payload_data, _ = parse_socks5_udp_packet(received_data)
        assert src_host == "127.0.0.1", f"Unexpected source host: {src_host}"
        assert src_port == TEST_TARGET_UDP_PORT, f"Unexpected source port: {src_port}"
        assert payload_data == b"ECHO_UDP:" + test_payload, f"Unexpected reply payload: {payload_data}"

        print(f"  [OK] UDP Datagram successfully routed through Reverse Agent to target!")
        print(f"  [OK] Target received payload and echoed: {payload_data.decode()}")

        # Close client sockets
        client_udp_sock.close()
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 2: SOCKS5 TCP CONNECT
        # ======================================================================
        print("\n[*] TEST 2: SOCKS5 TCP CONNECT (Standard TCP Tunneling)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)
        pr_w.write(b"\x05\x01\x02")
        await pr_w.drain()
        await pr_r.readexactly(2)
        pr_w.write(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
        await pr_w.drain()
        await pr_r.readexactly(2)

        # CONNECT 127.0.0.1:TEST_TARGET_TCP_PORT
        target_ip_b = socket.inet_aton("127.0.0.1")
        target_port_b = struct.pack("!H", TEST_TARGET_TCP_PORT)
        pr_w.write(b"\x05\x01\x00\x01" + target_ip_b + target_port_b)
        await pr_w.drain()

        resp_hdr = await pr_r.readexactly(4)
        assert resp_hdr[1] == 0x00, f"CONNECT failed: {resp_hdr[1]}"
        await pr_r.readexactly(6)  # consume BND addr & port

        pr_w.write(b"PING_TCP_MESSAGE\n")
        await pr_w.drain()
        tcp_echo = await pr_r.readline()
        assert tcp_echo == b"ECHO_TCP:PING_TCP_MESSAGE\n", f"Unexpected TCP reply: {tcp_echo}"
        print(f"  [OK] TCP CONNECT stream routed and echoed: {tcp_echo.decode().strip()}")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 3: SOCKS5 TCP BIND (Incoming TCP Connection)
        # ======================================================================
        print("\n[*] TEST 3: SOCKS5 TCP BIND (RFC 1928 Command 0x02)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)
        pr_w.write(b"\x05\x01\x02")
        await pr_w.drain()
        await pr_r.readexactly(2)
        pr_w.write(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
        await pr_w.drain()
        await pr_r.readexactly(2)

        # Send BIND request (0x02)
        pr_w.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        await pr_w.drain()

        # First reply: proxy listening port
        reply1 = await pr_r.readexactly(10)
        assert reply1[1] == 0x00, f"BIND request rejected: {reply1[1]}"
        bind_port = struct.unpack("!H", reply1[8:10])[0]
        print(f"  [+] BIND listener bound on port: {bind_port}")

        # Connect an external peer to the bound port
        peer_r, peer_w = await asyncio.open_connection("127.0.0.1", bind_port)

        # Second reply: peer connected
        reply2 = await pr_r.readexactly(10)
        assert reply2[1] == 0x00, f"BIND second reply failed: {reply2[1]}"

        # Test data flow between client and incoming peer
        pr_w.write(b"MSG_FROM_CLIENT_TO_PEER\n")
        await pr_w.drain()
        msg_at_peer = await peer_r.readline()
        assert msg_at_peer == b"MSG_FROM_CLIENT_TO_PEER\n"

        peer_w.write(b"MSG_FROM_PEER_TO_CLIENT\n")
        await peer_w.drain()
        msg_at_client = await pr_r.readline()
        assert msg_at_client == b"MSG_FROM_PEER_TO_CLIENT\n"

        print(f"  [OK] SOCKS5 BIND bi-directional data transfer PASSED!")
        await safe_close_writer(peer_w)
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 4: SOCKS4 TCP CONNECT
        # ======================================================================
        print("\n[*] TEST 4: SOCKS4 TCP CONNECT (Legacy Protocol)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)

        # SOCKS4 packet: VN=0x04, CD=0x01 (CONNECT), PORT, IP, USERID + NULL
        s4_req = (
            b"\x04\x01"
            + struct.pack("!H", TEST_TARGET_TCP_PORT)
            + socket.inet_aton("127.0.0.1")
            + TEST_USER.encode()
            + b"\x00"
        )
        pr_w.write(s4_req)
        await pr_w.drain()

        # SOCKS4 reply: 8 bytes, CD=0x5A (90 = granted)
        s4_rep = await pr_r.readexactly(8)
        assert s4_rep[1] == 0x5A, f"SOCKS4 request rejected: {s4_rep[1]:#x}"

        pr_w.write(b"HELLO_SOCKS4\n")
        await pr_w.drain()
        s4_echo = await pr_r.readline()
        assert s4_echo == b"ECHO_TCP:HELLO_SOCKS4\n", f"Unexpected SOCKS4 reply: {s4_echo}"
        print(f"  [OK] SOCKS4 request granted (0x5A) and data echoed: {s4_echo.decode().strip()}")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 5: SOCKS4a DOMAIN NAME CONNECT
        # ======================================================================
        print("\n[*] TEST 5: SOCKS4a (Domain Name Resolution)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)

        # SOCKS4a packet: IP=0.0.0.1, followed by USERID\x00 and DOMAIN\x00
        s4a_req = (
            b"\x04\x01"
            + struct.pack("!H", TEST_TARGET_TCP_PORT)
            + b"\x00\x00\x00\x01"
            + TEST_USER.encode()
            + b"\x00"
            + b"localhost\x00"
        )
        pr_w.write(s4a_req)
        await pr_w.drain()

        s4a_rep = await pr_r.readexactly(8)
        assert s4a_rep[1] == 0x5A, f"SOCKS4a request rejected: {s4a_rep[1]:#x}"

        pr_w.write(b"HELLO_SOCKS4A\n")
        await pr_w.drain()
        s4a_echo = await pr_r.readline()
        assert s4a_echo == b"ECHO_TCP:HELLO_SOCKS4A\n", f"Unexpected SOCKS4a reply: {s4a_echo}"
        print(f"  [OK] SOCKS4a domain resolution to 'localhost' succeeded and echoed!")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 6: HTTP CONNECT (HTTPS Tunneling)
        # ======================================================================
        print("\n[*] TEST 6: HTTP CONNECT (HTTPS Proxy Tunneling with Basic Auth)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)

        # Credentials header
        creds_b64 = base64.b64encode(f"{TEST_USER}:{TEST_PASS}".encode()).decode()
        connect_req = (
            f"CONNECT 127.0.0.1:{TEST_TARGET_TCP_PORT} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{TEST_TARGET_TCP_PORT}\r\n"
            f"Proxy-Authorization: Basic {creds_b64}\r\n"
            f"\r\n"
        ).encode()

        pr_w.write(connect_req)
        await pr_w.drain()

        # Should receive HTTP/1.1 200 Connection Established
        http_status_line = await pr_r.readline()
        assert b"200 Connection Established" in http_status_line, f"HTTP CONNECT failed: {http_status_line}"
        await pr_r.readline()  # empty line after headers

        # Send data through established HTTPS tunnel
        pr_w.write(b"HELLO_HTTP_CONNECT_TUNNEL\n")
        await pr_w.drain()
        tunnel_echo = await pr_r.readline()
        assert tunnel_echo == b"ECHO_TCP:HELLO_HTTP_CONNECT_TUNNEL\n"
        print(f"  [OK] HTTP CONNECT 200 Connection Established! Data tunneled successfully.")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 7: HTTP GET FORWARD PROXY
        # ======================================================================
        print("\n[*] TEST 7: HTTP GET Forward Proxy (Standard HTTP Proxying)...")
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)

        get_req = (
            f"GET http://127.0.0.1:{TEST_TARGET_TCP_PORT}/index.html HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{TEST_TARGET_TCP_PORT}\r\n"
            f"Proxy-Authorization: Basic {creds_b64}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        pr_w.write(get_req)
        await pr_w.drain()

        # Read response from target server through proxy
        http_body = await pr_r.read(4096)
        assert b"HTTP_TARGET_HELLO" in http_body, f"HTTP GET forward failed: {http_body}"
        print(f"  [OK] HTTP GET forward proxy returned target page successfully!")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 8: AUTHENTICATION ENFORCEMENT ACROSS PROTOCOLS
        # ======================================================================
        print("\n[*] TEST 8: Strict Authentication Enforcement on All Protocols...")

        # A. HTTP proxy without auth -> 407 Proxy Authentication Required
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)
        pr_w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await pr_w.drain()
        auth_req_resp = await pr_r.readline()
        assert b"407 Proxy Authentication Required" in auth_req_resp, f"Expected 407, got: {auth_req_resp}"
        print("  [OK] Unauthenticated HTTP proxy request rejected with 407!")
        await safe_close_writer(pr_w)

        # B. SOCKS4 with invalid user -> 0x5B rejected
        pr_r, pr_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)
        bad_s4 = b"\x04\x01\x00\x50\x7f\x00\x00\x01eviluser\x00"
        pr_w.write(bad_s4)
        await pr_w.drain()
        s4_bad_rep = await pr_r.readexactly(8)
        assert s4_bad_rep[1] == 0x5B, f"Expected 0x5B (rejected), got {s4_bad_rep[1]:#x}"
        print("  [OK] Unauthorized SOCKS4 request strictly rejected with 0x5B!")
        await safe_close_writer(pr_w)

        # ======================================================================
        # TEST 9: SOCKS5 UDP DIRECT FALLBACK (When 0 reverse agents connected)
        # ======================================================================
        print("\n[*] TEST 9: SOCKS5 UDP Direct Fallback (Standalone / 0 agents)...")
        # Disconnect reverse agent
        await agent.stop()
        agent_task.cancel()
        for _ in range(20):
            if agent_manager.get_agent_count() == 0:
                break
            await asyncio.sleep(0.05)
        assert agent_manager.get_agent_count() == 0

        # Initiate UDP associate with zero agents
        fb_r, fb_w = await asyncio.open_connection("127.0.0.1", TEST_PROXY_PORT)
        fb_w.write(b"\x05\x01\x02")
        await fb_w.drain()
        await fb_r.readexactly(2)
        fb_w.write(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
        await fb_w.drain()
        await fb_r.readexactly(2)

        # Send UDP ASSOCIATE request
        fb_w.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        await fb_w.drain()

        fb_hdr = await fb_r.readexactly(4)
        assert fb_hdr[1] == 0x00, "Direct fallback UDP associate rejected"
        fb_bnd_ip = socket.inet_ntoa(await fb_r.readexactly(4))
        fb_bnd_port = struct.unpack("!H", await fb_r.readexactly(2))[0]

        # Send UDP datagram to fallback relay
        fb_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fb_sock.bind(("127.0.0.1", 0))
        fb_sock.setblocking(False)

        fb_payload = b"FALLBACK_DIRECT_UDP_TEST"
        fb_pkt = pack_socks5_udp_packet("127.0.0.1", TEST_TARGET_UDP_PORT, fb_payload)
        fb_sock.sendto(fb_pkt, (fb_bnd_ip, fb_bnd_port))

        fb_recv = None
        for _ in range(30):
            try:
                data, _ = fb_sock.recvfrom(65535)
                fb_recv = data
                break
            except BlockingIOError:
                await asyncio.sleep(0.1)

        assert fb_recv is not None, "Did not receive fallback UDP reply"
        _, _, fb_echo_data, _ = parse_socks5_udp_packet(fb_recv)
        assert fb_echo_data == b"ECHO_UDP:" + fb_payload
        print(f"  [OK] UDP Direct Fallback relay functional without reverse agents!")
        fb_sock.close()
        await safe_close_writer(fb_w)

        print("\n" + "=" * 70)
        print("   [SUCCESS] ALL MULTI-PROTOCOL TESTS PASSED 100%!")
        print("   - SOCKS5 TCP: PASSED")
        print("   - SOCKS5 UDP (UDP ASSOCIATE): PASSED")
        print("   - SOCKS5 BIND: PASSED")
        print("   - SOCKS4: PASSED")
        print("   - SOCKS4a: PASSED")
        print("   - HTTP CONNECT (HTTPS): PASSED")
        print("   - HTTP FORWARD PROXY: PASSED")
        print("=" * 70)

    finally:
        # Cleanup
        udp_target_transport.close()
        tcp_target_server.close()
        await agent.stop()
        agent_task.cancel()
        await proxy_server.stop()
        await control_server.stop()
        if os.path.exists(users_file):
            try:
                os.remove(users_file)
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
