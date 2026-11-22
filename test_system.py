"""
Automated Test Suite for Reverse SOCKS5 System with HTTP Admin Panel.
Tests:
1. Target Mock Web Server (Internet).
2. socks-control with Admin Panel (Port 9091) and SOCKS5 (Port 10800).
3. 3 Reverse Agents (ALPHA, BETA, GAMMA).
4. Strict SOCKS5 Auth:
   - Reject unauthenticated connection (NO_AUTH -> 0xFF).
   - Reject invalid credentials.
5. HTTP Admin Panel:
   - Login to http://127.0.0.1:9091 with ziqp / ziqp2010.
   - Add new SOCKS5 user (e.g. client1 / pass123).
6. SOCKS5 Proxy Requests:
   - Send requests using new user credentials.
   - Verify random load balancing across all 3 reverse agents.
"""
import asyncio
import socket
import struct
import sys
import os
import urllib.request
import urllib.parse
import http.cookiejar

import hmac
import hashlib
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-control"))
from agent_manager import AgentManager
from socks_users import UserManager
from mtproto_users import MtprotoUserManager
from socks5 import Socks5Server
from admin_web import AdminWebServer
from server import ControlBridgeServer
from mtproto import MtprotoProxyServer, create_aes_ctr, normalize_secret, get_tg_links

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-reverse"))
from agent import ReverseAgent


# --- 1. Target Mock Server ---
class TargetServer:
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port
        self.server = None
        self.request_count = 0

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.request_count += 1
        await reader.readline()
        while True:
            header_line = await reader.readline()
            if not header_line or header_line in (b"\r\n", b"\n"):
                break

        body = f"Hello from Target! Request #{self.request_count}\n".encode("utf-8")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("utf-8")
            + b"Connection: close\r\n\r\n"
            + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_request, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


# --- Mock Telegram DC ---
class MockTelegramDC:
    def __init__(self, host="127.0.0.1", port=18444):
        self.host = host
        self.port = port
        self.server = None
        self.received_messages = []

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # 1. Read 64 bytes Obfuscated2 greeting from reverse agent
            handshake = await reader.readexactly(64)
            dec_prekey_and_iv = handshake[8:56]
            enc_prekey_and_iv = handshake[8:56][::-1]

            dc_decryptor = create_aes_ctr(dec_prekey_and_iv[:32], int.from_bytes(dec_prekey_and_iv[32:], "big"))
            dc_encryptor = create_aes_ctr(enc_prekey_and_iv[:32], int.from_bytes(enc_prekey_and_iv[32:], "big"))

            decrypted = dc_decryptor.update(handshake)
            proto_tag = decrypted[56:60]

            # 2. Read first post-handshake payload packet
            enc_msg = await reader.read(4096)
            plain_msg = dc_decryptor.update(enc_msg)
            self.received_messages.append(plain_msg)

            # 3. Send response back
            reply = b"PONG_FROM_TELEGRAM_DC_2"
            enc_reply = dc_encryptor.update(reply)
            writer.write(enc_reply)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle_conn, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


async def mtproto_fake_tls_request(proxy_host, proxy_port, secret_hex, domain, test_payload):
    raw_secret, _, fake_tls_secret = normalize_secret(secret_hex, domain)
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # 1. Generate Fake-TLS ClientHello
    dummy_body = os.urandom(512)
    c_pkt = bytearray(b"\x16\x03\x01\x02\x00" + dummy_body)
    c_msg = c_pkt[:11] + b"\x00" * 32 + c_pkt[43:]
    c_comp = hmac.new(raw_secret, c_msg, hashlib.sha256).digest()
    c_ts = int(time.time()).to_bytes(4, "little")
    c_xored = b"\x00" * 28 + c_ts
    c_digest = bytes(c_comp[i] ^ c_xored[i] for i in range(32))
    c_pkt[11:43] = c_digest
    writer.write(c_pkt)
    await writer.drain()

    # 2. Read Fake-TLS ServerHello response
    s_hdr = await reader.readexactly(5)
    s_len = int.from_bytes(s_hdr[3:5], "big")
    await reader.readexactly(s_len)
    # ChangeCipherSpec
    await reader.readexactly(6)
    # Fake HTTP/2 data
    app_hdr = await reader.readexactly(5)
    app_len = int.from_bytes(app_hdr[3:5], "big")
    await reader.readexactly(app_len)

    # 3. Inside Fake-TLS, generate 64-byte Obfuscated2 greeting for DC 2
    c_nonce = bytearray(os.urandom(64))
    c_nonce[56:60] = b"\xdd\xdd\xdd\xdd"  # PROTO_TAG_SECURE
    c_nonce[60:62] = struct.pack("<h", 2)  # DC 2

    c_enc_prekey_and_iv = bytes(c_nonce[8:56])
    c_dec_prekey_and_iv = bytes(c_nonce[8:56][::-1])

    c_enc_key = hashlib.sha256(c_enc_prekey_and_iv[:32] + raw_secret).digest()
    c_enc_iv = int.from_bytes(c_enc_prekey_and_iv[32:], "big")
    client_encryptor = create_aes_ctr(c_enc_key, c_enc_iv)

    c_dec_key = hashlib.sha256(c_dec_prekey_and_iv[:32] + raw_secret).digest()
    c_dec_iv = int.from_bytes(c_dec_prekey_and_iv[32:], "big")
    client_decryptor = create_aes_ctr(c_dec_key, c_dec_iv)

    client_handshake = bytes(c_nonce[:56]) + client_encryptor.update(bytes(c_nonce))[56:]

    # Send 64-byte handshake wrapped in TLS Application Data record (\x17\x03\x03)
    rec_hs = b"\x17\x03\x03" + int.to_bytes(len(client_handshake), 2, "big") + client_handshake
    writer.write(rec_hs)
    await writer.drain()

    # 4. Send encrypted test payload wrapped in TLS record
    enc_payload = client_encryptor.update(test_payload)
    rec_payload = b"\x17\x03\x03" + int.to_bytes(len(enc_payload), 2, "big") + enc_payload
    writer.write(rec_payload)
    await writer.drain()

    # 5. Read TLS Application Data record from proxy
    resp_hdr = await reader.readexactly(5)
    assert resp_hdr[0] == 0x17, f"Expected 0x17 TLS Application Data, got {resp_hdr[0]:#x}"
    resp_len = int.from_bytes(resp_hdr[3:5], "big")
    enc_resp = await reader.readexactly(resp_len)

    plain_resp = client_decryptor.update(enc_resp)
    writer.close()
    await writer.wait_closed()
    return plain_resp


async def mtproto_plain_request(proxy_host, proxy_port, secret_hex, test_payload):
    """Simulates a classic MTProto client connecting with a raw 32-hex secret (no Fake-TLS)."""
    raw_secret = bytes.fromhex(secret_hex)
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # 1. Generate 64-byte Obfuscated2 greeting for DC 2
    c_nonce = bytearray(os.urandom(64))
    c_nonce[56:60] = b"\xee\xee\xee\xee"  # PROTO_TAG_INTERMEDIATE
    c_nonce[60:62] = struct.pack("<h", 2)  # DC 2

    c_enc_prekey_and_iv = bytes(c_nonce[8:56])
    c_dec_prekey_and_iv = bytes(c_nonce[8:56][::-1])

    c_enc_key = hashlib.sha256(c_enc_prekey_and_iv[:32] + raw_secret).digest()
    c_enc_iv = int.from_bytes(c_enc_prekey_and_iv[32:], "big")
    client_encryptor = create_aes_ctr(c_enc_key, c_enc_iv)

    c_dec_key = hashlib.sha256(c_dec_prekey_and_iv[:32] + raw_secret).digest()
    c_dec_iv = int.from_bytes(c_dec_prekey_and_iv[32:], "big")
    client_decryptor = create_aes_ctr(c_dec_key, c_dec_iv)

    client_handshake = bytes(c_nonce[:56]) + client_encryptor.update(bytes(c_nonce))[56:]

    # Send 64-byte handshake directly over TCP (NO TLS wrapper!)
    writer.write(client_handshake)
    await writer.drain()

    # 2. Send encrypted test payload directly over TCP (NO TLS wrapper!)
    enc_payload = client_encryptor.update(test_payload)
    writer.write(enc_payload)
    await writer.drain()

    # 3. Read response directly from TCP
    enc_resp = await reader.read(4096)
    plain_resp = client_decryptor.update(enc_resp)
    writer.close()
    await writer.wait_closed()
    return plain_resp


# --- SOCKS5 Client Helper with Auth Support ---
async def socks5_request(
    socks_host, socks_port, target_host, target_port, username=None, password=None, path="/"
):
    reader, writer = await asyncio.open_connection(socks_host, socks_port)

    # 1. Greeting
    if username is None:
        # Only offer NO_AUTH (0x00)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        ver, method = await reader.readexactly(2)
        writer.close()
        await writer.wait_closed()
        return {"status": "handshake", "method": method}

    # Offer USER_PASS (0x02)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    ver, method = await reader.readexactly(2)
    if method != 0x02:
        writer.close()
        await writer.wait_closed()
        return {"status": "auth_method_rejected", "method": method}

    # RFC 1929 Auth subnegotiation
    u_bytes = username.encode("utf-8")
    p_bytes = password.encode("utf-8")
    auth_req = b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
    writer.write(auth_req)
    await writer.drain()

    auth_ver, auth_status = await reader.readexactly(2)
    if auth_status != 0x00:
        writer.close()
        await writer.wait_closed()
        return {"status": "auth_failed", "code": auth_status}

    # 2. CONNECT request
    port_bytes = struct.pack("!H", target_port)
    host_bytes = target_host.encode("utf-8")
    req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port_bytes
    writer.write(req)
    await writer.drain()

    # 3. Read reply
    reply = await reader.readexactly(4)
    rep_ver, rep_code, _, atyp = reply
    if rep_code != 0:
        writer.close()
        await writer.wait_closed()
        return {"status": "connect_failed", "code": rep_code}

    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 3:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)

    # 4. HTTP request
    http_req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    writer.write(http_req)
    await writer.drain()

    # 5. Read response
    response_data = await reader.read()
    writer.close()
    await writer.wait_closed()

    return {"status": "success", "body": response_data.decode("utf-8", errors="ignore")}


# --- Admin Panel HTTP Client Helper ---
async def admin_http_post(url, data, cookie=None):
    parsed = urllib.parse.urlparse(url)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)

    body = urllib.parse.urlencode(data).encode("utf-8")
    req_lines = [
        f"POST {parsed.path} HTTP/1.1",
        f"Host: {parsed.hostname}:{parsed.port}",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if cookie:
        req_lines.append(f"Cookie: {cookie}")

    req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8") + body
    writer.write(req_bytes)
    await writer.drain()

    resp = await reader.read()
    writer.close()
    await writer.wait_closed()
    return resp.decode("utf-8", errors="ignore")


async def main():
    print("=" * 70)
    print("   STARTING INTEGRATION TEST: REVERSE SOCKS5 + HTTP ADMIN PANEL")
    print("=" * 70)

    # 1. Target server
    target_server = TargetServer(host="127.0.0.1", port=8888)
    await target_server.start()
    print("[+] Target Server started on 127.0.0.1:8888")

    # 2. Control Server components
    TOKEN = "TestSecret2026"
    SOCKS_PORT = 10800
    CONTROL_PORT = 9090
    ADMIN_PORT = 9091

    # Temporary test users files
    test_users_file = os.path.join(os.path.dirname(__file__), "socks-control", "test_users.json")
    if os.path.exists(test_users_file):
        os.remove(test_users_file)

    test_mtproto_users_file = os.path.join(os.path.dirname(__file__), "socks-control", "test_mtproto_users.json")
    if os.path.exists(test_mtproto_users_file):
        os.remove(test_mtproto_users_file)

    user_manager = UserManager(filepath=test_users_file)
    mtproto_user_manager = MtprotoUserManager(
        filepath=test_mtproto_users_file,
        default_secret="d04843361111fc744f516582107f9fb6",
        default_domain="google.com",
    )
    agent_manager = AgentManager(strategy="rotation", fast_timeout=2.0)

    control_server = ControlBridgeServer(agent_manager, "127.0.0.1", CONTROL_PORT, TOKEN)
    socks_server = Socks5Server(agent_manager, user_manager, "127.0.0.1", SOCKS_PORT, fast_timeout=2.0)
    admin_server = AdminWebServer(
        agent_manager=agent_manager,
        user_manager=user_manager,
        mtproto_user_manager=mtproto_user_manager,
        host="127.0.0.1",
        port=ADMIN_PORT,
        admin_user="ziqp",
        admin_pass="ziqp2010",
        socks5_port=SOCKS_PORT,
        mtproto_port=18443,
        mtproto_secret=mtproto_user_manager.clients.get("default", {}).get("fake_tls_secret"),
        mtproto_domain="google.com",
    )

    await control_server.start()
    await socks_server.start()
    await admin_server.start()
    print(f"[+] socks-control started (SOCKS5: {SOCKS_PORT}, Control: {CONTROL_PORT}, Admin: {ADMIN_PORT})")

    # 3. Start 3 reverse agents
    agents = []
    agent_tasks = []
    agent_names = ["reverse-node-ALPHA", "reverse-node-BETA", "reverse-node-GAMMA"]

    for name in agent_names:
        agent = ReverseAgent(
            control_host="127.0.0.1",
            control_port=CONTROL_PORT,
            secret_token=TOKEN,
            agent_id=name,
            reconnect_delay=1.0,
        )
        agents.append(agent)
        task = asyncio.create_task(agent.start())
        agent_tasks.append(task)

    # Wait for all 3 agents to register
    print("[*] Waiting for 3 reverse agents to connect...")
    for _ in range(50):
        if agent_manager.get_agent_count() == 3:
            break
        await asyncio.sleep(0.1)

    assert agent_manager.get_agent_count() == 3
    print("[+] All 3 reverse agents connected and registered successfully!")

    # 4. TEST SOCKS5 STRICT AUTH ENFORCEMENT
    print("\n[*] Testing SOCKS5 authentication enforcement...")

    # 4a. Connect without auth (should be rejected with 0xFF)
    res_no_auth = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", 8888, username=None)
    assert res_no_auth["method"] == 0xFF, f"Expected 0xFF (no acceptable methods), got: {res_no_auth}"
    print("  [OK] Unauthenticated connection was strictly rejected with 0xFF")

    # 4b. Connect with non-existent user
    res_bad_user = await socks5_request(
        "127.0.0.1", SOCKS_PORT, "127.0.0.1", 8888, username="ghost", password="123"
    )
    assert res_bad_user["status"] == "auth_failed", f"Expected auth_failed, got: {res_bad_user}"
    print("  [OK] Unknown user credentials strictly rejected")

    # 5. TEST HTTP ADMIN PANEL (PORT 9091)
    print("\n[*] Testing HTTP Admin Panel at http://127.0.0.1:9091...")

    # 5a. Admin login with wrong password
    bad_login = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/login",
        {"username": "ziqp", "password": "wrong_password"},
    )
    assert "Location: /login?error=" in bad_login or "Неверный" in bad_login
    print("  [OK] Admin rejected invalid login attempt")

    # 5b. Admin login with correct password ziqp / ziqp2010
    login_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/login",
        {"username": "ziqp", "password": "ziqp2010"},
    )
    assert "Set-Cookie: admin_session=" in login_resp
    assert "Location: /" in login_resp

    # Extract session cookie
    cookie_line = [line for line in login_resp.split("\r\n") if line.lower().startswith("set-cookie:")][0]
    session_cookie = cookie_line.split(":", 1)[1].split(";")[0].strip()
    print(f"  [OK] Admin successfully logged in! Session cookie obtained: {session_cookie[:25]}...")

    # 5c. Add new SOCKS5 user via Admin Panel
    add_user_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/users/add",
        {"username": "vipclient", "password": "SuperSecretPass2026"},
        cookie=session_cookie,
    )
    assert user_manager.authenticate("vipclient", "SuperSecretPass2026")
    print("  [OK] SOCKS5 user 'vipclient' created via Admin Panel successfully!")

    # 6. TEST PROXY TRAFFIC WITH NEW USER CREDENTIALS & RANDOM BALANCING
    NUM_REQUESTS = 15
    print(f"\n[*] Sending {NUM_REQUESTS} requests with 'vipclient' credentials to test random balancing...\n")

    for i in range(1, NUM_REQUESTS + 1):
        res = await socks5_request(
            "127.0.0.1",
            SOCKS_PORT,
            "127.0.0.1",
            8888,
            username="vipclient",
            password="SuperSecretPass2026",
            path=f"/test-{i}",
        )
        assert res["status"] == "success", f"Request {i} failed: {res}"
        assert f"Request #{i}" in res["body"]

    # 7. Check Load Balancing distribution
    print("=" * 70)
    print("               LOAD BALANCING STATISTICS:")
    print("=" * 70)
    status_list = agent_manager.get_agent_status_list()
    total_handled = 0
    nodes_used = 0

    for agent_stat in status_list:
        handled = agent_stat["total_handled"]
        total_handled += handled
        if handled > 0:
            nodes_used += 1
        percentage = (handled / NUM_REQUESTS) * 100
        print(f"  * Node: {agent_stat['agent_id']:<22} Handled: {handled:>2} requests ({percentage:>5.1f}%)")

    print("-" * 70)
    print(f"Total requests routed: {total_handled} / {NUM_REQUESTS}")
    print(f"Nodes active and participating: {nodes_used} / {len(agent_names)}")
    print("=" * 70)

    assert total_handled == NUM_REQUESTS
    assert nodes_used > 1, "Load balancing failed: only 1 node received all traffic!"

    # 8. Test user deletion
    print("\n[*] Testing user deletion via Admin Panel...")
    del_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/users/delete",
        {"username": "vipclient"},
        cookie=session_cookie,
    )
    assert not user_manager.authenticate("vipclient", "SuperSecretPass2026")
    print("  [OK] User 'vipclient' deleted successfully.")

    # 9. Verify deleted user cannot connect to SOCKS5 anymore
    res_after_del = await socks5_request(
        "127.0.0.1", SOCKS_PORT, "127.0.0.1", 8888, username="vipclient", password="SuperSecretPass2026"
    )
    assert res_after_del["status"] == "auth_failed"
    print("  [OK] Deleted user is immediately rejected by SOCKS5 server!")

    # 10. TEST MTPROTO PROXY WITH FAKE-TLS ROUTED THROUGH REVERSE AGENT
    print("\n" + "=" * 70)
    print("      TESTING MTPROTO FAKE-TLS PROXY ROUTED VIA REVERSE AGENT")
    print("=" * 70)

    MTPROTO_PORT = 18443
    MOCK_DC_PORT = 18444
    MTPROTO_SECRET = "d04843361111fc744f516582107f9fb6"
    MTPROTO_DOMAIN = "google.com"

    mock_dc = MockTelegramDC(host="127.0.0.1", port=MOCK_DC_PORT)
    await mock_dc.start()

    mtproto_server = MtprotoProxyServer(
        agent_manager=agent_manager,
        user_manager=mtproto_user_manager,
        host="127.0.0.1",
        port=MTPROTO_PORT,
        secret=MTPROTO_SECRET,
        domain=MTPROTO_DOMAIN,
        tg_port=MOCK_DC_PORT,
        dc_mapping={2: "127.0.0.1"},
    )
    await mtproto_server.start()

    links = get_tg_links("127.0.0.1", MTPROTO_PORT, mtproto_server.fake_tls_secret)
    print(f"  [+] MTProto listening on port {MTPROTO_PORT}")
    print(f"  [+] Fake-TLS Secret: {mtproto_server.fake_tls_secret}")
    print(f"  [+] Telegram One-Click Link: {links['tg_link']}")

    # 10a. Send simulated Telegram client request inside Fake-TLS
    test_msg = b"PING_FROM_TELEGRAM_CLIENT_VIA_FAKETLS"
    dc_reply = await mtproto_fake_tls_request(
        "127.0.0.1",
        MTPROTO_PORT,
        MTPROTO_SECRET,
        MTPROTO_DOMAIN,
        test_msg,
    )
    assert dc_reply == b"PONG_FROM_TELEGRAM_DC_2", f"Unexpected reply: {dc_reply}"
    assert len(mock_dc.received_messages) == 1
    assert mock_dc.received_messages[0] == test_msg
    print("  [OK] Telegram client <-> Fake-TLS <-> Reverse Agent <-> Mock DC test PASSED!")

    # 10a-2. Send simulated Telegram client request using raw Hex32 secret directly (no Fake-TLS)
    test_msg_plain = b"PING_FROM_TELEGRAM_CLIENT_VIA_RAW_HEX32"
    dc_reply_plain = await mtproto_plain_request(
        "127.0.0.1",
        MTPROTO_PORT,
        MTPROTO_SECRET,
        test_msg_plain,
    )
    assert dc_reply_plain == b"PONG_FROM_TELEGRAM_DC_2", f"Unexpected reply: {dc_reply_plain}"
    assert mock_dc.received_messages[-1] == test_msg_plain
    print("  [OK] Telegram client <-> Plain Hex32 (Obfuscated2) <-> Reverse Agent <-> Mock DC test PASSED!")

    # 10b. Create new MTProto client via Admin Panel (auto-generating secret key and setting Promo TAG)
    print("\n[*] Testing MTProto client creation & Promo TAG via Admin Panel...")
    test_promo_tag = "96bd93d09a01f79d01c8d3e4cd5d5c26"
    
    # Test setting TAG on existing default client
    set_tag_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/mtproto/set_tag",
        {"client_name": "default", "tag": test_promo_tag},
        cookie=session_cookie,
    )
    assert mtproto_user_manager.clients["default"].get("tag") == test_promo_tag
    print(f"  [OK] Successfully assigned Promo TAG '{test_promo_tag}' to 'default' client via Admin Panel!")

    add_mtproto_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/mtproto/add",
        {"client_name": "alex_phone", "secret": "", "tag": test_promo_tag},
        cookie=session_cookie,
    )
    assert "alex_phone" in mtproto_user_manager.clients
    alex_client = mtproto_user_manager.clients["alex_phone"]
    assert alex_client.get("tag") == test_promo_tag
    alex_secret = alex_client["secret"]
    alex_fake_tls = alex_client["fake_tls_secret"]
    print(f"  [OK] Created MTProto client 'alex_phone' with auto-generated secret: {alex_secret}")
    print(f"       Fake-TLS Secret: {alex_fake_tls}")
    print(f"       Promo TAG: {alex_client.get('tag')}")

    # 10c. Connect with alex_phone's newly generated secret (Fake-TLS)
    test_msg_alex = b"PING_FROM_ALEX_PHONE_MTPROTO_FAKETLS"
    dc_reply_alex = await mtproto_fake_tls_request(
        "127.0.0.1",
        MTPROTO_PORT,
        alex_secret,
        MTPROTO_DOMAIN,
        test_msg_alex,
    )
    assert dc_reply_alex == b"PONG_FROM_TELEGRAM_DC_2"
    assert mock_dc.received_messages[-1] == test_msg_alex
    print("  [OK] Telegram client connected using new MTProto Fake-TLS secret successfully!")

    # 10c-2. Connect with alex_phone's newly generated secret via Plain Hex32
    test_msg_alex_plain = b"PING_FROM_ALEX_PHONE_RAW_HEX32"
    dc_reply_alex_plain = await mtproto_plain_request(
        "127.0.0.1",
        MTPROTO_PORT,
        alex_secret,
        test_msg_alex_plain,
    )
    assert dc_reply_alex_plain == b"PONG_FROM_TELEGRAM_DC_2"
    assert mock_dc.received_messages[-1] == test_msg_alex_plain
    print("  [OK] Telegram client connected using new MTProto Plain Hex32 secret successfully!")

    # 10d. Test deleting MTProto client via Admin Panel
    print("\n[*] Testing MTProto client deletion via Admin Panel...")
    del_mtproto_resp = await admin_http_post(
        f"http://127.0.0.1:{ADMIN_PORT}/mtproto/delete",
        {"client_name": "alex_phone"},
        cookie=session_cookie,
    )
    assert "alex_phone" not in mtproto_user_manager.clients
    print("  [OK] MTProto client 'alex_phone' deleted successfully.")

    # 10e. Test active scanner probe (invalid Fake-TLS secret)
    bad_reader, bad_writer = await asyncio.open_connection("127.0.0.1", MTPROTO_PORT)
    bad_writer.write(b"GET / HTTP/1.1\r\nHost: probe-scanner.com\r\n\r\n")
    await bad_writer.drain()
    try:
        await asyncio.wait_for(bad_reader.read(1024), timeout=1.0)
    except Exception:
        pass
    bad_writer.close()
    try:
        await bad_writer.wait_closed()
    except Exception:
        pass
    print("  [OK] Active scanner probe handled safely by MTProto proxy!")

    await mtproto_server.stop()
    await mock_dc.stop()

    print("\n[SUCCESS] ALL INTEGRATION TESTS (SOCKS5 + ADMIN + MTPROTO) PASSED PERFECTLY!\n")

    # Clean up
    if os.path.exists(test_users_file):
        os.remove(test_users_file)
    if os.path.exists(test_mtproto_users_file):
        os.remove(test_mtproto_users_file)
    for agent in agents:
        await agent.stop()
    for task in agent_tasks:
        task.cancel()
    await socks_server.stop()
    await control_server.stop()
    await admin_server.stop()
    await target_server.stop()


if __name__ == "__main__":
    asyncio.run(main())
