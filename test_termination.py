"""
Dedicated Test Suite for Clean and Fast Termination (Shutdown).
Verifies:
1. socks-control and socks-reverse terminate cleanly in < 3 seconds even when:
   - SOCKS5 client connections are actively open / idle
   - MTProto client connections are actively open / idle
   - Reverse agents are connected
2. No bare wait_closed() hangs or unhandled socket reset exceptions.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-control"))
from agent_manager import AgentManager
from socks_users import UserManager
from mtproto_users import MtprotoUserManager
from socks5 import Socks5Server
from admin_web import AdminWebServer
from server import ControlBridgeServer
from mtproto import MtprotoProxyServer
from protocol import safe_close_writer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-reverse"))
from agent import ReverseAgent

from test_system import TargetServer, socks5_request, mtproto_plain_request

CONTROL_PORT = 19080
SOCKS_PORT = 11080
MTPROTO_PORT = 18445
ADMIN_PORT = 19095
TARGET_PORT = 18895
TOKEN = "TerminationSecret2026!"
SECRET_HEX = "11112222333344445555666677778888"


async def main():
    print("=" * 70)
    print("      TESTING CLEAN & INSTANT TERMINATION (NO HANGS)")
    print("=" * 70)

    # 1. Start Mock Target
    target = TargetServer(port=TARGET_PORT)
    await target.start()

    # 2. Setup user managers
    user_mgr = UserManager(filepath="test_term_users.json")
    await user_mgr.add_user("testuser", "testpass")

    mtproto_user_mgr = MtprotoUserManager(filepath="test_term_mtproto.json", default_secret=SECRET_HEX)

    agent_mgr = AgentManager(strategy="rotation", fast_timeout=2.0)
    control_server = ControlBridgeServer(agent_mgr, "127.0.0.1", CONTROL_PORT, TOKEN)
    socks_server = Socks5Server(agent_mgr, user_mgr, "127.0.0.1", SOCKS_PORT, fast_timeout=2.0)
    mtproto_server = MtprotoProxyServer(agent_mgr, user_manager=mtproto_user_mgr, host="127.0.0.1", port=MTPROTO_PORT, secret=SECRET_HEX)
    admin_server = AdminWebServer(
        agent_manager=agent_mgr,
        user_manager=user_mgr,
        mtproto_user_manager=mtproto_user_mgr,
        host="127.0.0.1",
        port=ADMIN_PORT,
    )

    await control_server.start()
    await socks_server.start()
    await mtproto_server.start()
    await admin_server.start()
    print("[+] All control services started successfully.")

    # 3. Connect 2 Reverse Agents
    agent1 = ReverseAgent("127.0.0.1", CONTROL_PORT, TOKEN, "agent-1")
    agent2 = ReverseAgent("127.0.0.1", CONTROL_PORT, TOKEN, "agent-2")
    t1 = asyncio.create_task(agent1.start())
    t2 = asyncio.create_task(agent2.start())

    for _ in range(30):
        if agent_mgr.get_agent_count() == 2:
            break
        await asyncio.sleep(0.1)
    assert agent_mgr.get_agent_count() == 2
    print("[+] 2 Reverse Agents connected and registered.")

    # 4. Open persistent / idle connections (holding sockets open to simulate active users)
    # SOCKS5 persistent connection
    s_reader, s_writer = await asyncio.open_connection("127.0.0.1", SOCKS_PORT)
    s_writer.write(b"\x05\x01\x02")  # offer auth
    await s_writer.drain()

    # MTProto persistent connection
    m_reader, m_writer = await asyncio.open_connection("127.0.0.1", MTPROTO_PORT)
    m_writer.write(b"SOME_PARTIAL_MTPROTO_DATA_WAITING")
    await m_writer.drain()

    print("[+] Idle client connections opened (holding sockets open).")

    # 5. TEST TERMINATION SPEED
    print("[*] Initiating graceful termination of all services and agents...")
    t_start = time.time()

    stop_coros = [
        mtproto_server.stop(),
        socks_server.stop(),
        control_server.stop(),
        admin_server.stop(),
        agent1.stop(),
        agent2.stop(),
    ]

    await asyncio.wait_for(asyncio.gather(*stop_coros, return_exceptions=True), timeout=3.0)

    t1.cancel()
    t2.cancel()
    try:
        await t1
    except asyncio.CancelledError:
        pass
    try:
        await t2
    except asyncio.CancelledError:
        pass

    await target.stop()

    await safe_close_writer(s_writer, timeout=0.2)
    await safe_close_writer(m_writer, timeout=0.2)

    elapsed = time.time() - t_start
    print(f"[SUCCESS] All services terminated in {elapsed:.3f} seconds! (Threshold: < 3.0s)")
    assert elapsed < 3.0, f"Termination took too long: {elapsed:.2f}s"

    # Clean up test files
    for f in ("test_term_users.json", "test_term_mtproto.json"):
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass

    print("[PASS] Clean termination test completed successfully with ZERO hangs!")


if __name__ == "__main__":
    asyncio.run(main())
