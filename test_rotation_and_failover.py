"""
Dedicated Test Suite for Rotation and 2-Second Failover in Reverse SOCKS5 Cluster.

Verifies:
1. Continuous Rotation: Each consecutive request is handled by a DIFFERENT reverse node.
2. 2-Second Failover: If a node does not respond within 2.0 seconds, the control server
   automatically falls back to the previous / alternative node, transparently completing
   the request without dropping the client.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-control"))
from agent_manager import AgentManager, AgentSession, StreamContext
from socks_users import UserManager
from socks5 import Socks5Server
from server import ControlBridgeServer
from protocol import (
    CMD_CONNECT_REQ,
    CMD_CONNECT_RESP,
    CMD_DATA,
    CMD_CLOSE,
    STATUS_SUCCESS,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-reverse"))
from agent import ReverseAgent

from test_system import TargetServer, socks5_request

SOCKS_PORT = 10810
CONTROL_PORT = 9080
TARGET_PORT = 8890
TOKEN = "RotationSecret2026!"


async def main():
    print("=" * 70)
    print("      TESTING CONSTANT ROTATION & 2-SECOND FAILOVER")
    print("=" * 70)

    # 1. Start Target Server
    target = TargetServer(port=TARGET_PORT)
    await target.start()
    print(f"[+] Target mock server running on 127.0.0.1:{TARGET_PORT}")

    # 2. Setup user and AgentManager with rotation and 2.0s fast failover
    users_file = "test_rotation_users.json"
    if os.path.exists(users_file):
        os.remove(users_file)
    user_mgr = UserManager(filepath=users_file)
    await user_mgr.add_user("alice", "alicepass")
    await user_mgr.add_user("bob", "bobpass")

    agent_mgr = AgentManager(strategy="rotation", fast_timeout=2.0)
    control_server = ControlBridgeServer(agent_mgr, "127.0.0.1", CONTROL_PORT, TOKEN)
    socks_server = Socks5Server(agent_mgr, user_mgr, "127.0.0.1", SOCKS_PORT, fast_timeout=2.0)

    await control_server.start()
    await socks_server.start()

    # 3. Start 2 normal reverse nodes: NODE-1 and NODE-2
    agent1 = ReverseAgent("127.0.0.1", CONTROL_PORT, TOKEN, "reverse-node-1")
    agent2 = ReverseAgent("127.0.0.1", CONTROL_PORT, TOKEN, "reverse-node-2")

    t1 = asyncio.create_task(agent1.start())
    t2 = asyncio.create_task(agent2.start())

    # Wait for both agents to register
    for _ in range(50):
        if agent_mgr.get_agent_count() == 2:
            break
        await asyncio.sleep(0.1)
    assert agent_mgr.get_agent_count() == 2
    print("[+] reverse-node-1 and reverse-node-2 connected and ready!")

    # -------------------------------------------------------------------------
    # TEST 1: INDEPENDENT PER-USER ROTATION (Alice vs Bob)
    # -------------------------------------------------------------------------
    print("\n[*] TEST 1: Testing per-user rotation with interleaved requests between Alice and Bob...")

    # Alice Request 1 -> should be Node 1
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="alice", password="alicepass", path="/a1")
    assert res["status"] == "success"
    a1_node = agent_mgr.user_states["socks:alice"].last_successful_agent_id
    print(f"  [Alice] Req #1 -> Handled by: [{a1_node}]")

    # Bob Request 1 -> starts fresh for Bob (Node 1)
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="bob", password="bobpass", path="/b1")
    assert res["status"] == "success"
    b1_node = agent_mgr.user_states["socks:bob"].last_successful_agent_id
    print(f"  [Bob]   Req #1 -> Handled by: [{b1_node}]")

    # Bob Request 2 -> should rotate for Bob (Node 2)
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="bob", password="bobpass", path="/b2")
    assert res["status"] == "success"
    b2_node = agent_mgr.user_states["socks:bob"].last_successful_agent_id
    print(f"  [Bob]   Req #2 -> Handled by: [{b2_node}]")
    assert b2_node != b1_node, f"Bob rotation failed: {b2_node} == {b1_node}"

    # Bob Request 3 -> should rotate for Bob (Node 1)
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="bob", password="bobpass", path="/b3")
    assert res["status"] == "success"
    b3_node = agent_mgr.user_states["socks:bob"].last_successful_agent_id
    print(f"  [Bob]   Req #3 -> Handled by: [{b3_node}]")
    assert b3_node != b2_node, f"Bob rotation failed: {b3_node} == {b2_node}"

    # Alice Request 2 -> MUST be different from Alice's Req #1, regardless of Bob's requests!
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="alice", password="alicepass", path="/a2")
    assert res["status"] == "success"
    a2_node = agent_mgr.user_states["socks:alice"].last_successful_agent_id
    print(f"  [Alice] Req #2 -> Handled by: [{a2_node}]")
    assert a2_node != a1_node, f"Alice rotation failed: {a2_node} == {a1_node}"

    # Alice Request 3 -> MUST be different from Alice's Req #2
    res = await socks5_request("127.0.0.1", SOCKS_PORT, "127.0.0.1", TARGET_PORT, username="alice", password="alicepass", path="/a3")
    assert res["status"] == "success"
    a3_node = agent_mgr.user_states["socks:alice"].last_successful_agent_id
    print(f"  [Alice] Req #3 -> Handled by: [{a3_node}]")
    assert a3_node != a2_node, f"Alice rotation failed: {a3_node} == {a2_node}"

    print("  [PASS] Per-user rotation confirmed! Alice and Bob have independent alternating cycles.")

    # -------------------------------------------------------------------------
    # TEST 2: 2-SECOND FAILOVER TO PREVIOUS / OTHER NODE
    # -------------------------------------------------------------------------
    print("\n[*] TEST 2: Testing 2-second failover when primary rotated node is unresponsive...")
    # We will simulate a frozen node by creating an agent session that intentionally
    # ignores CMD_CONNECT_REQ (simulating network freeze or overloaded worker).
    last_working_node = agent_mgr._last_successful_agent_id
    print(f"  Last successful node was: [{last_working_node}]")

    # Connect a 3rd node "hanging-node" that won't answer connect requests
    class HangingAgent(ReverseAgent):
        async def _handle_connect(self, stream_id: int, payload: bytes):
            # Intentionally sleep longer than fast_timeout (e.g. 5 seconds)
            # to trigger the 2.0s failover on the control server
            try:
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                # Cancelled by control server after failover
                pass

    hanging_agent = HangingAgent("127.0.0.1", CONTROL_PORT, TOKEN, "hanging-node-3")
    t3 = asyncio.create_task(hanging_agent.start())

    for _ in range(50):
        if agent_mgr.get_agent_count() == 3:
            break
        await asyncio.sleep(0.1)
    assert agent_mgr.get_agent_count() == 3
    print("[+] hanging-node-3 connected!")

    initial_failovers = agent_mgr.failover_count

    # Send requests until we encounter the failover from hanging-node-3
    print("  Sending requests until hanging-node-3 is hit in Alice's rotation...")
    failover_occurred = False
    for req_idx in range(5):
        start_t = time.time()
        res = await socks5_request(
            "127.0.0.1",
            SOCKS_PORT,
            "127.0.0.1",
            TARGET_PORT,
            username="alice",
            password="alicepass",
            path=f"/failover-test-{req_idx}",
        )
        elapsed = time.time() - start_t
        rescuing_node = agent_mgr.user_states["socks:alice"].last_successful_agent_id
        print(f"  Attempt #{req_idx + 1}: completed in {elapsed:.2f}s via [{rescuing_node}]")
        assert res["status"] == "success"
        if elapsed >= 1.8:
            failover_occurred = True
            print(f"  [SUCCESS] 2-second failover observed on attempt #{req_idx + 1}!")
            print(f"  Rescued by fallback node: [{rescuing_node}]")
            break

    assert failover_occurred, "Failover did not occur within expected rotation cycle!"
    assert agent_mgr.failover_count > initial_failovers
    print("  [PASS] 2-second failover worked seamlessly! When hanging-node-3 timed out, request was rescued by fallback node!")

    # Cleanup
    print("\n[*] Cleaning up...")
    await hanging_agent.stop()
    t3.cancel()
    await agent1.stop()
    t1.cancel()
    await agent2.stop()
    t2.cancel()
    await socks_server.stop()
    await control_server.stop()
    await target.stop()

    if os.path.exists(users_file):
        os.remove(users_file)

    print("\n" + "=" * 70)
    print("   ALL TESTS FOR ROTATION & 2S FAILOVER COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
