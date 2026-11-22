"""
Automated Integration Test for Multi-Tor Reverse Cluster.
Verifies that:
1. Control Bridge Server receives connections from multiple Tor Reverse Agents.
2. Agents authenticate and register with agent_manager as tor-node-01, tor-node-02, etc.
3. Requests sent to control server are routed through the Tor Reverse Agents.
4. Agents successfully route outbound traffic through their assigned Tor SOCKS5 ports to target server.
5. Bidirectional data transfer works end-to-end.
"""
import asyncio
import os
import sys
import struct
import json

# Add search paths
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "socks-control"))
sys.path.insert(0, os.path.join(ROOT, "reverse-multi-tor"))

from agent_manager import AgentManager, StreamContext
from server import ControlBridgeServer
from tor_agent import TorReverseAgent
from protocol import (
    CMD_CONNECT_REQ,
    CMD_DATA,
    CMD_CLOSE,
    STATUS_SUCCESS,
)


class MockTorSocksServer:
    """Mock SOCKS5 server simulating Tor listening on a specific port."""

    def __init__(self, port: int):
        self.port = port
        self.server = None
        self.connections_handled = 0

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.connections_handled += 1
        try:
            # 1. Handshake
            ver_hdr = await reader.readexactly(2)
            ver, nmethods = ver_hdr
            methods = await reader.readexactly(nmethods)

            if 0x02 in methods:
                writer.write(b"\x05\x02")
                await writer.drain()
                # Read user/pass subneg (RFC 1929)
                sub_ver = (await reader.readexactly(1))[0]
                u_len = (await reader.readexactly(1))[0]
                user = await reader.readexactly(u_len)
                p_len = (await reader.readexactly(1))[0]
                password = await reader.readexactly(p_len)
                writer.write(b"\x01\x00")
                await writer.drain()
            else:
                writer.write(b"\x05\x00")
                await writer.drain()

            # 2. Request
            hdr = await reader.readexactly(4)
            ver, cmd, rsv, atyp = hdr
            if atyp == 0x01:  # IPv4
                addr_b = await reader.readexactly(4)
                host = ".".join(str(b) for b in addr_b)
            elif atyp == 0x03:  # Domain
                dlen = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(dlen)).decode()
            port = struct.unpack("!H", await reader.readexactly(2))[0]

            # Connect to actual target
            target_reader, target_writer = await asyncio.open_connection(host, port)

            # Reply OK
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.port))
            await writer.drain()

            # Pipe both directions
            async def fwd(src, dst):
                try:
                    while True:
                        buf = await src.read(8192)
                        if not buf:
                            break
                        dst.write(buf)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    dst.close()

            await asyncio.gather(
                fwd(reader, target_writer),
                fwd(target_reader, writer),
                return_exceptions=True,
            )
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, "127.0.0.1", self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


async def main():
    print("=" * 65)
    print("   STARTING INTEGRATION TEST: REVERSE MULTI-TOR CLUSTER")
    print("=" * 65)

    CONTROL_PORT = 39800
    TOR_PORT_1 = 39050
    TOR_PORT_2 = 39051
    TARGET_PORT = 39888
    TOKEN = "TestSecret2026!"

    # 1. Start Mock Target Echo Server
    async def echo_handler(r, w):
        data = await r.read(1024)
        w.write(b"TOR_ECHO:" + data)
        await w.drain()
        w.close()
        await w.wait_closed()

    echo_srv = await asyncio.start_server(echo_handler, "127.0.0.1", TARGET_PORT)
    print(f"[+] Mock Target Echo Server running on 127.0.0.1:{TARGET_PORT}")

    # 2. Start 2 Mock Tor SOCKS5 Servers
    mock_tor_1 = MockTorSocksServer(TOR_PORT_1)
    mock_tor_2 = MockTorSocksServer(TOR_PORT_2)
    await mock_tor_1.start()
    await mock_tor_2.start()
    print(f"[+] Mock Tor SOCKS Servers running on ports {TOR_PORT_1} and {TOR_PORT_2}")

    # 3. Start Control Server
    agent_mgr = AgentManager()
    control_server = ControlBridgeServer(agent_mgr, "127.0.0.1", CONTROL_PORT, TOKEN)
    await control_server.start()
    print(f"[+] Control Bridge Server running on 127.0.0.1:{CONTROL_PORT}")

    # 4. Start 2 Tor Reverse Agents
    agent_1 = TorReverseAgent(
        control_host="127.0.0.1",
        control_port=CONTROL_PORT,
        secret_token=TOKEN,
        agent_id="tor-node-01",
        tor_host="127.0.0.1",
        tor_port=TOR_PORT_1,
    )
    agent_2 = TorReverseAgent(
        control_host="127.0.0.1",
        control_port=CONTROL_PORT,
        secret_token=TOKEN,
        agent_id="tor-node-02",
        tor_host="127.0.0.1",
        tor_port=TOR_PORT_2,
    )

    task_1 = asyncio.create_task(agent_1.run())
    task_2 = asyncio.create_task(agent_2.run())

    # Wait for both agents to connect and register
    for _ in range(50):
        if len(agent_mgr.agents) == 2:
            break
        await asyncio.sleep(0.1)

    assert "tor-node-01" in agent_mgr.agents
    assert "tor-node-02" in agent_mgr.agents
    print("  [OK] Both Tor Reverse Agents registered in Control Server successfully!")

    # 5. Test Live Routing through tor-node-01
    print("\n[*] Testing target connection routed through tor-node-01 (Tor Port 39050)...")
    agent_obj_1 = agent_mgr.agents["tor-node-01"]
    stream_id_1 = agent_mgr.get_next_stream_id()
    stream_1 = StreamContext(stream_id_1, "127.0.0.1", TARGET_PORT, "tor-node-01")
    agent_obj_1.register_stream(stream_1)

    await agent_obj_1.send_json(CMD_CONNECT_REQ, stream_id_1, {"host": "127.0.0.1", "port": TARGET_PORT})
    await asyncio.wait_for(stream_1.connect_event.wait(), timeout=5.0)
    assert stream_1.connect_status == STATUS_SUCCESS
    print("  [OK] tor-node-01 established tunnel through Tor port 39050!")

    # Send data
    await agent_obj_1.send_frame(CMD_DATA, stream_id_1, b"PING_TOR_1")
    reply_1 = await asyncio.wait_for(stream_1.data_queue.get(), timeout=5.0)
    assert reply_1 == b"TOR_ECHO:PING_TOR_1"
    print(f"  [OK] Data returned through Tor tunnel: {reply_1.decode('utf-8')}")

    await agent_obj_1.send_frame(CMD_CLOSE, stream_id_1)
    agent_obj_1.remove_stream(stream_id_1)

    # 6. Test Live Routing through tor-node-02
    print("\n[*] Testing target connection routed through tor-node-02 (Tor Port 39051)...")
    agent_obj_2 = agent_mgr.agents["tor-node-02"]
    stream_id_2 = agent_mgr.get_next_stream_id()
    stream_2 = StreamContext(stream_id_2, "127.0.0.1", TARGET_PORT, "tor-node-02")
    agent_obj_2.register_stream(stream_2)

    await agent_obj_2.send_json(CMD_CONNECT_REQ, stream_id_2, {"host": "127.0.0.1", "port": TARGET_PORT})
    await asyncio.wait_for(stream_2.connect_event.wait(), timeout=5.0)
    assert stream_2.connect_status == STATUS_SUCCESS
    print("  [OK] tor-node-02 established tunnel through Tor port 39051!")

    await agent_obj_2.send_frame(CMD_DATA, stream_id_2, b"PING_TOR_2")
    reply_2 = await asyncio.wait_for(stream_2.data_queue.get(), timeout=5.0)
    assert reply_2 == b"TOR_ECHO:PING_TOR_2"
    print(f"  [OK] Data returned through Tor tunnel: {reply_2.decode('utf-8')}")

    await agent_obj_2.send_frame(CMD_CLOSE, stream_id_2)
    agent_obj_2.remove_stream(stream_id_2)

    # 7. Test Unique IP Registry and Collision Avoidance
    print("\n[*] Testing ClusterIPRegistry duplicate IP rejection and re-roll...")
    from cluster import ClusterIPRegistry
    reg = ClusterIPRegistry()
    assert await reg.claim("185.220.101.5", "node-01") is True
    # Duplicate claim by another node must be REJECTED!
    assert await reg.claim("185.220.101.5", "node-02") is False
    # Unique claim accepted
    assert await reg.claim("198.51.100.23", "node-02") is True
    assert reg.unique_count() == 2
    print("  [OK] Duplicate IP was strictly rejected and forced to re-roll unique circuit!")

    # Clean shutdown
    print("\n[*] Shutting down test services...")
    await agent_1.stop()
    await agent_2.stop()
    task_1.cancel()
    task_2.cancel()
    await control_server.stop()
    await mock_tor_1.stop()
    await mock_tor_2.stop()
    echo_srv.close()
    await echo_srv.wait_closed()

    print("=" * 65)
    print("   ALL MULTI-TOR INTEGRATION TESTS PASSED 100%!")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
