import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-control"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "socks-reverse"))

from protocol import (
    pack_frame,
    pack_json,
    read_frame,
    CMD_AUTH_REQ,
    CMD_AUTH_RESP,
    CMD_CONNECT_REQ,
    CMD_CONNECT_RESP,
    CMD_DATA,
    CMD_CLOSE,
    STATUS_SUCCESS,
)
from agent import ReverseAgent
from server import ControlBridgeServer
from agent_manager import AgentManager, StreamContext


async def mock_http_proxy(reader, writer):
    """Simulates PythonAnywhere's Squid proxy on proxy.server:3128."""
    req_line = await reader.readline()
    parts = req_line.decode().split()
    if parts[0] != "CONNECT":
        writer.close()
        return
    host, port = parts[1].split(":")
    port = int(port)
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break

    # Connect to actual target (our control server)
    tr, tw = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()

    async def fwd(src, dst):
        try:
            while True:
                d = await src.read(4096)
                if not d:
                    break
                dst.write(d)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    t1 = asyncio.create_task(fwd(reader, tw))
    t2 = asyncio.create_task(fwd(tr, writer))
    await asyncio.gather(t1, t2, return_exceptions=True)


async def main():
    print("=" * 60)
    print("TEST: REVERSE AGENT FAKE-TLS + PYTHONANYWHERE HTTP CONNECT")
    print("=" * 60)

    CONTROL_PORT = 39090
    PROXY_PORT = 33128
    TOKEN = "SecretToken123"

    agent_mgr = AgentManager()
    control_server = ControlBridgeServer(
        agent_manager=agent_mgr,
        host="127.0.0.1",
        port=CONTROL_PORT,
        secret_token=TOKEN,
    )
    await control_server.start()

    # 1. Test Plain Agent connection (backward compatibility)
    plain_agent = ReverseAgent(
        control_host="127.0.0.1",
        control_port=CONTROL_PORT,
        secret_token=TOKEN,
        agent_id="agent-plain",
        use_faketls=False,
    )
    plain_task = asyncio.create_task(plain_agent.start())
    await asyncio.sleep(0.3)
    assert "agent-plain" in agent_mgr.agents
    s_plain = agent_mgr.agents["agent-plain"]
    assert s_plain.is_faketls is False
    print("  [OK] Plain Agent connected successfully! is_faketls=False")

    # 2. Test Fake-TLS Agent connection (Direct HTTPS Fake-TLS with white SNI)
    faketls_agent = ReverseAgent(
        control_host="127.0.0.1",
        control_port=CONTROL_PORT,
        secret_token=TOKEN,
        agent_id="agent-faketls",
        use_faketls=True,
        faketls_domain="google.com",
    )
    faketls_task = asyncio.create_task(faketls_agent.start())
    await asyncio.sleep(0.3)
    assert "agent-faketls" in agent_mgr.agents
    s_tls = agent_mgr.agents["agent-faketls"]
    assert s_tls.is_faketls is True
    assert s_tls.sni_domain == "google.com"
    print("  [OK] Fake-TLS Agent connected directly! is_faketls=True, SNI=google.com")

    # 3. Test Agent through PythonAnywhere HTTP CONNECT Proxy + Fake-TLS!
    proxy_server = await asyncio.start_server(mock_http_proxy, "127.0.0.1", PROXY_PORT)
    pyanywhere_agent = ReverseAgent(
        control_host="127.0.0.1",
        control_port=CONTROL_PORT,
        secret_token=TOKEN,
        agent_id="agent-pythonanywhere",
        use_faketls=True,
        faketls_domain="api.telegram.org",
        http_proxy=f"http://127.0.0.1:{PROXY_PORT}",
        connect_host="api.telegram.org",
    )
    pyanywhere_task = asyncio.create_task(pyanywhere_agent.start())
    await asyncio.sleep(0.5)
    assert "agent-pythonanywhere" in agent_mgr.agents
    s_pa = agent_mgr.agents["agent-pythonanywhere"]
    assert s_pa.is_faketls is True
    assert s_pa.sni_domain == "api.telegram.org"
    print("  [OK] PythonAnywhere Agent (HTTP Proxy + Fake-TLS) connected! SNI=api.telegram.org")

    # 4. Check Agent status list
    status_list = agent_mgr.get_agent_status_list()
    assert len(status_list) == 3
    print(f"  [OK] Active agent count: {len(status_list)}")

    # 5. Route actual data stream through PythonAnywhere Fake-TLS Reverse Agent!
    print("\n[*] Testing live stream routing through PythonAnywhere Fake-TLS Agent...")
    
    # Start a mock echo target server
    async def echo_srv(r, w):
        data = await r.read(1024)
        w.write(b"ECHO_RESP:" + data)
        await w.drain()
        w.close()
        await w.wait_closed()
        
    echo_target = await asyncio.start_server(echo_srv, "127.0.0.1", 38888)
    
    # Route via pyanywhere agent specifically
    agent_obj = agent_mgr.agents["agent-pythonanywhere"]
    stream_id = agent_mgr.get_next_stream_id()
    stream = StreamContext(stream_id, "127.0.0.1", 38888, agent_obj.agent_id)
    agent_obj.register_stream(stream)
    
    await agent_obj.send_json(CMD_CONNECT_REQ, stream_id, {"host": "127.0.0.1", "port": 38888})
    await asyncio.wait_for(stream.connect_event.wait(), timeout=5.0)
    assert stream.connect_status == STATUS_SUCCESS
    print("  [OK] PythonAnywhere agent connected to target server through Fake-TLS tunnel!")
    
    # Send data through Fake-TLS reverse agent to target
    await agent_obj.send_frame(CMD_DATA, stream.stream_id, b"HELLO_PYTHONANYWHERE")
    reply = await asyncio.wait_for(stream.data_queue.get(), timeout=5.0)
    assert reply == b"ECHO_RESP:HELLO_PYTHONANYWHERE"
    print(f"  [OK] Target returned: {reply.decode('utf-8')}")
    
    # Close stream
    await agent_obj.send_frame(CMD_CLOSE, stream.stream_id)
    agent_obj.remove_stream(stream.stream_id)
    echo_target.close()
    await echo_target.wait_closed()

    # Stop all agents and servers
    await plain_agent.stop()
    await faketls_agent.stop()
    await pyanywhere_agent.stop()
    plain_task.cancel()
    faketls_task.cancel()
    pyanywhere_task.cancel()
    await control_server.stop()
    proxy_server.close()
    await proxy_server.wait_closed()

    print("=" * 60)
    print("ALL FAKE-TLS AND PYTHONANYWHERE TESTS PASSED 100%!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
