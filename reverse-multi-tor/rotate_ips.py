"""
Tor IP Rotation Utility.
Connects to Tor ControlPort and sends SIGNAL NEWNYM to switch all exit nodes/circuits.
"""
import asyncio
import argparse
import sys


async def rotate_tor_ips(control_host: str = "127.0.0.1", control_port: int = 9049, password: str = "") -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(control_host, control_port),
            timeout=5.0,
        )
    except Exception as e:
        print(f"[ERROR] Could not connect to Tor ControlPort at {control_host}:{control_port}: {e}")
        return False

    try:
        # Authenticate
        auth_cmd = f'AUTHENTICATE "{password}"\r\n'.encode()
        writer.write(auth_cmd)
        await writer.drain()

        resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not resp.startswith(b"250"):
            print(f"[ERROR] Tor Control authentication failed: {resp.decode().strip()}")
            return False

        # Send SIGNAL NEWNYM
        writer.write(b"SIGNAL NEWNYM\r\n")
        await writer.drain()

        resp2 = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if resp2.startswith(b"250"):
            print(f"[SUCCESS] SIGNAL NEWNYM accepted! All Tor circuits are rebuilding with brand NEW exit IPs!")
            return True
        else:
            print(f"[ERROR] Tor rejected SIGNAL NEWNYM: {resp2.decode().strip()}")
            return False

    finally:
        writer.write(b"QUIT\r\n")
        try:
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Rotate Tor Exit IPs via ControlPort (SIGNAL NEWNYM)")
    parser.add_argument("--host", default="127.0.0.1", help="Tor ControlPort host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9049, help="Tor ControlPort port (default: 9049)")
    parser.add_argument("--password", default="", help="Tor Control password if configured")
    args = parser.parse_args()

    ok = asyncio.run(rotate_tor_ips(args.host, args.port, args.password))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
