"""
Generator for multi-port isolated Tor configuration (torrc).
Creates N isolated SocksPorts in a single Tor daemon or separate instance configs.
"""
import argparse
import os
import sys

TEMPLATE_HEADER = """# ==============================================================================
# Multi-Tor Cluster Configuration
# Generated automatically for Reverse SOCKS5 Cluster
# ==============================================================================
DataDirectory {data_dir}
PidFile {pid_file}
Log notice stdout

# Tor Control Port for IP rotation (SIGNAL NEWNYM)
ControlPort {control_ip}:{control_port}
CookieAuthentication 0

# Client only - do not act as relay or exit
ClientOnly 1
ExitRelay 0

# Stream Isolation & Circuits Configuration
# Each SocksPort has full isolation to build independent circuits
"""

PORT_ENTRY = "SocksPort {ip}:{port} IsolateDestAddr IsolateDestPort\n"


def generate_torrc(
    count: int = 50,
    start_port: int = 9050,
    ip: str = "127.0.0.1",
    control_port: int = 9049,
    control_ip: str = "127.0.0.1",
    data_dir: str = "/var/lib/tor_cluster",
    pid_file: str = "/var/run/tor_cluster.pid",
    output_path: str = "torrc",
) -> str:
    # Quote paths containing spaces (especially on Windows)
    safe_data_dir = f'"{data_dir}"' if (" " in data_dir and not data_dir.startswith('"')) else data_dir
    safe_pid_file = f'"{pid_file}"' if (" " in pid_file and not pid_file.startswith('"')) else pid_file

    content = TEMPLATE_HEADER.format(
        data_dir=safe_data_dir,
        pid_file=safe_pid_file,
        control_ip=control_ip,
        control_port=control_port,
    )
    content += "\n# ------------------ Isolated SOCKS5 Ports ------------------\n"
    for i in range(count):
        port = start_port + i
        content += PORT_ENTRY.format(ip=ip, port=port)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def main():
    parser = argparse.ArgumentParser(description="Generate Multi-Tor torrc configuration file")
    parser.add_argument("--count", type=int, default=50, help="Number of Tor SOCKS ports (default: 50)")
    parser.add_argument("--start-port", type=int, default=9050, help="First SOCKS port (default: 9050)")
    parser.add_argument("--ip", default="127.0.0.1", help="Binding IP for SOCKS ports (default: 127.0.0.1)")
    parser.add_argument("--control-port", type=int, default=9049, help="Tor ControlPort (default: 9049)")
    parser.add_argument("--data-dir", default="/var/lib/tor_cluster", help="Tor DataDirectory")
    parser.add_argument("--output", default="torrc", help="Output torrc file path")
    args = parser.parse_args()

    # On Windows fallback data directory
    data_dir = args.data_dir
    pid_file = "/var/run/tor_cluster.pid"
    if os.name == "nt":
        data_dir = os.path.abspath("./tor_data")
        pid_file = os.path.abspath("./tor.pid")

    out = generate_torrc(
        count=args.count,
        start_port=args.start_port,
        ip=args.ip,
        control_port=args.control_port,
        data_dir=data_dir,
        pid_file=pid_file,
        output_path=args.output,
    )
    print(f"[OK] Generated {args.count} Tor ports ({args.start_port}..{args.start_port + args.count - 1}) into '{out}'")
    print(f"     ControlPort: {args.ip}:{args.control_port}")


if __name__ == "__main__":
    main()
