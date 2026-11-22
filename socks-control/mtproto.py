"""
MTProto Proxy Server with Fake-TLS support for socks-control.
Disguises Telegram proxy traffic as TLS 1.3 / HTTPS to google.com (or any domain)
to bypass Russian TSPU / DPI censors.
Routes Telegram DC connections through the connected socks-reverse worker pool.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import random
import struct
import time
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from agent_manager import AgentManager, StreamContext
from protocol import (
    CMD_CONNECT_REQ,
    CMD_DATA,
    CMD_CLOSE,
    STATUS_SUCCESS,
    safe_close_writer,
    enable_socket_keepalive,
)

logger = logging.getLogger("MTProto")

# Telegram Data Centers IPv4
TG_DATACENTERS_V4 = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "149.154.171.5",
}
DEFAULT_DC = 2
TG_DATACENTER_PORT = 443

# Protocol tags
PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_TAG_SECURE = b"\xdd\xdd\xdd\xdd"

HANDSHAKE_LEN = 64
SKIP_LEN = 8
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

RESERVED_NONCE_FIRST_CHARS = [b"\xef"]
RESERVED_NONCE_BEGINNINGS = [
    b"\x48\x45\x41\x44",  # HEAD
    b"\x50\x4F\x53\x54",  # POST
    b"\x47\x45\x54\x20",  # GET 
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",
]
RESERVED_NONCE_CONTINUES = [b"\x00\x00\x00\x00"]


def create_aes_ctr(key: bytes, iv: int):
    """Creates a high-performance native AES-CTR cipher adapter."""
    iv_bytes = int.to_bytes(iv, 16, "big")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv_bytes), default_backend())
    return cipher.encryptor()


def gen_x25519_public_key() -> bytes:
    """Generates a valid X25519 public key curve point for TLS ServerHello."""
    p = 2**255 - 19
    n = random.randrange(p)
    return int.to_bytes((n * n) % p, length=32, byteorder="little")


def normalize_secret(secret_str: str, domain: str = "google.com") -> tuple[bytes, str, str]:
    """
    Parses secret in various formats:
    - 32 hex chars raw secret: 'd04843361111fc744f516582107f9fb6'
    - Fake-TLS secret: 'ee' + 32 hex chars + domain hex
    Returns (raw_secret_bytes, domain, fake_tls_hex_secret).
    """
    cleaned = secret_str.strip().lower()
    if cleaned.startswith("ee") and len(cleaned) > 34:
        raw_hex = cleaned[2:34]
        domain_hex = cleaned[34:]
        try:
            extracted_domain = bytes.fromhex(domain_hex).decode("utf-8", errors="ignore")
            if extracted_domain:
                domain = extracted_domain
        except Exception:
            pass
        return bytes.fromhex(raw_hex), domain, cleaned

    # Plain 32 hex chars secret
    raw_hex = cleaned[:32].zfill(32)
    raw_bytes = bytes.fromhex(raw_hex)
    domain_hex = domain.encode("utf-8").hex()
    fake_tls_secret = f"ee{raw_hex}{domain_hex}"
    return raw_bytes, domain, fake_tls_secret


def get_tg_links(server_host: str, port: int, fake_tls_secret: str, raw_secret_hex: Optional[str] = None) -> dict[str, str]:
    """Returns direct app links and web links for Telegram client configuration (Fake-TLS and Hex32)."""
    links = {
        "tg_link": f"tg://proxy?server={server_host}&port={port}&secret={fake_tls_secret}",
        "tme_link": f"https://t.me/proxy?server={server_host}&port={port}&secret={fake_tls_secret}",
    }
    if raw_secret_hex:
        links["tg_link_hex32"] = f"tg://proxy?server={server_host}&port={port}&secret={raw_secret_hex}"
        links["tme_link_hex32"] = f"https://t.me/proxy?server={server_host}&port={port}&secret={raw_secret_hex}"
    return links


class FakeTLSStreamReader:
    """
    Unwraps TLS 1.3 records sent by Telegram client, exposing the
    inner MTProto Obfuscated2 stream.
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

            rec_type = hdr[0]
            version = hdr[1:3]
            rec_len = int.from_bytes(hdr[3:5], "big")

            if rec_len == 0:
                continue
            if rec_len > 18432:
                logger.warning(f"FakeTLS record length {rec_len} exceeds maximum allowed")
                return b""

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


class FakeTLSStreamWriter:
    """
    Wraps outgoing MTProto stream into TLS 1.3 Application Data records (\x17\x03\x03).
    """
    MAX_RECORD_LEN = 16384

    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer

    def write(self, data: bytes):
        for start in range(0, len(data), self.MAX_RECORD_LEN):
            chunk = data[start : start + self.MAX_RECORD_LEN]
            record = b"\x17\x03\x03" + int.to_bytes(len(chunk), 2, "big") + chunk
            self.writer.write(record)

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

    def __getattr__(self, name):
        return getattr(self.writer, name)


class MtprotoProxyServer:
    """
    MTProto Proxy with Fake-TLS (Port 8443).
    Accepts Telegram connections disguised as TLS 1.3, handles Obfuscated2 framing,
    and tunnels all outbound traffic to Telegram Data Centers through the
    connected socks-reverse agent pool.
    """

    def __init__(
        self,
        agent_manager: AgentManager,
        host: str = "0.0.0.0",
        port: int = 8443,
        secret: str = "d04843361111fc744f516582107f9fb6",
        domain: str = "google.com",
        tag: Optional[str] = None,
        mask_host: str = "google.com",
        mask_port: int = 443,
        fast_timeout: float = 4.0,
        connect_timeout: float = 20.0,
        tg_port: int = TG_DATACENTER_PORT,
        dc_mapping: Optional[dict] = None,
        user_manager=None,
    ):
        self.agent_manager = agent_manager
        self.host = host
        self.port = port
        self.raw_secret, self.domain, self.fake_tls_secret = normalize_secret(secret, domain)
        self.tag = tag
        self.mask_host = mask_host
        self.mask_port = mask_port
        self.fast_timeout = fast_timeout
        self.connect_timeout = connect_timeout
        self.tg_port = tg_port
        self.dc_mapping = dc_mapping or TG_DATACENTERS_V4
        self.user_manager = user_manager
        self.server: Optional[asyncio.Server] = None
        self.active_tasks: set[asyncio.Task] = set()
        self.active_writers: set[asyncio.StreamWriter] = set()
        self.closed = False

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.host,
            port=self.port,
            backlog=2048,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(
            f"[*] MTProto Proxy Server listening on {addrs} (Dual-mode: Fake-TLS + Plain Hex32)"
        )
        logger.info(f"[*] Default MTProto Fake-TLS Secret: {self.fake_tls_secret}")
        logger.info(f"[*] Default MTProto Raw Hex32 Secret: {self.raw_secret.hex()}")

    async def stop(self):
        self.closed = True
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
            except Exception:
                pass

        # Close all active client connections immediately
        for writer in list(self.active_writers):
            try:
                writer.close()
            except Exception:
                pass
        self.active_writers.clear()

        # Cancel remaining active tasks
        for task in list(self.active_tasks):
            if not task.done():
                task.cancel()
        if self.active_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self.active_tasks), return_exceptions=True),
                    timeout=1.0,
                )
            except Exception:
                pass
        self.active_tasks.clear()
        logger.info("MTProto Proxy Server stopped.")

    @staticmethod
    def _decrypt_obfuscated2(handshake: bytes, secret: bytes):
        """
        Attempts to decrypt a 64-byte Obfuscated2 handshake using the given raw secret bytes.
        Returns (proto_tag, dc_num, client_decryptor, client_encryptor) or None.
        """
        if len(handshake) != HANDSHAKE_LEN:
            return None

        dec_prekey_and_iv = handshake[SKIP_LEN : SKIP_LEN + KEY_LEN + IV_LEN]
        dec_prekey, dec_iv = dec_prekey_and_iv[:KEY_LEN], dec_prekey_and_iv[KEY_LEN:]

        enc_prekey_and_iv = handshake[SKIP_LEN : SKIP_LEN + KEY_LEN + IV_LEN][::-1]
        enc_prekey, enc_iv = enc_prekey_and_iv[:KEY_LEN], enc_prekey_and_iv[KEY_LEN:]

        client_dec_key = hashlib.sha256(dec_prekey + secret).digest()
        client_decryptor = create_aes_ctr(client_dec_key, int.from_bytes(dec_iv, "big"))

        client_enc_key = hashlib.sha256(enc_prekey + secret).digest()
        client_encryptor = create_aes_ctr(client_enc_key, int.from_bytes(enc_iv, "big"))

        # Decrypt handshake tail (bytes 56..64)
        decrypted = client_decryptor.update(handshake)
        proto_tag = decrypted[PROTO_TAG_POS : PROTO_TAG_POS + 4]
        if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
            return None

        dc_idx = int.from_bytes(decrypted[DC_IDX_POS : DC_IDX_POS + 2], "little", signed=True)
        dc_num = abs(dc_idx)
        if not (1 <= dc_num <= 5):
            if dc_num == 0:
                dc_num = DEFAULT_DC
            else:
                return None

        return proto_tag, dc_num, client_decryptor, client_encryptor

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        if self.closed:
            try:
                client_writer.close()
            except Exception:
                pass
            return

        current_task = asyncio.current_task()
        if current_task:
            self.active_tasks.add(current_task)
        self.active_writers.add(client_writer)

        client_addr = client_writer.get_extra_info("peername")
        client_ip = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "unknown"
        ip_only = client_addr[0] if client_addr else "unknown"

        enable_socket_keepalive(client_writer)

        logger.info(f"[MTProto] Incoming connection from {client_ip}")

        try:
            # Get dict of {client_name: raw_secret_bytes}
            secrets_to_check = (
                self.user_manager.get_secrets_map()
                if self.user_manager
                else {"default": self.raw_secret}
            )
            if not secrets_to_check and self.raw_secret:
                secrets_to_check = {"default": self.raw_secret}

            # 1. Read first 3 bytes to detect protocol: TLS ClientHello vs raw MTProto Obfuscated2
            prefix = await asyncio.wait_for(client_reader.readexactly(3), timeout=10.0)

            is_faketls = False
            matched_user = None
            matched_secret = None
            proto_tag = None
            dc_num = None
            client_decryptor = None
            client_encryptor = None
            stream_reader = None
            stream_writer = None

            # Case A: Potential TLS ClientHello (Fake-TLS)
            if prefix == b"\x16\x03\x01":
                len_bytes = await asyncio.wait_for(client_reader.readexactly(2), timeout=5.0)
                rec_len = int.from_bytes(len_bytes, "big")
                if 40 <= rec_len <= 16384:
                    body = await asyncio.wait_for(client_reader.readexactly(rec_len), timeout=5.0)
                    client_hello = prefix + len_bytes + body

                    if len(client_hello) >= 44:
                        digest = client_hello[11:43]
                        msg = client_hello[:11] + b"\x00" * 32 + client_hello[43:]

                        valid_xored = None
                        for uname, sec_bytes in secrets_to_check.items():
                            comp_digest = hmac.new(sec_bytes, msg, hashlib.sha256).digest()
                            xored = bytes(digest[i] ^ comp_digest[i] for i in range(32))
                            if xored.startswith(b"\x00" * 28):
                                matched_user = uname
                                matched_secret = sec_bytes
                                valid_xored = xored
                                is_faketls = True
                                break

                        if is_faketls:
                            timestamp = int.from_bytes(valid_xored[-4:], "little")
                            time_diff = time.time() - timestamp
                            if not (-25 * 60 < time_diff < 25 * 60) and timestamp > 86400:
                                logger.warning(f"[{client_ip}] Fake-TLS clock skew detected ({int(time_diff)}s diff)")

                            # Send Fake-TLS ServerHello response
                            await self._send_tls_server_hello(client_writer, client_hello, digest, matched_secret)

                            # Wrap in FakeTLS stream layers
                            tls_reader = FakeTLSStreamReader(client_reader)
                            tls_writer = FakeTLSStreamWriter(client_writer)
                            stream_reader = tls_reader
                            stream_writer = tls_writer

                            # Read Obfuscated2 64-byte handshake inside Fake-TLS
                            handshake = await asyncio.wait_for(tls_reader.readexactly(HANDSHAKE_LEN), timeout=10.0)
                            res = self._decrypt_obfuscated2(handshake, matched_secret)
                            if not res:
                                logger.warning(f"[{client_ip}] Invalid inner MTProto handshake inside Fake-TLS")
                                return
                            proto_tag, dc_num, client_decryptor, client_encryptor = res
                        else:
                            # TLS ClientHello, but HMAC mismatch -> probe or wrong Fake-TLS secret
                            logger.info(f"[{client_ip}] Invalid Fake-TLS secret HMAC. Forwarding to mask host {self.mask_host}...")
                            await self._handle_bad_client(client_reader, client_writer, client_hello, client_ip)
                            return
                else:
                    # Invalid TLS record length -> active scanner probe
                    await self._handle_bad_client(client_reader, client_writer, prefix + len_bytes, client_ip)
                    return

            # Case B: Plain MTProto Obfuscated2 (Connecting with hex32 secret directly)
            else:
                try:
                    rest = await asyncio.wait_for(client_reader.readexactly(HANDSHAKE_LEN - len(prefix)), timeout=5.0)
                    handshake = prefix + rest
                except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
                    partial = e.partial if isinstance(e, asyncio.IncompleteReadError) else b""
                    await self._handle_bad_client(client_reader, client_writer, prefix + partial, client_ip)
                    return

                # Try to decrypt the 64-byte handshake with each registered secret
                for uname, sec_bytes in secrets_to_check.items():
                    res = self._decrypt_obfuscated2(handshake, sec_bytes)
                    if res:
                        matched_user = uname
                        matched_secret = sec_bytes
                        proto_tag, dc_num, client_decryptor, client_encryptor = res
                        is_faketls = False
                        stream_reader = client_reader
                        stream_writer = client_writer
                        break

                if not matched_secret:
                    logger.info(
                        f"[{client_ip}] Invalid MTProto handshake / secret (checked {len(secrets_to_check)} secret(s)). "
                        f"Forwarding probe to mask host {self.mask_host}..."
                    )
                    await self._handle_bad_client(client_reader, client_writer, handshake, client_ip)
                    return

            auth_mode = "Fake-TLS" if is_faketls else "Plain Hex32 (Obfuscated2)"
            target_dc = self.dc_mapping.get(dc_num, self.dc_mapping.get(DEFAULT_DC, "149.154.167.51"))
            target_port = self.tg_port

            client_tag = None
            if self.user_manager and hasattr(self.user_manager, "get_tag_for_user"):
                client_tag = self.user_manager.get_tag_for_user(matched_user)
            if not client_tag:
                client_tag = self.tag

            tag_info = f"Promo TAG: {client_tag}" if client_tag else "No Promo TAG"
            logger.info(
                f"[MTProto] Client {client_ip} authenticated as '{matched_user}' via {auth_mode} [{tag_info}]! "
                f"Protocol: {proto_tag.hex()}, Target: Telegram DC {dc_num} ({target_dc}:{target_port})"
            )

            # 5. Connect to Telegram DC via rotated/sticky reverse agent for this client (failover to other nodes)
            user_key = f"mtproto:{matched_user}:{ip_only}"
            agent, stream, status = await self.agent_manager.establish_stream(
                target_dc,
                target_port,
                user_key=user_key,
                client_ip=ip_only,
                fast_timeout=max(self.fast_timeout, 4.0),
                total_timeout=max(self.connect_timeout, 20.0),
            )
            if not agent or not stream:
                logger.warning(
                    f"[{client_ip}] [{user_key}] No active socks-reverse agents to route Telegram DC connection (status={status})!"
                )
                return

            stream_id = stream.stream_id
            logger.info(
                f"[MTProto ROUTE] [{client_ip}] [{user_key}] -> Routing MTProto stream #{stream_id} ({auth_mode}) to DC "
                f"{target_dc}:{target_port} via Reverse Agent [{agent.agent_id}]"
            )

            # 6. Generate standard Obfuscated2 handshake to Telegram DC (NO secret)
            while True:
                rnd = bytearray(os.urandom(HANDSHAKE_LEN))
                if rnd[:1] in RESERVED_NONCE_FIRST_CHARS:
                    continue
                if rnd[:4] in RESERVED_NONCE_BEGINNINGS:
                    continue
                if rnd[4:8] in RESERVED_NONCE_CONTINUES:
                    continue
                break

            rnd[PROTO_TAG_POS : PROTO_TAG_POS + 4] = proto_tag

            dc_enc_prekey_and_iv = bytes(rnd[SKIP_LEN : SKIP_LEN + KEY_LEN + IV_LEN])
            dc_dec_prekey_and_iv = bytes(rnd[SKIP_LEN : SKIP_LEN + KEY_LEN + IV_LEN][::-1])

            dc_encryptor = create_aes_ctr(
                dc_enc_prekey_and_iv[:KEY_LEN],
                int.from_bytes(dc_enc_prekey_and_iv[KEY_LEN:], "big"),
            )
            dc_decryptor = create_aes_ctr(
                dc_dec_prekey_and_iv[:KEY_LEN],
                int.from_bytes(dc_dec_prekey_and_iv[KEY_LEN:], "big"),
            )

            # Encrypt tail of DC handshake
            rnd_enc = bytes(rnd[:PROTO_TAG_POS]) + dc_encryptor.update(bytes(rnd))[PROTO_TAG_POS:]

            # Send DC handshake to Telegram DC via reverse agent
            await agent.send_frame(CMD_DATA, stream_id, rnd_enc)

            # 7. Bi-directional data tunneling
            await self._tunnel_traffic(
                stream_reader,
                stream_writer,
                agent,
                stream,
                client_decryptor,
                client_encryptor,
                dc_decryptor,
                dc_encryptor,
                client_ip,
            )

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except Exception as e:
            logger.error(f"[{client_ip}] Error in MTProto handler: {e}", exc_info=True)
        finally:
            if current_task:
                self.active_tasks.discard(current_task)
            self.active_writers.discard(client_writer)
            await safe_close_writer(client_writer, timeout=0.5)

    async def _send_tls_server_hello(
        self,
        writer: asyncio.StreamWriter,
        client_hello: bytes,
        client_digest: bytes,
        raw_secret: Optional[bytes] = None,
    ):
        """Constructs standard TLS 1.3 ServerHello response."""
        sec = raw_secret or self.raw_secret
        TLS_VERS = b"\x03\x03"
        TLS_CIPHERSUITE = b"\x13\x01"
        TLS_CHANGE_CIPHER = b"\x14" + TLS_VERS + b"\x00\x01\x01"
        TLS_APP_HTTP2_HDR = b"\x17" + TLS_VERS

        tls_extensions = (
            b"\x00\x2e"
            + b"\x00\x33\x00\x24"
            + b"\x00\x1d\x00\x20"
            + gen_x25519_public_key()
            + b"\x00\x2b\x00\x02\x03\x04"
        )

        sess_id_len = client_hello[43] if len(client_hello) > 43 else 0
        if sess_id_len > 32 or len(client_hello) < 44 + sess_id_len:
            sess_id_len = min(32, max(0, len(client_hello) - 44))
            sess_id = client_hello[44 : 44 + sess_id_len]
        else:
            sess_id = client_hello[44 : 44 + sess_id_len]

        fake_cert_len = random.randrange(1024, 3072)
        http_data = os.urandom(fake_cert_len)

        srv_hello = TLS_VERS + b"\x00" * 32 + bytes([sess_id_len]) + sess_id
        srv_hello += TLS_CIPHERSUITE + b"\x00" + tls_extensions

        hello_pkt = b"\x16" + TLS_VERS + int.to_bytes(len(srv_hello) + 4, 2, "big")
        hello_pkt += b"\x02" + int.to_bytes(len(srv_hello), 3, "big") + srv_hello
        hello_pkt += TLS_CHANGE_CIPHER + TLS_APP_HTTP2_HDR
        hello_pkt += int.to_bytes(len(http_data), 2, "big") + http_data

        computed_digest = hmac.new(sec, client_digest + hello_pkt, hashlib.sha256).digest()
        hello_pkt = hello_pkt[:11] + computed_digest + hello_pkt[43:]

        writer.write(hello_pkt)
        await writer.drain()

    async def _tunnel_traffic(
        self,
        stream_reader,
        stream_writer,
        agent,
        stream: StreamContext,
        client_decryptor,
        client_encryptor,
        dc_decryptor,
        dc_encryptor,
        client_ip: str,
    ):
        """
        Bidirectionally pipes data between Telegram Client and Telegram DC via Reverse Agent.
        Supports both FakeTLSStreamReader/Writer and raw asyncio StreamReader/StreamWriter (Hex32).
        - Client -> (Unwrap if FakeTLS) -> Client Decrypt -> DC Encrypt -> Reverse Agent -> DC
        - DC -> Reverse Agent -> DC Decrypt -> Client Encrypt -> (Wrap if FakeTLS) -> Client
        """
        stream_id = stream.stream_id
        bytes_up = 0
        bytes_down = 0
        IDLE_TIMEOUT = 300.0  # 5 minutes idle timeout to clean up stale/ghost connections

        async def client_to_dc():
            nonlocal bytes_up
            try:
                while not agent.closed:
                    chunk = await asyncio.wait_for(stream_reader.read(32768), timeout=IDLE_TIMEOUT)
                    if not chunk:
                        break
                    bytes_up += len(chunk)
                    plain = client_decryptor.update(chunk)
                    to_dc = dc_encryptor.update(plain)
                    await agent.send_frame(CMD_DATA, stream_id, to_dc)
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            finally:
                agent.send_frame_nowait(CMD_CLOSE, stream_id)

        async def dc_to_client():
            nonlocal bytes_down
            try:
                while True:
                    chunk = await stream.data_queue.get()
                    if chunk is None:
                        break
                    bytes_down += len(chunk)
                    plain = dc_decryptor.update(chunk)
                    to_client = client_encryptor.update(plain)
                    stream_writer.write(to_client)
                    await stream_writer.drain()
                    stream.data_queue.task_done()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, asyncio.IncompleteReadError):
                pass

        try:
            logger.info(f"[MTProto TUNNEL OPEN] Stream #{stream_id} active: {client_ip} <-> DC {stream.host}:{stream.port}")
            t1 = asyncio.create_task(client_to_dc(), name=f"mtproto-up-{stream_id}")
            t2 = asyncio.create_task(dc_to_client(), name=f"mtproto-down-{stream_id}")
            done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done:
                try:
                    t.exception()
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            agent.remove_stream(stream_id, notify_agent=True)
            agent.send_frame_nowait(CMD_CLOSE, stream_id)
            logger.info(
                f"[MTProto TUNNEL CLOSED] Stream #{stream_id} finished. "
                f"Client sent: {bytes_up} bytes, Telegram DC returned: {bytes_down} bytes"
            )

    async def _handle_bad_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        initial_bytes: bytes,
        client_ip: str,
    ):
        """
        Anti-censorship scanner protection:
        Forward invalid probes to mask_host:mask_port (e.g. google.com:443).
        TSPU / Censorship scanners will see a live, genuine TLS certificate from Google!
        """
        target_writer = None
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(self.mask_host, self.mask_port),
                timeout=5.0,
            )
            if initial_bytes:
                target_writer.write(initial_bytes)
                await target_writer.drain()

            async def pipe_c2t():
                try:
                    while True:
                        data = await client_reader.read(8192)
                        if not data:
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                except Exception:
                    pass
                finally:
                    await safe_close_writer(target_writer, timeout=0.5)

            async def pipe_t2c():
                try:
                    while True:
                        data = await target_reader.read(8192)
                        if not data:
                            break
                        client_writer.write(data)
                        await client_writer.drain()
                except Exception:
                    pass
                finally:
                    await safe_close_writer(client_writer, timeout=0.5)

            t1 = asyncio.create_task(pipe_c2t())
            t2 = asyncio.create_task(pipe_t2c())
            try:
                await asyncio.wait_for(
                    asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                pass
            t1.cancel()
            t2.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
        except Exception:
            pass
        finally:
            if target_writer:
                await safe_close_writer(target_writer, timeout=0.5)
            self.active_writers.discard(client_writer)
            await safe_close_writer(client_writer, timeout=0.5)
