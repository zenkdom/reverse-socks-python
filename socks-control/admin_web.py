"""
HTTP Admin Panel for socks-control.
Runs on port 9001.
Provides a modern web UI and REST endpoints to manage SOCKS5 client credentials
and monitor connected reverse agents.
"""
from __future__ import annotations

import asyncio
import base64
import html
import json
import logging
import secrets
import time
import urllib.parse
from typing import Optional
from agent_manager import AgentManager
from socks_users import UserManager
from protocol import safe_close_writer, enable_socket_keepalive

logger = logging.getLogger("AdminWeb")


class AdminWebServer:
    def __init__(
        self,
        agent_manager: AgentManager,
        user_manager: UserManager,
        host: str = "0.0.0.0",
        port: int = 9001,
        admin_user: str = "admin",
        admin_pass: str = "changeme",
        socks5_port: int = 1080,
        mtproto_port: Optional[int] = 8443,
        mtproto_secret: Optional[str] = None,
        mtproto_domain: Optional[str] = "google.com",
        mtproto_tag: Optional[str] = None,
        mtproto_user_manager=None,
    ):
        self.agent_manager = agent_manager
        self.user_manager = user_manager
        self.host = host
        self.port = port
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.socks5_port = socks5_port
        self.mtproto_port = mtproto_port
        self.mtproto_secret = mtproto_secret
        self.mtproto_domain = mtproto_domain
        self.mtproto_tag = mtproto_tag
        self.mtproto_user_manager = mtproto_user_manager

        self.server: Optional[asyncio.Server] = None
        self.sessions: dict[str, float] = {}  # session_token -> expiry_time
        self.active_tasks: set[asyncio.Task] = set()
        self.active_writers: set[asyncio.StreamWriter] = set()
        self.closed = False

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_http_client,
            host=self.host,
            port=self.port,
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"[*] Admin Web Panel listening on {addrs} (User: {self.admin_user})")

    async def stop(self):
        self.closed = True
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
            except Exception:
                pass

        for writer in list(self.active_writers):
            try:
                writer.close()
            except Exception:
                pass
        self.active_writers.clear()

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
        logger.info("Admin Web Panel stopped.")

    async def _handle_http_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self.closed:
            try:
                writer.close()
            except Exception:
                pass
            return

        current_task = asyncio.current_task()
        if current_task:
            self.active_tasks.add(current_task)
        self.active_writers.add(writer)

        enable_socket_keepalive(writer)

        try:
            async def _read_http_request():
                # 1. Read request line
                req_line = await reader.readline()
                if not req_line:
                    return None

                parts = req_line.decode("utf-8", errors="ignore").strip().split()
                if len(parts) < 2:
                    return None

                method = parts[0].upper()
                full_path = parts[1]

                # Parse path and query
                url_parts = urllib.parse.urlparse(full_path)
                path = url_parts.path
                query_params = urllib.parse.parse_qs(url_parts.query)

                # 2. Read headers
                headers = {}
                while True:
                    line = await reader.readline()
                    if not line or line in (b"\r\n", b"\n"):
                        break
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if ":" in line_str:
                        k, v = line_str.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

                # 3. Read body if present
                body = b""
                content_length = int(headers.get("content-length", 0))
                if content_length > 0:
                    if content_length > 10 * 1024 * 1024:
                        return None
                    body = await reader.readexactly(content_length)

                return method, full_path, path, query_params, headers, body

            # Guard entire HTTP reading with 15s timeout to prevent idle scanner leaks
            req = await asyncio.wait_for(_read_http_request(), timeout=15.0)
            if not req:
                return

            method, full_path, path, query_params, headers, body = req

            # 4. Check Authentication
            is_authenticated = self._check_auth(headers)

            # Route handling
            if path == "/login":
                if method == "POST":
                    await self._route_login_post(writer, body)
                else:
                    await self._route_login_get(writer, query_params)
            elif path == "/logout":
                await self._route_logout(writer, headers)
            elif not is_authenticated:
                # If API request or basic auth requested, return 401
                if path.startswith("/api/"):
                    self._send_response(
                        writer,
                        401,
                        "application/json",
                        b'{"error": "Unauthorized"}',
                        headers={"WWW-Authenticate": 'Basic realm="Socks Admin"'},
                    )
                else:
                    self._send_redirect(writer, "/login")
            else:
                # Authenticated routes
                if path == "/" or path == "/dashboard":
                    await self._route_dashboard(writer, query_params)
                elif path == "/users/add" and method == "POST":
                    await self._route_add_user(writer, body)
                elif path == "/users/delete" and method == "POST":
                    await self._route_delete_user(writer, body)
                elif path == "/mtproto/add" and method == "POST":
                    await self._route_add_mtproto_client(writer, body)
                elif path == "/mtproto/set_tag" and method == "POST":
                    await self._route_set_mtproto_tag(writer, body)
                elif path == "/mtproto/delete" and method == "POST":
                    await self._route_delete_mtproto_client(writer, body)
                elif path == "/api/status":
                    await self._route_api_status(writer)
                else:
                    self._send_response(writer, 404, "text/plain", b"404 Not Found")

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except Exception as e:
            logger.error(f"Error handling HTTP admin request: {e}", exc_info=True)
            try:
                self._send_response(writer, 500, "text/plain", b"500 Internal Server Error")
            except Exception:
                pass
        finally:
            if current_task:
                self.active_tasks.discard(current_task)
            self.active_writers.discard(writer)
            await safe_close_writer(writer, timeout=0.5)

    def _check_auth(self, headers: dict) -> bool:
        """Verify cookie session or HTTP Basic Auth header."""
        # Check Basic Auth header
        auth_header = headers.get("authorization", "")
        if auth_header.startswith("Basic "):
            try:
                encoded = auth_header[6:].strip()
                decoded = base64.b64decode(encoded).decode("utf-8")
                user, passwd = decoded.split(":", 1)
                if user == self.admin_user and passwd == self.admin_pass:
                    return True
            except Exception:
                pass

        # Check Cookie session
        cookie_header = headers.get("cookie", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(";")]
            for cookie in cookies:
                if cookie.startswith("admin_session="):
                    token = cookie.split("=", 1)[1]
                    expiry = self.sessions.get(token)
                    if expiry and expiry > time.time():
                        return True
                    elif token in self.sessions:
                        del self.sessions[token]
        return False

    async def _route_login_get(self, writer: asyncio.StreamWriter, query_params: dict):
        error = query_params.get("error", [""])[0]
        error_html = (
            f'<div class="alert error">{html.escape(error)}</div>'
            if error
            else ""
        )

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In | SOCKS5 Control Admin</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
body {{ background-color: #0f172a; color: #f8fafc; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
.card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; color: #6366f1; text-align: center; }}
p.sub {{ color: #94a3b8; font-size: 14px; text-align: center; margin-bottom: 24px; }}
.form-group {{ margin-bottom: 18px; }}
label {{ display: block; font-size: 13px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }}
input {{ width: 100%; padding: 10px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #f8fafc; font-size: 14px; }}
input:focus {{ outline: none; border-color: #6366f1; ring: 2px #6366f1; }}
button {{ width: 100%; padding: 12px; background: #6366f1; color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; }}
button:hover {{ background: #4f46e5; }}
.alert {{ padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 18px; }}
.alert.error {{ background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }}
</style>
</head>
<body>
<div class="card">
  <h1>SOCKS5 Control</h1>
  <p class="sub">Server Administration Dashboard</p>
  {error_html}
  <form method="POST" action="/login">
    <div class="form-group">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="username" autofocus>
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
    </div>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>"""
        self._send_response(writer, 200, "text/html; charset=utf-8", content.encode("utf-8"))

    async def _route_login_post(self, writer: asyncio.StreamWriter, body: bytes):
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        username = form_data.get("username", [""])[0]
        password = form_data.get("password", [""])[0]

        if username == self.admin_user and password == self.admin_pass:
            # Generate session token
            token = secrets.token_hex(24)
            self.sessions[token] = time.time() + 86400  # 24 hours
            self._send_redirect(
                writer,
                "/",
                cookies=[f"admin_session={token}; Path=/; HttpOnly; SameSite=Lax"],
            )
        else:
            self._send_redirect(writer, "/login?error=" + urllib.parse.quote("Invalid username or password"))

    async def _route_logout(self, writer: asyncio.StreamWriter, headers: dict):
        cookie_header = headers.get("cookie", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(";")]
            for cookie in cookies:
                if cookie.startswith("admin_session="):
                    token = cookie.split("=", 1)[1]
                    self.sessions.pop(token, None)
        self._send_redirect(
            writer,
            "/login",
            cookies=["admin_session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        )

    async def _route_dashboard(self, writer: asyncio.StreamWriter, query_params: dict):
        msg = query_params.get("msg", [""])[0]
        error = query_params.get("error", [""])[0]

        notification_html = ""
        if msg:
            notification_html = f'<div class="alert success">{html.escape(msg)}</div>'
        elif error:
            notification_html = f'<div class="alert error">{html.escape(error)}</div>'

        agents = self.agent_manager.get_agent_status_list()
        users = self.user_manager.get_all_users()

        # Agents table rows
        agents_rows = ""
        if not agents:
            agents_rows = '<tr><td colspan="6" class="empty">No active reverse nodes. Connect a socks-reverse node сервер.</td></tr>'
        else:
            for a in agents:
                uptime = self._format_duration(a["uptime_seconds"])
                is_last_badge = '<span class="badge" style="background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid #6366f1;">ПОСЛЕДНЯЯ</span>' if a.get("is_last_used") else ""
                if a.get("is_faketls"):
                    sni = a.get("sni_domain") or "google.com"
                    transport_badge = f'<span class="badge active" style="font-size:10px; background:rgba(99,102,241,0.2); color:#818cf8; border:1px solid #6366f1;">🔒 Fake-TLS ({html.escape(sni)})</span>'
                else:
                    transport_badge = '<span class="badge" style="font-size:10px; background:#1e293b; color:#94a3b8; border:1px solid #334155;">PLAIN TCP</span>'

                exit_ip = a.get("exit_ip")
                if exit_ip and exit_ip != a['remote_ip']:
                    ip_display = f"<code>{html.escape(exit_ip)}</code> <span style='font-size:10px; color:#34d399; font-weight:600;'>✓ Exit IP</span><br><span style='font-size:11px; color:#64748b;'>Шлюз: {html.escape(a['remote_ip'])}</span>"
                else:
                    ip_display = f"<code>{html.escape(a['remote_ip'])}</code>"

                agents_rows += f"""<tr>
                  <td><span class="badge active">ONLINE</span> {is_last_badge}<strong>{html.escape(a['agent_id'])}</strong></td>
                  <td>{transport_badge}</td>
                  <td>{ip_display}</td>
                  <td>{uptime}</td>
                  <td>{a['active_connections']}</td>
                  <td>{a['total_handled']}</td>
                </tr>"""

        # Users table rows
        users_rows = ""
        if not users:
            users_rows = '<tr><td colspan="5" class="empty">User list is empty. Add a new user below.</td></tr>'
        else:
            for u in users:
                uname = u['username']
                u_state = self.agent_manager.user_states.get(f"socks:{uname}")
                last_node = (
                    f"<span class='badge' style='background:rgba(99,102,241,0.2); color:#818cf8; border:1px solid #6366f1;'>"
                    f"{html.escape(u_state.last_successful_agent_id)}</span>"
                    if (u_state and u_state.last_successful_agent_id)
                    else "<span style='color:#64748b;'>—</span>"
                )
                req_count = u_state.total_requests if u_state else 0
                users_rows += f"""<tr>
                  <td><strong>{html.escape(uname)}</strong></td>
                  <td><code>{html.escape(u['password'])}</code></td>
                  <td>{last_node} <span style="font-size:11px; color:#94a3b8;">({req_count} reqs)</span></td>
                  <td>{html.escape(u.get('created_at', '-'))}</td>
                  <td>
                    <form method="POST" action="/users/delete" style="display:inline;" onsubmit="return confirm('Delete user {html.escape(uname)}?');">
                      <input type="hidden" name="username" value="{html.escape(uname)}">
                      <button type="submit" class="btn-danger">Delete</button>
                    </form>
                  </td>
                </tr>"""

        # MTProto clients table rows
        mtproto_clients = self.mtproto_user_manager.get_all_clients() if self.mtproto_user_manager else []
        mtproto_clients_rows = ""
        if not mtproto_clients:
            mtproto_clients_rows = '<tr><td colspan="7" class="empty">MTProto client list is empty. Create a new client below.</td></tr>'
        else:
            for c in mtproto_clients:
                raw_c_name = c.get("client_name", "")
                c_name = html.escape(raw_c_name)
                c_secret = html.escape(c.get("secret", ""))
                c_fake_tls = html.escape(c.get("fake_tls_secret", ""))
                raw_c_tag = c.get("tag") or ""
                c_tag = html.escape(raw_c_tag)
                c_created = html.escape(c.get("created_at", "-"))
                c_state = self.agent_manager.user_states.get(f"mtproto:{raw_c_name}")
                last_node = (
                    f"<span class='badge' style='background:rgba(16,185,129,0.2); color:#34d399; border:1px solid #10b981;'>"
                    f"{html.escape(c_state.last_successful_agent_id)}</span>"
                    if (c_state and c_state.last_successful_agent_id)
                    else "<span style='color:#64748b;'>—</span>"
                )
                req_count = c_state.total_requests if c_state else 0
                tag_badge = (
                    f'<span class="badge active" style="font-size:9px; background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid #f59e0b;">✓ TAG АКТИВЕН</span>'
                    if raw_c_tag
                    else '<span style="font-size:10px; color:#64748b;">No TAG attached</span>'
                )
                mtproto_clients_rows += f"""<tr>
                  <td><span class="badge active" style="font-size:10px;">TG</span> <strong>{c_name}</strong></td>
                  <td><code style="font-size:12px; color:#38bdf8;">{c_secret}</code></td>
                  <td><code style="color:#34d399; font-size:11px;">{c_fake_tls}</code></td>
                  <td>
                    <form method="POST" action="/mtproto/set_tag" style="display:flex; gap:4px; align-items:center;">
                      <input type="hidden" name="client_name" value="{c_name}">
                      <input type="text" name="tag" value="{c_tag}" placeholder="32 hex bot tag" style="width:160px; padding:4px 6px; font-size:11px; background:#0f172a; border:1px solid #334155; border-radius:4px; color:#fbbf24; font-family:monospace;" title="32-значный hex TAG промо-канала из @MTProxybot">
                      <button type="submit" class="btn-primary" style="padding:4px 7px; font-size:11px; background:#f59e0b; color:#0f172a; font-weight:700;" title="Сохранить TAG промо-канала">💾</button>
                    </form>
                    <div style="margin-top:2px;">{tag_badge}</div>
                  </td>
                  <td>{last_node} <span style="font-size:11px; color:#94a3b8;">({req_count} reqs)</span></td>
                  <td>{c_created}</td>
                  <td style="white-space:nowrap;">
                    <div style="display:flex; flex-direction:column; gap:4px;">
                      <div style="display:flex; gap:4px;">
                        <button type="button" class="btn-primary" style="background:#10b981; font-size:11px; padding:4px 8px; cursor:pointer;" title="Подключиться в Telegram через Fake-TLS (обход ТСПУ/DPI)" onclick="openTgForSecret('{c_fake_tls}')">🚀 Fake-TLS</button>
                        <button type="button" class="btn-primary" style="background:#0284c7; font-size:11px; padding:4px 8px; cursor:pointer;" title="Подключиться в Telegram по Hex32 (классический MTProto)" onclick="openTgForSecret('{c_secret}')">🚀 Hex32</button>
                      </div>
                      <div style="display:flex; gap:4px; align-items:center;">
                        <button type="button" class="btn-primary" style="background:#334155; font-size:11px; padding:4px 7px; cursor:pointer;" title="Скопировать ссылку Fake-TLS" onclick="copyTgForSecret('{c_fake_tls}', 'Fake-TLS')">📋 Fake-TLS</button>
                        <button type="button" class="btn-primary" style="background:#1e293b; border:1px solid #475569; font-size:11px; padding:4px 7px; cursor:pointer;" title="Скопировать ссылку Hex32" onclick="copyTgForSecret('{c_secret}', 'Hex32')">📋 Hex32</button>
                        <form method="POST" action="/mtproto/delete" style="display:inline; margin-left:auto;" onsubmit="return confirm('Удалить MTProto клиента {c_name}?');">
                          <input type="hidden" name="client_name" value="{c_name}">
                          <button type="submit" class="btn-danger" style="padding:4px 8px; font-size:11px;" title="Delete client">✕</button>
                        </form>
                      </div>
                    </div>
                  </td>
                </tr>"""

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOCKS5 Control Admin Panel</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
body {{ background-color: #0f172a; color: #f8fafc; min-height: 100vh; padding: 24px 20px; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #334155; }}
.brand {{ display: flex; align-items: center; gap: 12px; }}
.brand h1 {{ font-size: 22px; font-weight: 700; color: #6366f1; }}
.header-actions {{ display: flex; align-items: center; gap: 14px; }}
.user-badge {{ font-size: 13px; color: #94a3b8; background: #1e293b; padding: 6px 12px; border-radius: 6px; border: 1px solid #334155; }}
.btn-logout {{ text-decoration: none; font-size: 13px; color: #f43f5e; background: rgba(244, 63, 94, 0.1); border: 1px solid #f43f5e; padding: 6px 12px; border-radius: 6px; font-weight: 600; transition: background 0.2s; }}
.btn-logout:hover {{ background: rgba(244, 63, 94, 0.25); }}

.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; }}
.stat-title {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 6px; }}
.stat-value {{ font-size: 28px; font-weight: 800; color: #f8fafc; }}
.stat-desc {{ font-size: 12px; color: #64748b; margin-top: 4px; }}

.card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 22px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
.card-title {{ font-size: 17px; font-weight: 700; margin-bottom: 16px; color: #cbd5e1; display: flex; justify-content: space-between; align-items: center; }}

table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
th {{ background: #0f172a; padding: 12px 14px; font-size: 12px; text-transform: uppercase; color: #94a3b8; border-bottom: 1px solid #334155; }}
td {{ padding: 12px 14px; border-bottom: 1px solid #334155; color: #e2e8f0; }}
tr:last-child td {{ border-bottom: none; }}
.empty {{ text-align: center; color: #64748b; padding: 24px 0; }}
code {{ font-family: monospace; background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #38bdf8; font-size: 13px; }}

.badge {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 3px 6px; border-radius: 4px; margin-right: 6px; vertical-align: middle; }}
.badge.active {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}

.form-inline {{ display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; align-items: flex-end; }}
.form-group label {{ display: block; font-size: 12px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; }}
.form-group input {{ width: 100%; padding: 9px 12px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; font-size: 14px; }}
.btn-primary {{ padding: 9px 18px; background: #6366f1; color: white; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; }}
.btn-primary:hover {{ background: #4f46e5; }}
.btn-danger {{ padding: 5px 10px; background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid #f43f5e; border-radius: 4px; font-size: 12px; font-weight: 600; cursor: pointer; transition: background 0.2s; }}
.btn-danger:hover {{ background: rgba(244, 63, 94, 0.3); }}

.alert {{ padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 20px; }}
.alert.success {{ background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #6ee7b7; }}
.alert.error {{ background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }}

.help-box {{ background: #0f172a; border-left: 4px solid #6366f1; padding: 14px 18px; border-radius: 0 8px 8px 0; font-size: 13px; color: #94a3b8; line-height: 1.6; margin-top: 14px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <h1>SOCKS5 Reverse Cluster</h1>
    </div>
    <div class="header-actions">
      <span class="user-badge">Admin: <strong>{html.escape(self.admin_user)}</strong></span>
      <a href="/logout" class="btn-logout">Sign Out</a>
    </div>
  </header>

  {notification_html}

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-title">Active Reverse Nodes</div>
      <div class="stat-value">{len(agents)}</div>
      <div class="stat-desc">Online exit servers</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">SOCKS5 Users</div>
      <div class="stat-value">{len(users)}</div>
      <div class="stat-desc">Authorized accounts</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">SOCKS5 Port</div>
      <div class="stat-value">{self.socks5_port}</div>
      <div class="stat-desc">Authentication: <strong>REQUIRED</strong></div>
    </div>
    <div class="stat-card" style="border-color: rgba(16, 185, 129, 0.4);">
      <div class="stat-title" style="color: #34d399;">Telegram MTProto</div>
      <div class="stat-value" style="color: #34d399;">{self.mtproto_port}</div>
      <div class="stat-desc">Fake-TLS: <strong>{html.escape(self.mtproto_domain or "google.com")}</strong></div>
    </div>
    <div class="stat-card">
      <div class="stat-title">Load Balancing</div>
      <div class="stat-value">{self.agent_manager.strategy.upper()}</div>
      <div class="stat-desc">{"Per-user rotation (2s failover)" if self.agent_manager.strategy in ("rotation", "round_robin") else "Случайный выбор ноды"}</div>
    </div>
  </div>

  <div class="card" style="border: 1px solid #10b981; background: linear-gradient(180deg, #1e293b 0%, rgba(16, 185, 129, 0.08) 100%);">
    <div class="card-title" style="color: #34d399;">
      <span>⚡ Telegram MTProto Proxy (Fake-TLS) — Клиенты ({len(mtproto_clients)})</span>
      <span class="badge active" style="font-size:11px; padding:4px 8px;">DPI & FIREWALL BYPASS</span>
    </div>
    <p style="font-size: 13px; color: #94a3b8; margin-bottom: 14px; line-height: 1.5;">
      Proxy masquerades Telegram traffic as genuine HTTPS / TLS 1.3 to <code>{html.escape(self.mtproto_domain or "google.com")}</code>.
      Каждый клиент подключается по своему индивидуальному Secret Key. Все запросы выводятся в интернет через ваши <strong>Reverse Ноды</strong>.
    </p>

    <div style="background: #0f172a; border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; font-family: monospace; font-size: 13px; border: 1px solid #334155;">
      <strong style="color:#e2e8f0;">MTProto Port:</strong> <code style="color:#38bdf8;">{self.mtproto_port}</code> &nbsp;|&nbsp;
      <strong style="color:#e2e8f0;">Masked SNI:</strong> <code style="color:#38bdf8;">{html.escape(self.mtproto_domain or "google.com")}</code>
    </div>

    <table>
      <thead>
        <tr>
          <th>MTProto Client</th>
          <th>Secret Key (Raw Hex)</th>
          <th>Fake-TLS Secret (Telegram)</th>
          <th>Promo TAG (@MTProxybot)</th>
          <th>Current Rotation</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {mtproto_clients_rows}
      </tbody>
    </table>

    <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid #334155;">
      <h3 style="font-size: 14px; margin-bottom: 10px; color: #cbd5e1;">Add New MTProto Client:</h3>
      <form method="POST" action="/mtproto/add" class="form-inline" style="grid-template-columns: 1fr 1fr 1fr auto;">
        <div class="form-group">
          <label for="mtproto_client_name">Client / Device Name</label>
          <input type="text" id="mtproto_client_name" name="client_name" placeholder="e.g. alex_phone" required>
        </div>
        <div class="form-group">
          <label for="mtproto_secret_key">Secret Key (32 hex or blank)</label>
          <input type="text" id="mtproto_secret_key" name="secret" placeholder="leave blank for auto-generate">
        </div>
        <div class="form-group">
          <label for="mtproto_tag_input">TAG from @MTProxybot (optional)</label>
          <input type="text" id="mtproto_tag_input" name="tag" placeholder="e.g. 96bd93d09a01f79d...">
        </div>
        <button type="submit" class="btn-primary" style="background:#10b981;">+ Create Client</button>
      </form>
    </div>

    <div class="help-box" style="margin-top: 16px;">
      <strong>📢 Sponsor Channel Configuration:</strong><br>
      • В поле <strong>Промо-тег (TAG)</strong> введите выданный ботом <strong>@MTProxybot</strong> 32-значный hex-тег (например: <code>96bd93d09a01f79d01c8d3e4cd5d5c26</code>) и нажмите <strong>💾</strong>.<br>
      • Промо-канал будет закреплён в самом верху чатов Telegram с отметкой <em>«Спонсор прокси»</em> для всех пользователей, подключенных через этот прокси.<br>
      • <strong>Двойной режим:</strong> Прокси на порту <code>{self.mtproto_port}</code> поддерживает подключение как по <strong>Fake-TLS</strong> (обход блокировок ТСПУ), так и по чистому <strong>Hex32</strong> (для ботов и стандартных клиентов).
    </div>

    <script>
      function openTgForSecret(secret) {{
        var hostIp = window.location.hostname;
        var port = '{self.mtproto_port}';
        var tgUrl = 'tg://proxy?server=' + hostIp + '&port=' + port + '&secret=' + secret;
        window.location.href = tgUrl;
      }}
      function copyTgForSecret(secret, typeName) {{
        var hostIp = window.location.hostname;
        var port = '{self.mtproto_port}';
        var tgUrl = 'tg://proxy?server=' + hostIp + '&port=' + port + '&secret=' + secret;
        navigator.clipboard.writeText(tgUrl);
        var label = typeName ? ' (' + typeName + ')' : '';
        alert('Telegram proxy connect link' + label + ' copied to clipboard!\\n\\n' + tgUrl);
      }}
    </script>
  </div>

  <div class="card">
    <div class="card-title">
      <span>Connected Reverse Servers ({len(agents)})</span>
      <span style="font-size:12px; font-weight:normal; color:#94a3b8;">Auto-refreshes in real time</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Node (Agent ID)</th>
          <th>Transport</th>
          <th>External IP / Address</th>
          <th>Uptime</th>
          <th>Active Connections</th>
          <th>Total Relayed</th>
        </tr>
      </thead>
      <tbody>
        {agents_rows}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">
      <span>SOCKS5 Users ({len(users)})</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Password</th>
          <th>Current Rotation</th>
          <th>Added</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {users_rows}
      </tbody>
    </table>

    <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid #334155;">
      <h3 style="font-size: 15px; margin-bottom: 12px; color: #cbd5e1;">Add New SOCKS5 User:</h3>
      <form method="POST" action="/users/add" class="form-inline">
        <div class="form-group">
          <label for="new_username">Username</label>
          <input type="text" id="new_username" name="username" placeholder="e.g. client1" required>
        </div>
        <div class="form-group">
          <label for="new_password">Password</label>
          <input type="text" id="new_password" name="password" placeholder="e.g. pass12345" required>
        </div>
        <button type="submit" class="btn-primary">+ Add User</button>
      </form>
    </div>

    <div class="help-box">
      <strong>Universal Multi-Protocol Proxy (порт {self.socks5_port}):</strong><br>
      • <strong>SOCKS5 (TCP + UDP):</strong> поддерживает TCP (CONNECT), UDP (UDP ASSOCIATE для звонков Telegram, DNS, игр, WebRTC, QUIC), и TCP BIND.<br>
      • <strong>SOCKS4 / SOCKS4a:</strong> <code>curl --socks4a ЛОГИН@IP:{self.socks5_port} http://...</code><br>
      • <strong>HTTP / HTTPS Proxy:</strong> <code>curl -x http://ЛОГИН:ПАРОЛЬ@IP:{self.socks5_port} https://...</code> (CONNECT и обычный HTTP proxy).<br>
      • <strong>Telegram / Браузер:</strong> укажите SOCKS5, порт <code>{self.socks5_port}</code>, логин и пароль. Звонки Telegram работают через UDP ASSOCIATE!<br>
      • <strong>Безопасность:</strong> запросы без логина/пароля или с неверными данными строго отклоняются.
    </div>
  </div>
</div>
</body>
</html>"""
        self._send_response(writer, 200, "text/html; charset=utf-8", content.encode("utf-8"))

    async def _route_add_user(self, writer: asyncio.StreamWriter, body: bytes):
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        username = form_data.get("username", [""])[0].strip()
        password = form_data.get("password", [""])[0].strip()

        success, message = await self.user_manager.add_user(username, password)
        if success:
            self._send_redirect(writer, "/?msg=" + urllib.parse.quote(message))
        else:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote(message))

    async def _route_delete_user(self, writer: asyncio.StreamWriter, body: bytes):
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        username = form_data.get("username", [""])[0].strip()

        success, message = await self.user_manager.delete_user(username)
        if success:
            self._send_redirect(writer, "/?msg=" + urllib.parse.quote(message))
        else:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote(message))

    async def _route_add_mtproto_client(self, writer: asyncio.StreamWriter, body: bytes):
        if not self.mtproto_user_manager:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote("MTProto manager is not configured"))
            return
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        client_name = form_data.get("client_name", [""])[0].strip()
        secret = form_data.get("secret", [""])[0].strip()
        tag = form_data.get("tag", [""])[0].strip()

        success, message, _ = await self.mtproto_user_manager.add_client(client_name, secret, tag=tag)
        if success:
            self._send_redirect(writer, "/?msg=" + urllib.parse.quote(message))
        else:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote(message))

    async def _route_set_mtproto_tag(self, writer: asyncio.StreamWriter, body: bytes):
        if not self.mtproto_user_manager:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote("MTProto manager is not configured"))
            return
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        client_name = form_data.get("client_name", [""])[0].strip()
        tag = form_data.get("tag", [""])[0].strip()

        success, message = await self.mtproto_user_manager.update_client_tag(client_name, tag)
        if success:
            self._send_redirect(writer, "/?msg=" + urllib.parse.quote(message))
        else:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote(message))

    async def _route_delete_mtproto_client(self, writer: asyncio.StreamWriter, body: bytes):
        if not self.mtproto_user_manager:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote("MTProto manager is not configured"))
            return
        form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
        client_name = form_data.get("client_name", [""])[0].strip()

        success, message = await self.mtproto_user_manager.delete_client(client_name)
        if success:
            self._send_redirect(writer, "/?msg=" + urllib.parse.quote(message))
        else:
            self._send_redirect(writer, "/?error=" + urllib.parse.quote(message))

    async def _route_api_status(self, writer: asyncio.StreamWriter):
        data = {
            "agents": self.agent_manager.get_agent_status_list(),
            "users": [u["username"] for u in self.user_manager.get_all_users()],
            "mtproto_clients": [
                c["client_name"]
                for c in (self.mtproto_user_manager.get_all_clients() if self.mtproto_user_manager else [])
            ],
            "socks5_port": self.socks5_port,
            "mtproto_port": self.mtproto_port,
        }
        content = json.dumps(data, indent=2).encode("utf-8")
        self._send_response(writer, 200, "application/json", content)

    def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        content_type: str,
        body: bytes,
        headers: Optional[dict] = None,
        cookies: Optional[list[str]] = None,
    ):
        status_text = {
            200: "OK",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            404: "Not Found",
            500: "Internal Server Error",
        }.get(status_code, "OK")

        lines = [
            f"HTTP/1.1 {status_code} {status_text}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        if cookies:
            for c in cookies:
                lines.append(f"Set-Cookie: {c}")

        header_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        writer.write(header_bytes + body)

    def _send_redirect(self, writer: asyncio.StreamWriter, location: str, cookies: Optional[list[str]] = None):
        self._send_response(
            writer,
            302,
            "text/plain",
            b"",
            headers={"Location": location},
            cookies=cookies,
        )

    def _format_duration(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m {seconds % 60}s"
        hours = minutes // 60
        return f"{hours}h {minutes % 60}m"
