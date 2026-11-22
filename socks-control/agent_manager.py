"""
Agent Manager for Reverse SOCKS Control Server.
Manages connected reverse agents, multiplexed streams, and load-balancing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import Optional
from protocol import (
    CMD_CONNECT_REQ,
    CMD_CONNECT_RESP,
    CMD_DATA,
    CMD_CLOSE,
    CMD_PING,
    CMD_PONG,
    CMD_UDP_DATA,
    STATUS_SUCCESS,
    STATUS_GENERAL_FAILURE,
    STATUS_HOST_UNREACHABLE,
    STATUS_TIMEOUT,
    pack_frame,
    pack_json,
    safe_close_writer,
)

logger = logging.getLogger("AgentManager")


class StreamContext:
    """Represents an active SOCKS5 proxy session stream (TCP or UDP)."""

    def __init__(self, stream_id: int, host: str, port: int, agent_id: str, proto: str = "tcp"):
        self.stream_id = stream_id
        self.host = host
        self.port = port
        self.agent_id = agent_id
        self.proto = proto
        self.connect_event = asyncio.Event()
        self.connect_status = STATUS_GENERAL_FAILURE
        self.connect_error = ""
        self.data_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.udp_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.closed = False
        self.created_at = time.time()

    def mark_connected(self, status: int, error: str = ""):
        self.connect_status = status
        self.connect_error = error
        self.connect_event.set()

    def close(self):
        if not self.closed:
            self.closed = True
            # Enqueue None as EOF sentinel for consumers
            try:
                self.data_queue.put_nowait(None)
            except Exception:
                pass
            try:
                self.udp_queue.put_nowait(None)
            except Exception:
                pass


class AgentSession:
    """Represents a connection from a single socks-reverse agent."""

    def __init__(
        self,
        agent_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_ip: str,
        is_faketls: bool = False,
        sni_domain: str = "",
        exit_ip: str = "",
    ):
        self.agent_id = agent_id
        self.reader = reader
        self.writer = writer
        self.remote_ip = remote_ip
        self.is_faketls = is_faketls
        self.sni_domain = sni_domain
        self.exit_ip = exit_ip
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.streams: dict[int, StreamContext] = {}
        self.send_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.writer_task: Optional[asyncio.Task] = None
        self.active_connections_count = 0
        self.total_connections_handled = 0
        self.closed = False
        self.consecutive_failures = 0
        self.last_failure_time = 0.0

    def record_success(self):
        self.consecutive_failures = 0

    def record_failure(self):
        self.consecutive_failures += 1
        self.last_failure_time = time.time()

    def is_healthy(self, cooldown: float = 30.0) -> bool:
        if self.closed:
            return False
        if self.consecutive_failures == 0:
            return True
        return (time.time() - self.last_failure_time) > cooldown

    def start_writer(self):
        """Start the background writer task to flush frames sequentially."""
        self.writer_task = asyncio.create_task(self._writer_loop(), name=f"writer-{self.agent_id}")

    async def _writer_loop(self):
        try:
            while not self.closed:
                frame = await self.send_queue.get()
                if frame is None:
                    break
                self.writer.write(frame)
                await self.writer.drain()
                self.send_queue.task_done()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.warning(f"[{self.agent_id}] Writer error: {e}")
        finally:
            self.closed = True

    async def send_frame(self, cmd: int, stream_id: int, payload: bytes = b""):
        """Queue a binary frame for sending."""
        if self.closed:
            return
        frame = pack_frame(cmd, stream_id, payload)
        try:
            await self.send_queue.put(frame)
        except asyncio.CancelledError:
            pass

    def send_frame_nowait(self, cmd: int, stream_id: int, payload: bytes = b""):
        """Queue a binary frame without awaiting, ideal for high-throughput UDP datagrams."""
        if self.closed:
            return
        frame = pack_frame(cmd, stream_id, payload)
        try:
            self.send_queue.put_nowait(frame)
        except Exception:
            pass

    async def send_json(self, cmd: int, stream_id: int, data: dict):
        """Queue a JSON frame for sending."""
        if self.closed:
            return
        frame = pack_json(cmd, stream_id, data)
        try:
            await self.send_queue.put(frame)
        except asyncio.CancelledError:
            pass

    def register_stream(self, stream: StreamContext):
        self.streams[stream.stream_id] = stream
        self.active_connections_count += 1
        self.total_connections_handled += 1

    def remove_stream(self, stream_id: int, notify_agent: bool = True):
        stream = self.streams.pop(stream_id, None)
        if stream:
            self.active_connections_count = max(0, self.active_connections_count - 1)
            stream.close()
            if notify_agent and not self.closed:
                self.send_frame_nowait(CMD_CLOSE, stream_id)

    def handle_incoming_frame(self, cmd: int, stream_id: int, payload: bytes):
        """Dispatch frames received from this agent."""
        self.last_seen = time.time()

        if cmd == CMD_CONNECT_RESP:
            stream = self.streams.get(stream_id)
            if stream:
                try:
                    data = json.loads(payload.decode("utf-8"))
                    status = data.get("status", STATUS_GENERAL_FAILURE)
                    error = data.get("error", "")
                except Exception:
                    status = STATUS_GENERAL_FAILURE
                    error = "Failed to parse connect response"
                stream.mark_connected(status, error)

        elif cmd == CMD_DATA:
            stream = self.streams.get(stream_id)
            if stream and not stream.closed:
                try:
                    stream.data_queue.put_nowait(payload)
                except asyncio.QueueFull:
                    logger.warning(f"[{self.agent_id}] Stream {stream_id} buffer overflow, dropping packet")

        elif cmd == CMD_UDP_DATA:
            stream = self.streams.get(stream_id)
            if stream and not stream.closed:
                try:
                    stream.udp_queue.put_nowait(payload)
                except asyncio.QueueFull:
                    logger.warning(f"[{self.agent_id}] Stream {stream_id} UDP buffer overflow, dropping packet")

        elif cmd == CMD_CLOSE:
            self.remove_stream(stream_id, notify_agent=False)

        elif cmd == CMD_PING:
            asyncio.create_task(self.send_frame(CMD_PONG, 0))

        elif cmd == CMD_PONG:
            pass

    async def close(self):
        """Gracefully close agent session and all of its active streams."""
        if self.closed:
            return
        self.closed = True
        logger.info(f"[{self.agent_id}] Disconnecting agent from {self.remote_ip}")

        # Close all active streams
        for stream_id, stream in list(self.streams.items()):
            stream.mark_connected(STATUS_GENERAL_FAILURE, "Agent disconnected")
            stream.close()
        self.streams.clear()

        # Stop writer
        try:
            self.send_queue.put_nowait(None)
        except Exception:
            pass

        if self.writer_task and not self.writer_task.done():
            self.writer_task.cancel()

        await safe_close_writer(self.writer, timeout=0.5)


class UserRotationState:
    """Tracks independent rotation and fallback state for a specific user/client."""

    def __init__(self, user_key: str):
        self.user_key = user_key
        self.rr_index = 0
        self.last_assigned_agent_id: Optional[str] = None
        self.last_successful_agent_id: Optional[str] = None
        self.total_requests = 0
        self.failover_count = 0
        self.last_seen = time.time()


class AgentManager:
    """
    Manages active reverse agents, continuous per-user rotation across nodes,
    and automatic failover (2-second timeout per candidate).
    """

    def __init__(self, strategy: str = "rotation", fast_timeout: float = 2.0):
        self.agents: dict[str, AgentSession] = {}
        self.strategy = strategy  # "rotation", "round_robin", "random", "sticky"
        self.fast_timeout = fast_timeout
        self._stream_counter = 1
        self.user_states: dict[str, UserRotationState] = {}
        self._last_successful_agent_id: Optional[str] = None
        self.failover_count = 0
        self.total_requests = 0
        self._lock = asyncio.Lock()

    def get_agent_count(self) -> int:
        return len(self.agents)

    def _get_user_state(self, user_key: str) -> UserRotationState:
        # Prune stale states if cache grows too large
        if len(self.user_states) > 5000:
            now = time.time()
            stale_keys = [k for k, s in self.user_states.items() if now - s.last_seen > 86400]
            for k in stale_keys:
                del self.user_states[k]

        state = self.user_states.get(user_key)
        if state is None:
            state = UserRotationState(user_key)
            self.user_states[user_key] = state
        state.last_seen = time.time()
        return state

    def register(self, agent: AgentSession):
        """Add newly authenticated agent to pool."""
        self.agents[agent.agent_id] = agent
        logger.info(
            f"[+] Agent registered: '{agent.agent_id}' from {agent.remote_ip} "
            f"(Total active agents: {len(self.agents)})"
        )

    def unregister(self, agent_id: str):
        """Remove agent from pool."""
        if agent_id in self.agents:
            del self.agents[agent_id]
            logger.info(
                f"[-] Agent unregistered: '{agent_id}' "
                f"(Total active agents: {len(self.agents)})"
            )

    async def close_all(self):
        """Gracefully disconnect all registered agents and close their sessions."""
        agents = list(self.agents.values())
        self.agents.clear()
        if agents:
            logger.info(f"Closing {len(agents)} active reverse agent session(s)...")
            close_tasks = [agent.close() for agent in agents]
            try:
                await asyncio.wait_for(asyncio.gather(*close_tasks, return_exceptions=True), timeout=2.0)
            except Exception:
                pass

    async def reap_stale_agents(self, max_inactive: float = 60.0):
        """Disconnect and unregister reverse agents that have sent no pings or frames for > max_inactive."""
        now = time.time()
        stale = []
        for agent_id, agent in list(self.agents.items()):
            if agent.closed or (now - agent.last_seen > max_inactive):
                stale.append(agent)
                self.agents.pop(agent_id, None)

        for agent in stale:
            logger.info(f"[-] Watchdog reaped inactive agent '{agent.agent_id}' (idle > {max_inactive}s)")
            await agent.close()

    def get_next_stream_id(self) -> int:
        """Generate unique uint32 stream ID."""
        self._stream_counter = (self._stream_counter + 1) & 0x7FFFFFFF
        if self._stream_counter == 0:
            self._stream_counter = 1
        return self._stream_counter

    def get_candidate_agents(
        self, user_key: Optional[str] = None, client_ip: Optional[str] = None
    ) -> list[AgentSession]:
        """
        Return an ordered list of candidate agents to attempt for a request.
        Rotation is calculated strictly per user_key (SOCKS5 username or MTProto secret/client).
        Candidate 0 is the primary rotated node for this specific user.
        Candidates 1..N are fallbacks in case candidate 0 fails or does not respond within 2 seconds.
        Filters out stale/closed nodes and prioritizes healthy agents.
        """
        now = time.time()
        active = [a for a in self.agents.values() if not a.closed and (now - a.last_seen <= 90)]
        if not active:
            return []

        if len(active) == 1:
            return active

        effective_user = user_key or (client_ip.split(":")[0] if client_ip else "global")
        state = self._get_user_state(effective_user)

        if self.strategy in ("rotation", "round_robin"):
            # For MTProto sessions, maintain stickiness per client device (user_key)
            # to prevent Telegram DC from resetting connections due to IP flapping across nodes
            if user_key and user_key.startswith("mtproto:"):
                # If user previously connected through a node that is still active and healthy, stick to it!
                if state.last_successful_agent_id:
                    for a in active:
                        if a.agent_id == state.last_successful_agent_id and a.is_healthy():
                            fallbacks = [fb for fb in active if fb.agent_id != a.agent_id]
                            fallbacks.sort(key=lambda x: (not x.is_healthy(), x.consecutive_failures))
                            return [a] + fallbacks

                # Otherwise pick from healthy active agents first
                healthy = [a for a in active if a.is_healthy()]
                pool = healthy if healthy else active
                idx = abs(hash(user_key)) % len(pool)
                primary = pool[idx]
                fallbacks = [a for a in active if a.agent_id != primary.agent_id]
                fallbacks.sort(key=lambda x: (not x.is_healthy(), x.consecutive_failures))
                return [primary] + fallbacks

            # Rotate to next agent specifically for this user, prioritizing healthy nodes
            healthy = [a for a in active if a.is_healthy()]
            pool = healthy if healthy else active

            start_idx = state.rr_index % len(pool)
            state.rr_index += 1

            # Ensure candidate 0 is strictly different from the previous assigned/successful node FOR THIS USER
            last_id = state.last_assigned_agent_id or state.last_successful_agent_id
            if pool[start_idx].agent_id == last_id and len(pool) > 1:
                start_idx = (start_idx + 1) % len(pool)

            # Generate candidate list in rotation order
            candidates = [pool[(start_idx + i) % len(pool)] for i in range(len(pool))]
            # Append any unhealthy agents at the end as last-resort fallbacks
            for a in active:
                if a not in candidates:
                    candidates.append(a)
            state.last_assigned_agent_id = candidates[0].agent_id
            return candidates

        elif self.strategy in ("sticky", "client_ip"):
            if state.last_successful_agent_id:
                for a in active:
                    if a.agent_id == state.last_successful_agent_id and a.is_healthy():
                        fallbacks = [fb for fb in active if fb.agent_id != a.agent_id]
                        fallbacks.sort(key=lambda x: (not x.is_healthy(), x.consecutive_failures))
                        return [a] + fallbacks

            healthy = [a for a in active if a.is_healthy()]
            pool = healthy if healthy else active
            key_to_hash = user_key or (client_ip.split(":")[0] if client_ip else "default")
            idx = abs(hash(key_to_hash)) % len(pool)
            primary = pool[idx]
            fallbacks = [a for a in active if a.agent_id != primary.agent_id]
            fallbacks.sort(key=lambda x: (not x.is_healthy(), x.consecutive_failures))
            return [primary] + fallbacks

        else:  # "random"
            healthy = [a for a in active if a.is_healthy()]
            pool = healthy if healthy else active
            shuffled = list(pool)
            random.shuffle(shuffled)
            last_id = state.last_assigned_agent_id or state.last_successful_agent_id
            if shuffled[0].agent_id == last_id and len(shuffled) > 1:
                shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
            for a in active:
                if a not in shuffled:
                    shuffled.append(a)
            state.last_assigned_agent_id = shuffled[0].agent_id
            return shuffled

    def select_agent(
        self, user_key: Optional[str] = None, client_ip: Optional[str] = None
    ) -> Optional[AgentSession]:
        """Returns the primary candidate agent for the request."""
        candidates = self.get_candidate_agents(user_key=user_key, client_ip=client_ip)
        return candidates[0] if candidates else None

    async def establish_stream(
        self,
        host: str,
        port: int,
        user_key: Optional[str] = None,
        client_ip: Optional[str] = None,
        fast_timeout: Optional[float] = None,
        total_timeout: float = 15.0,
        proto: str = "tcp",
    ) -> tuple[Optional[AgentSession], Optional[StreamContext], int]:
        """
        Establish a target connection through a rotated reverse agent for this user.
        Tries the primary rotated candidate first.
        If the primary candidate does not connect within fast_timeout (default 2.0s),
        or fails with an error, immediately falls back to the previous / next candidates.

        Returns (agent, stream, status_code).
        """
        self.total_requests += 1
        effective_user = user_key or (client_ip.split(":")[0] if client_ip else "global")
        state = self._get_user_state(effective_user)
        state.total_requests += 1

        fast_to = fast_timeout if fast_timeout is not None else self.fast_timeout
        if user_key and user_key.startswith("mtproto:"):
            fast_to = max(fast_to, 4.0)
            total_timeout = max(total_timeout, 20.0)
        candidates = self.get_candidate_agents(user_key=user_key, client_ip=client_ip)
        if not candidates:
            logger.warning(f"[{effective_user}] No active reverse agents available to connect to {host}:{port}")
            return None, None, STATUS_HOST_UNREACHABLE

        start_time = time.time()
        last_error_status = STATUS_GENERAL_FAILURE
        num_candidates = len(candidates)

        for idx, candidate in enumerate(candidates):
            if candidate.closed:
                continue

            time_elapsed = time.time() - start_time
            remaining_total = max(0.5, total_timeout - time_elapsed)
            if time_elapsed >= total_timeout:
                logger.warning(f"[{effective_user}] Total timeout reached ({total_timeout}s) trying to connect to {host}:{port}")
                break

            # If more candidates are available in the chain, give this candidate fast_timeout (e.g. 2.0s).
            # If this is the last candidate, allow it to use whatever total time remains.
            if idx < num_candidates - 1:
                attempt_timeout = min(fast_to, remaining_total)
            else:
                attempt_timeout = remaining_total

            stream_id = self.get_next_stream_id()
            stream = StreamContext(stream_id, host, port, candidate.agent_id, proto=proto)
            candidate.register_stream(stream)

            is_fallback = (idx > 0)
            candidate_role = f"Fallback #{idx} (previous/other node)" if is_fallback else "Rotated Primary"
            logger.info(
                f"[CONNECT ATTEMPT] [{effective_user}] -> Routing to {host}:{port} ({proto.upper()}) via [{candidate.agent_id}] "
                f"({candidate_role}, timeout: {attempt_timeout:.1f}s, Stream #{stream_id})"
            )

            # Send connect request to reverse node
            await candidate.send_json(
                CMD_CONNECT_REQ,
                stream_id,
                {"host": host, "port": port, "proto": proto},
            )

            # Wait for response from reverse node
            try:
                await asyncio.wait_for(stream.connect_event.wait(), timeout=attempt_timeout)
                if stream.connect_status == STATUS_SUCCESS:
                    candidate.record_success()
                    state.last_successful_agent_id = candidate.agent_id
                    self._last_successful_agent_id = candidate.agent_id
                    if is_fallback:
                        self.failover_count += 1
                        state.failover_count += 1
                        logger.info(
                            f"[FAILOVER SUCCESS] [{effective_user}] Target {host}:{port} successfully connected via "
                            f"fallback agent [{candidate.agent_id}]!"
                        )
                    return candidate, stream, STATUS_SUCCESS
                else:
                    candidate.record_failure()
                    if state.last_successful_agent_id == candidate.agent_id:
                        state.last_successful_agent_id = None
                    last_error_status = stream.connect_status
                    logger.warning(
                        f"[{effective_user}] [{candidate.agent_id}] Failed connecting to {host}:{port}: "
                        f"status={stream.connect_status}, err='{stream.connect_error}'"
                    )
            except asyncio.TimeoutError:
                candidate.record_failure()
                if state.last_successful_agent_id == candidate.agent_id:
                    state.last_successful_agent_id = None
                last_error_status = STATUS_TIMEOUT
                if is_fallback:
                    self.failover_count += 1
                    state.failover_count += 1
                logger.warning(
                    f"[{effective_user}] [{candidate.agent_id}] Did not connect within {attempt_timeout:.1f}s to {host}:{port}. "
                    f"{'Switching to fallback node...' if idx < num_candidates - 1 else 'All candidates exhausted.'}"
                )

            # Cancel and clean up failed/timed-out attempt
            await candidate.send_frame(CMD_CLOSE, stream_id)
            candidate.remove_stream(stream_id)

        return None, None, last_error_status

    def get_agent_status_list(self) -> list[dict]:
        """Return list of active agents with statistics."""
        return [
            {
                "agent_id": a.agent_id,
                "remote_ip": a.remote_ip,
                "uptime_seconds": int(time.time() - a.connected_at),
                "active_connections": a.active_connections_count,
                "total_handled": a.total_connections_handled,
                "is_last_used": (a.agent_id == self._last_successful_agent_id),
                "is_faketls": getattr(a, "is_faketls", False),
                "sni_domain": getattr(a, "sni_domain", ""),
                "exit_ip": getattr(a, "exit_ip", ""),
            }
            for a in self.agents.values()
        ]
