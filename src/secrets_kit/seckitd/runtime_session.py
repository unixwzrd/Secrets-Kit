"""Runtime session state, bounded retry, and reconnect FSM (Phase 5D).

Non-authoritative: pending delivery hints only; peers and datastore remain authoritative.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64

from typing import Any, Callable, Deque, Dict, List, Optional, Protocol


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ErrorClass(str, enum.Enum):
    """Whether an error may be retried under policy."""

    TRANSIENT = "transient"
    TERMINAL = "terminal"


class SessionState(str, enum.Enum):
    """High-level outbound transport session state per route."""

    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    BACKING_OFF = "backing_off"
    UNAVAILABLE = "unavailable"
    TERMINAL_FAILURE = "terminal_failure"


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry and backoff (explicit ceilings; no infinite loops)."""

    max_connect_attempts: int = 6
    max_send_attempts_per_item: int = 8
    initial_backoff_s: float = 0.05
    max_backoff_s: float = 30.0
    backoff_multiplier: float = 2.0


DEFAULT_RETRY_POLICY = RetryPolicy()


@dataclass
class OutboundWorkItem:
    """One submitted outbound unit (opaque b64 at IPC boundary)."""

    local_id: str
    received_at_iso: str
    route_key: str
    payload_b64: str
    payload_type: Optional[str]
    client_ref: Optional[str]
    phase: str = "submitted"  # submitted | sending | sent_hint | failed
    send_attempts: int = 0
    last_error_class: Optional[str] = None
    last_error_message: Optional[str] = None


@dataclass
class RouteRuntimeState:
    """Per-route session and backoff (ops visibility only)."""

    route_key: str
    session_state: SessionState = SessionState.IDLE
    connect_attempts: int = 0
    backoff_until_monotonic: float = 0.0
    current_backoff_s: float = 0.0
    last_connect_error: Optional[str] = None
    last_session_change_iso: str = field(default_factory=_now_iso)
    terminal_reason: Optional[str] = None


@dataclass
class RuntimeCounters:
    """Aggregates aligned with SYNC_HOST_METRICS-style observability (no payloads)."""

    ipc_submits_total: int = 0
    transport_connect_attempts: int = 0
    transport_connect_ok: int = 0
    transport_disconnects: int = 0
    transport_send_attempts: int = 0
    transport_send_ok: int = 0
    transport_send_failures: int = 0
    transient_errors: int = 0
    terminal_errors: int = 0
    tick_count: int = 0


class OpaqueTransport(Protocol):
    """Minimal transport surface (no plugin framework)."""

    @property
    def connected(self) -> bool: ...

    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def send_opaque(self, data: bytes) -> None: ...


def classify_transport_error(exc: BaseException) -> ErrorClass:
    """Map exceptions to transient vs terminal for bounded retry."""
    if isinstance(exc, (BrokenPipeError, ConnectionError, TimeoutError, OSError)):
        return ErrorClass.TRANSIENT
    return ErrorClass.TERMINAL


@dataclass
class OutboundRuntimeCoordinator:
    """Queues outbound work per route; advances transport with bounded retries."""

    retry: RetryPolicy = field(default_factory=lambda: DEFAULT_RETRY_POLICY)
    pending_cap: int = 256
    monotonic_fn: Callable[[], float] = field(default_factory=lambda: time.monotonic)
    routes: Dict[str, RouteRuntimeState] = field(default_factory=dict)
    _queues: Dict[str, Deque[OutboundWorkItem]] = field(default_factory=dict)
    counters: RuntimeCounters = field(default_factory=RuntimeCounters)

    def _ensure_route(self, route_key: str) -> RouteRuntimeState:
        if route_key not in self.routes:
            self.routes[route_key] = RouteRuntimeState(route_key=route_key)
            self._queues[route_key] = deque()
        return self.routes[route_key]

    def enqueue(
        self,
        *,
        payload_b64: str,
        route_key: str,
        payload_type: Optional[str],
        client_ref: Optional[str],
    ) -> OutboundWorkItem:
        self.counters.ipc_submits_total += 1
        rt = self._ensure_route(route_key)
        q = self._queues[route_key]
        if len(q) >= self.pending_cap:
            raise RuntimeError("pending_cap exceeded for route (non-authoritative queue full)")
        item = OutboundWorkItem(
            local_id=str(uuid.uuid4()),
            received_at_iso=_now_iso(),
            route_key=route_key,
            payload_b64=payload_b64,
            payload_type=payload_type,
            client_ref=client_ref,
        )
        q.append(item)
        if rt.session_state == SessionState.IDLE:
            rt.session_state = SessionState.CONNECTING
            rt.last_session_change_iso = _now_iso()
        return item

    def _next_backoff(self, route: RouteRuntimeState) -> float:
        if route.current_backoff_s <= 0:
            route.current_backoff_s = self.retry.initial_backoff_s
        else:
            route.current_backoff_s = min(
                route.current_backoff_s * self.retry.backoff_multiplier,
                self.retry.max_backoff_s,
            )
        return route.current_backoff_s

    def tick(self, transport: OpaqueTransport) -> None:
        """Single scheduler step: try connect / send one unit for each route with pending work."""
        self.counters.tick_count += 1
        now = self.monotonic_fn()
        for route_key, q in list(self._queues.items()):
            if not q:
                continue
            route = self.routes[route_key]
            if route.session_state == SessionState.TERMINAL_FAILURE:
                continue
            if route.session_state == SessionState.BACKING_OFF and now < route.backoff_until_monotonic:
                continue
            if route.session_state == SessionState.BACKING_OFF and now >= route.backoff_until_monotonic:
                route.session_state = SessionState.CONNECTING
                route.last_session_change_iso = _now_iso()

            if not transport.connected:
                if route.connect_attempts >= self.retry.max_connect_attempts:
                    route.session_state = SessionState.TERMINAL_FAILURE
                    route.terminal_reason = "max_connect_attempts"
                    route.last_session_change_iso = _now_iso()
                    self.counters.terminal_errors += 1
                    continue
                route.session_state = SessionState.CONNECTING
                route.last_session_change_iso = _now_iso()
                self.counters.transport_connect_attempts += 1
                try:
                    transport.connect()
                    route.connect_attempts = 0
                    route.current_backoff_s = 0.0
                    route.last_connect_error = None
                    route.session_state = SessionState.CONNECTED
                    route.last_session_change_iso = _now_iso()
                    self.counters.transport_connect_ok += 1
                except BaseException as exc:
                    route.connect_attempts += 1
                    route.last_connect_error = str(exc)
                    cl = classify_transport_error(exc)
                    if cl == ErrorClass.TRANSIENT:
                        self.counters.transient_errors += 1
                    else:
                        self.counters.terminal_errors += 1
                    if route.connect_attempts >= self.retry.max_connect_attempts:
                        route.session_state = SessionState.TERMINAL_FAILURE
                        route.terminal_reason = "connect_failed"
                        route.last_session_change_iso = _now_iso()
                    else:
                        delay = self._next_backoff(route)
                        route.backoff_until_monotonic = now + delay
                        route.session_state = SessionState.BACKING_OFF
                        route.last_session_change_iso = _now_iso()
                    continue

            item = q[0]
            if item.phase == "sent_hint":
                q.popleft()
                continue
            if item.send_attempts >= self.retry.max_send_attempts_per_item:
                item.phase = "failed"
                item.last_error_class = ErrorClass.TERMINAL.value
                item.last_error_message = "max_send_attempts_per_item"
                q.popleft()
                self.counters.terminal_errors += 1
                continue

            try:
                raw = base64.standard_b64decode(item.payload_b64)
            except Exception as exc:
                item.phase = "failed"
                item.last_error_class = ErrorClass.TERMINAL.value
                item.last_error_message = f"invalid_b64: {exc}"
                q.popleft()
                self.counters.terminal_errors += 1
                continue
            item.phase = "sending"
            item.send_attempts += 1
            self.counters.transport_send_attempts += 1
            try:
                transport.send_opaque(raw)
                item.phase = "sent_hint"
                item.last_error_class = None
                item.last_error_message = None
                self.counters.transport_send_ok += 1
            except BaseException as exc:
                self.counters.transport_send_failures += 1
                cl = classify_transport_error(exc)
                item.last_error_class = cl.value
                item.last_error_message = str(exc)
                if cl == ErrorClass.TRANSIENT:
                    self.counters.transient_errors += 1
                    try:
                        transport.disconnect()
                    except BaseException:
                        pass
                    self.counters.transport_disconnects += 1
                    route.session_state = SessionState.BACKING_OFF
                    delay = self._next_backoff(route)
                    route.backoff_until_monotonic = self.monotonic_fn() + delay
                    route.last_session_change_iso = _now_iso()
                else:
                    self.counters.terminal_errors += 1
                    item.phase = "failed"
                    q.popleft()

    def snapshot_status(self) -> Dict[str, Any]:
        """Structured status for IPC (no payload contents)."""
        pending_total = sum(len(q) for q in self._queues.values())
        routes_out: List[Dict[str, Any]] = []
        for rk, r in sorted(self.routes.items()):
            routes_out.append(
                {
                    "route_key": rk,
                    "session_state": r.session_state.value,
                    "connect_attempts": r.connect_attempts,
                    "pending_count": len(self._queues.get(rk, deque())),
                    "last_connect_error": r.last_connect_error,
                    "terminal_reason": r.terminal_reason,
                    "last_session_change_at": r.last_session_change_iso,
                }
            )
        return {
            "pending_total_non_authoritative": pending_total,
            "routes": routes_out,
            "counters": {
                "ipc_submits_total": self.counters.ipc_submits_total,
                "transport_connect_attempts": self.counters.transport_connect_attempts,
                "transport_connect_ok": self.counters.transport_connect_ok,
                "transport_disconnects": self.counters.transport_disconnects,
                "transport_send_attempts": self.counters.transport_send_attempts,
                "transport_send_ok": self.counters.transport_send_ok,
                "transport_send_failures": self.counters.transport_send_failures,
                "transient_errors": self.counters.transient_errors,
                "terminal_errors": self.counters.terminal_errors,
                "tick_count": self.counters.tick_count,
            },
            "retry": {
                "max_connect_attempts": self.retry.max_connect_attempts,
                "max_send_attempts_per_item": self.retry.max_send_attempts_per_item,
                "max_backoff_s": self.retry.max_backoff_s,
            },
            "note": "pending and session state are operational hints only; not sync authority",
        }
