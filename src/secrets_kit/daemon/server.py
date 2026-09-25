"""
secrets_kit.daemon.server

Move opaque payloads between local UDS and peer TCP transports.
"""

from __future__ import annotations

import json
import logging
import os
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from secrets_kit.daemon.client import (
    daemon_tcp_host,
    default_tcp_port,
    metadata_path,
    runtime_dir,
    uds_path,
)
from secrets_kit.daemon.control import (
    CONTROL_KIND,
    ROUTE_KIND,
    RUNTIME_ACCESS_KIND,
    ControlMessageError,
    parse_daemon_message,
    parse_route_frame,
)
from secrets_kit.daemon.routing import RoutingTable
from secrets_kit.daemon.transport import (
    Transport,
    TransportServices,
    _runtime_sign_binding,
    _runtime_verify_binding,
    create_transport,
    transport_mode,
)
from secrets_kit.identifiers import validate_identifier

LOGGER = logging.getLogger(__name__)
# Give independently started peers a bounded startup window before the
# crash-recovery delivery pass.
OUTBOUND_RUNTIME_STARTUP_GRACE_SECONDS = 10.0
REQUEST_READ_TIMEOUT_SECONDS = 15.0
RUNTIME_HANDOFF_TIMEOUT_SECONDS = 15.0
MAX_REQUEST_BYTES = 1024 * 1024
MAX_CONNECTION_WORKERS = 8


def _response(
    *,
    status: str,
    response: str | None = None,
    error: str | None = None,
    details: str | None = None,
    data: dict[str, Any] | None = None,
) -> bytes:
    """Serialize one daemon-owned transport response."""
    payload: dict[str, Any] = {"version": 1, "status": status}
    if response is not None:
        payload["response"] = response
    if error is not None:
        payload["error"] = error
    if details is not None:
        payload["details"] = details
    if data is not None:
        payload["data"] = data
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _handle_request(
    data: bytes,
    *,
    transport: str = "uds",
    transport_adapter: Transport | None = None,
    routing_table: RoutingTable | None = None,
    delivery_wake: Any = None,
    admission_wake: Any = None,
) -> tuple[bytes, bool]:
    """Handle daemon control/route messages or hand opaque TCP bytes to runtime."""
    try:
        message = parse_daemon_message(data=data)
    except ControlMessageError as exc:
        return _response(status="error", error="bad_control", details=str(exc)), False

    if message is not None and message.get("kind") == CONTROL_KIND:
        operation = message.get("operation")
        if operation == "ping":
            return _response(status="ok", response="pong"), False
        if operation == "status":
            return _status_response(
                transport_adapter=transport_adapter,
                routing_table=routing_table,
            ), False
        if operation == "shutdown":
            if transport != "uds":
                return _response(status="error", error="control_forbidden"), False
            return _response(status="ok", response="shutting_down"), True
        if operation == "delivery-wake":
            if transport != "uds":
                return _response(status="error", error="control_forbidden"), False
            if delivery_wake is not None:
                delivery_wake()
            return _response(status="ok", response="delivery_woken"), False
        if operation == "admission-changed":
            if transport != "uds":
                return _response(status="error", error="control_forbidden"), False
            if admission_wake is not None:
                admission_wake()
            return _response(status="ok", response="admission_reconsidered"), False
        if operation == "route-wait":
            if transport != "uds":
                return _response(status="error", error="control_forbidden"), False
            peer_id = message.get("peer_id")
            timeout_seconds = message.get("timeout_seconds")
            if not isinstance(peer_id, str) or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
                return _response(status="error", error="bad_control"), False
            try:
                peer_id = validate_identifier(value=peer_id, expected_type="node", field="peer_id")
            except ValueError:
                return _response(status="error", error="bad_control"), False
            if routing_table is None:
                return _response(status="error", error="route_unavailable"), False
            connected = routing_table.wait_connected(
                peer_id=peer_id,
                adapter=transport_adapter.name if transport_adapter else "direct_tcp",
                timeout=timeout_seconds,
            )
            if not connected:
                return _response(status="error", error="route_timeout"), False
            return _response(status="ok", response="route_connected"), False
        return _response(status="error", error="unsupported_control"), False

    if message is not None and message.get("kind") == RUNTIME_ACCESS_KIND:
        if transport != "uds":
            return _response(status="error", error="runtime_access_forbidden"), False
        return _invoke_runtime_access(data=data), False

    if message is not None and message.get("kind") == ROUTE_KIND:
        if transport != "uds":
            return _response(status="error", error="route_forbidden"), False
        try:
            if routing_table is not None:
                _refresh_runtime_routes(
                    routing_table=routing_table,
                    adapter=(transport_adapter.name if transport_adapter else "direct_tcp"),
                )
            route = parse_route_frame(value=message)
            adapter = transport_adapter
            if adapter is None:
                raise RuntimeError("no transport adapter is active")
            receipt = adapter.send(
                payload=route.payload,
                peer_id=route.peer_id,
            )
            delivered = receipt.delivered
            receipt_details = {
                "transport": receipt.transport,
                "endpoint": receipt.endpoint,
                "error": receipt.error,
            }
        except Exception as exc:
            return _response(
                status="error",
                error="transport_delivery_failed",
                details=str(exc),
            ), False
        if not delivered:
            return _response(
                status="error",
                error="transport_delivery_failed",
                details=str(receipt_details),
            ), False
        return _response(status="ok", response="delivered"), False

    if transport == "uds":
        return _response(status="error", error="route_frame_required"), False
    if _invoke_runtime(data=data):
        return _response(status="ok", response="delivered"), False
    return _response(status="error", error="runtime_handoff_failed"), False


def _status_response(
    *,
    transport_adapter: Transport | None,
    routing_table: RoutingTable | None,
) -> bytes:
    """Aggregate daemon-owned transport state and runtime-owned status."""
    runtime = _invoke_runtime_status()
    records = runtime.pop("transport_routes", None)
    if routing_table is not None and isinstance(records, list):
        routing_table.replace_from_runtime(
            records=records,
            adapter=(transport_adapter.name if transport_adapter else "direct_tcp"),
        )
    metadata = (
        transport_adapter.snapshot().as_dict()
        if transport_adapter is not None
        else {}
    )
    startup_timestamp = _read_startup_timestamp()
    daemon = {
        "running": True,
        "pid": os.getpid(),
        "startup_time": startup_timestamp,
        "uptime_seconds": _uptime_seconds(startup_timestamp),
        "transport": metadata.get("transport") or getattr(transport_adapter, "name", None),
        "transport_requested": (
            metadata.get("transport_requested")
            or metadata.get("transport")
            or getattr(transport_adapter, "name", None)
        ),
        "capabilities": metadata.get("capabilities", {}),
    }
    local_endpoint = {
        "host": metadata.get("tcp_host") or daemon_tcp_host(),
        "port": metadata.get("tcp_port"),
        "transport": daemon.get("transport"),
        "multiaddr": metadata.get("endpoint"),
        "bound_addresses": metadata.get("bound_addresses", []),
        "advertised_addresses": metadata.get("advertised_addresses", []),
        "transport_peer_id": metadata.get("peer_id"),
    }
    peers = runtime.get("peers") if isinstance(runtime, dict) else []
    peer_ids = {
        str(peer.get("peer_id"))
        for peer in peers
        if isinstance(peer, dict) and peer.get("peer_id")
    }
    snapshot_routes = metadata.get("routes", [])
    routes = [
        dict(route)
        for route in snapshot_routes
        if isinstance(route, dict) and route.get("peer_id") in peer_ids
    ]
    route_ids = {str(route["peer_id"]) for route in routes}
    routing = {
        "count": len(routes),
        "routes": routes,
        "missing": sorted(peer_ids - route_ids),
        "discovery": {
            "enabled": metadata.get("discovery", False),
            "state": metadata.get("discovery_state", "stopped"),
            "candidate_count": metadata.get("discovery_candidate_count", 0),
            "validated_route_count": metadata.get("validated_route_count", 0),
            "rejected_binding_count": metadata.get("rejected_binding_count", 0),
            "events": metadata.get("routing_events", []),
        },
    }
    route_by_peer = {route["peer_id"]: route for route in routes}
    if isinstance(peers, list):
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            route = route_by_peer.get(peer.get("peer_id"))
            peer["ip"] = route.get("host") if route else None
            peer["port"] = route.get("port") if route else None
            peer["reachable"] = route.get("reachable") if route else False
            peer["connected"] = route.get("connected") if route else False
            peer["route_source"] = route.get("source") if route else None
            peer["last_contact"] = route.get("last_contact") if route else None
    synchronization = runtime.get("synchronization", {}) if isinstance(runtime, dict) else {}
    transactions = runtime.get("transactions", {}) if isinstance(runtime, dict) else {}
    envelopes = runtime.get("envelopes", {}) if isinstance(runtime, dict) else {}
    synchronization = {
        **(synchronization if isinstance(synchronization, dict) else {}),
        "applied_transactions": transactions.get("applied", 0),
        "pending_envelopes": envelopes.get("pending", 0),
        "retry_queue": envelopes.get("retry_queue", envelopes.get("retry_pending", 0)),
        "currently_sending": envelopes.get("currently_sending", envelopes.get("sending", 0)),
    }
    overall = _overall_status(runtime=runtime, peers=peers, routing=routing)
    daemon_health = "healthy" if daemon.get("running") and runtime.get("available") else "degraded"
    discovery_state = routing["discovery"].get("state", "stopped")
    peer_discovery = "waiting" if not peers else str(discovery_state)
    identity = runtime.get("identity") if isinstance(runtime, dict) else None
    if isinstance(identity, dict):
        identity = {**identity, "version": runtime.get("version")}
    payload = {
        "version": 1,
        "ok": overall == "HEALTHY",
        "overall": overall,
        "daemon_health": daemon_health,
        "peer_discovery": peer_discovery,
        "backend": runtime.get("backend") if isinstance(runtime, dict) else None,
        "database": runtime.get("database") if isinstance(runtime, dict) else {},
        "transactions": transactions,
        "envelopes": envelopes,
        "identity": identity,
        "daemon": daemon,
        "local_endpoint": local_endpoint,
        "peers": peers if isinstance(peers, list) else [],
        "routing": routing,
        "rss": {
            "configured": metadata.get("relay_configured", False),
            "authenticated_relays": metadata.get("relay_connected", 0),
        },
        "synchronization": synchronization,
        "runtime": runtime,
    }
    return _response(status="ok", response="status", data=payload)


def _invoke_runtime_status() -> dict[str, Any]:
    """Ask the runtime interface for its operational state."""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "secrets_kit.runtime.status"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            check=False,
            env=dict(os.environ),
        )
        value = json.loads(completed.stdout.decode("utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        LOGGER.debug("runtime status request failed", exc_info=True)
    return {"version": 1, "available": False, "error": "runtime status unavailable", "peers": []}


def _invoke_runtime_access(*, data: bytes) -> bytes:
    """Pass an opaque same-user access request to the runtime-owned worker."""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "secrets_kit.cli", "internal", "runtime-access", "--stdin"],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            check=False,
            env=dict(os.environ),
        )
    except (OSError, subprocess.TimeoutExpired):
        LOGGER.warning("runtime access worker unavailable")
        return _response(status="error", error="runtime_unavailable")
    if completed.returncode != 0 or not completed.stdout:
        return _response(status="error", error="runtime_access_failed")
    if len(completed.stdout) > MAX_REQUEST_BYTES:
        return _response(status="error", error="runtime_response_too_large")
    return completed.stdout


def _read_startup_timestamp() -> str | None:
    try:
        value = json.loads(metadata_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    timestamp = value.get("startup_timestamp") if isinstance(value, dict) else None
    return timestamp if isinstance(timestamp, str) else None


def _uptime_seconds(startup_timestamp: str | None) -> int | None:
    if not startup_timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(startup_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(tz=timezone.utc) - parsed).total_seconds()))


def _overall_status(*, runtime: dict[str, Any], peers: object, routing: dict[str, Any]) -> str:
    if not runtime.get("available", False):
        return "DEGRADED"
    if not peers:
        return "WAITING FOR PEERS"
    if routing.get("missing"):
        return "NO ROUTES AVAILABLE"
    envelopes = runtime.get("envelopes", {})
    if isinstance(envelopes, dict) and (envelopes.get("retry_queue", 0) or envelopes.get("failed", 0)):
        return "DEGRADED"
    return "HEALTHY"


def _invoke_runtime(*, data: bytes) -> bool:
    """Supply opaque inbound bytes to the runtime without interpreting them."""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "secrets_kit.runtime.inbound_envelopes",
                "--stdin",
            ],
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            check=False,
            env=dict(os.environ),
        )
    except (OSError, subprocess.TimeoutExpired):
        LOGGER.exception("runtime handoff failed")
        return False
    if completed.returncode != 0:
        LOGGER.warning("runtime rejected inbound payload exit_code=%d", completed.returncode)
        return False
    return True


def _invoke_runtime_endpoint_registration(*, endpoint: str) -> bool:
    """Register the daemon's active endpoint through the runtime interface."""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "secrets_kit.cli",
                "internal",
                "register-endpoint",
                "--endpoint",
                endpoint,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            check=False,
            env=dict(os.environ),
        )
    except (OSError, subprocess.TimeoutExpired):
        LOGGER.exception("runtime endpoint registration failed")
        return False
    return completed.returncode == 0


def _advertised_endpoint(
    *,
    active_endpoint: object,
    transport_host: str,
    tcp_port: object,
    advertised_addresses: object = None,
) -> str:
    """Select the peer-facing endpoint separately from the daemon bind address."""
    configured = os.environ.get("SECKIT_DAEMON_ADVERTISED_ENDPOINT", "").strip()
    if configured:
        return configured
    if (
        isinstance(advertised_addresses, list)
        and advertised_addresses
        and isinstance(advertised_addresses[0], str)
        and isinstance(tcp_port, int)
    ):
        # Durable runtime endpoint records may retain the current host/port,
        # but never the daemon's ephemeral libp2p PeerID.
        return f"tcp://{advertised_addresses[0]}:{tcp_port}"
    if isinstance(active_endpoint, str) and active_endpoint:
        return active_endpoint.rsplit("/p2p/", 1)[0]
    return f"tcp://{transport_host}:{tcp_port}"


def _refresh_runtime_routes(*, routing_table: RoutingTable, adapter: str) -> None:
    """Refresh daemon routes from runtime-owned active endpoint records."""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "secrets_kit.runtime.endpoint_routes"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            check=False,
            env=dict(os.environ),
        )
        if completed.returncode != 0:
            return
        value = json.loads(completed.stdout.decode("utf-8"))
        records = value.get("routes")
        if isinstance(records, list):
            routing_table.replace_from_runtime(records=records, adapter=adapter)
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        LOGGER.debug("runtime route refresh failed", exc_info=True)


def _write_metadata(*, tcp_port: int | None, extra: dict[str, Any] | None = None) -> None:
    """Write daemon transport lifecycle metadata."""
    runtime_dir().mkdir(parents=True, exist_ok=True)
    metadata = {
        "pid": os.getpid(),
        "tcp_port": tcp_port,
        "uds_path": str(uds_path()),
        "startup_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        metadata.update(extra)
    target = metadata_path()
    descriptor, temporary = tempfile.mkstemp(prefix=".seckitd-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(metadata, indent=2, sort_keys=True))
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _bind_tcp_socket(*, requested_port: int) -> socket.socket:
    """Bind the configured TCP transport listener for compatibility callers."""
    port = requested_port
    while port <= 65535:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp_sock.bind((daemon_tcp_host(), port))
        except OSError:
            tcp_sock.close()
            port += 1
            continue
        tcp_sock.listen()
        return tcp_sock
    raise OSError("no available daemon tcp port")


def _handle_connection(
    conn: socket.socket,
    *,
    transport: str,
    transport_adapter: Transport | None = None,
    routing_table: RoutingTable | None = None,
    delivery_wake: Any = None,
    admission_wake: Any = None,
) -> bool:
    """Read one bounded transport request and send its transport response."""
    with conn:
        conn.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        chunks: list[bytes] = []
        total_size = 0
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total_size += len(chunk)
                if total_size > MAX_REQUEST_BYTES:
                    LOGGER.warning(
                        "rejected oversized daemon request transport=%s size=%d",
                        transport,
                        total_size,
                    )
                    conn.sendall(
                        _response(status="error", error="bad_request", details="request_too_large")
                    )
                    return False
        except socket.timeout:
            LOGGER.warning("timed out reading daemon request transport=%s", transport)
            conn.sendall(_response(status="error", error="bad_request", details="request_timeout"))
            return False
        # Runtime handoff may outlive the bounded request-read timeout; the
        # response still needs to be delivered when it returns.
        conn.settimeout(None)
        response, should_stop = _handle_request(
            b"".join(chunks),
            transport=transport,
            transport_adapter=transport_adapter,
            routing_table=routing_table,
            delivery_wake=delivery_wake,
            admission_wake=admission_wake,
        )
        conn.sendall(response)
    return should_stop


def _start_outbound_runtime_worker(
    *, recovered_peer_ids: tuple[str, ...] = ()
) -> subprocess.Popen[bytes]:
    """Start one runtime-owned durable-delivery pass."""
    command = [
        sys.executable,
        "-m",
        "secrets_kit.cli",
        "internal",
        "deliver-pending",
    ]
    for peer_id in recovered_peer_ids:
        command.extend(("--recovered-peer", peer_id))
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=dict(os.environ),
    )


class _OutboundRuntimeScheduler:
    """Coalesce delivery events and retain one cancellable next-due worker."""

    def __init__(self, *, startup_grace_seconds: float) -> None:
        self._lock = threading.RLock()
        self._worker: subprocess.Popen[bytes] | None = None
        self._wake_requested = False
        self._recovered_peer_ids: set[str] = set()
        self._next_run = time.monotonic() + startup_grace_seconds

    def wake(self) -> None:
        """Request one delivery pass for newly committed local work."""
        with self._lock:
            self._wake_requested = True

    def observe(self, observation: object) -> None:
        """Wake peer-specific retained work after authenticated route return."""
        if not isinstance(observation, dict) or observation.get("event") != "route_installed":
            return
        peer_id = observation.get("node_id")
        if not isinstance(peer_id, str):
            return
        with self._lock:
            self._recovered_peer_ids.add(peer_id)
            self._wake_requested = True

    def timeout(self, *, maximum: float = 0.2) -> float:
        """Return the bounded selector wait until the next event or deadline."""
        with self._lock:
            if self._worker is not None and self._worker.poll() is None:
                return maximum
            if self._wake_requested:
                return 0.0
            return max(0.0, min(maximum, self._next_run - time.monotonic()))

    def poll(self) -> None:
        """Collect a finished pass and start at most one due replacement."""
        with self._lock:
            worker = self._worker
            if worker is not None and worker.poll() is None:
                return
            if worker is not None:
                output, _ = worker.communicate()
                self._worker = None
                self._next_run = float("inf")
                if worker.returncode == 0:
                    try:
                        result = json.loads(output.decode("utf-8"))
                        next_attempt_at = (
                            result.get("next_attempt_at")
                            if isinstance(result, dict)
                            else None
                        )
                        if isinstance(next_attempt_at, str):
                            due = datetime.fromisoformat(
                                next_attempt_at.replace("Z", "+00:00")
                            )
                            if due.tzinfo is None:
                                due = due.replace(tzinfo=timezone.utc)
                            delay = max(
                                0.0,
                                (due - datetime.now(tz=timezone.utc)).total_seconds(),
                            )
                            self._next_run = time.monotonic() + delay
                    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                        LOGGER.warning("runtime delivery worker returned invalid schedule")
                else:
                    LOGGER.warning(
                        "runtime delivery worker failed exit_code=%s",
                        worker.returncode,
                    )
            if not self._wake_requested and time.monotonic() < self._next_run:
                return
            recovered_peer_ids = tuple(sorted(self._recovered_peer_ids))
            self._recovered_peer_ids.clear()
            self._wake_requested = False
            self._next_run = float("inf")
            self._worker = _start_outbound_runtime_worker(
                recovered_peer_ids=recovered_peer_ids
            )

    def stop(self) -> None:
        """Cancel the timer and terminate the owned worker during shutdown."""
        with self._lock:
            self._wake_requested = False
            self._recovered_peer_ids.clear()
            self._next_run = float("inf")
            worker = self._worker
            self._worker = None
        if worker is None or worker.poll() is not None:
            return
        worker.terminate()
        try:
            worker.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=2.0)


def serve_forever() -> int:
    """Run the continuously available UDS/TCP transport adapter."""
    runtime_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime_dir().chmod(0o700)
    path = uds_path()
    if path.exists():
        path.unlink()
    outbound_scheduler = _OutboundRuntimeScheduler(
        startup_grace_seconds=OUTBOUND_RUNTIME_STARTUP_GRACE_SECONDS
    )
    futures: set[Future[bool]] = set()
    selected_transport = transport_mode()
    requested_port = default_tcp_port(default=0 if selected_transport == "libp2p" else 19777)
    transport_host = daemon_tcp_host(
        default="0.0.0.0" if selected_transport == "libp2p" else "127.0.0.1"
    )
    routing_table = RoutingTable.from_environment(adapter=selected_transport)
    transport_adapter = create_transport(
        host=transport_host,
        requested_port=requested_port,
        routing_table=routing_table,
    )
    transport_requested = transport_adapter.name
    transport_services = TransportServices(
        frame_handler=lambda data, kind: _handle_request(
            data,
            transport=kind,
            transport_adapter=transport_adapter,
            routing_table=routing_table,
        ),
        routing_table=routing_table,
        sign_transport_binding=_runtime_sign_binding,
        verify_transport_binding=_runtime_verify_binding,
        observe=outbound_scheduler.observe,
    )
    transport_adapter.start(services=transport_services)
    try:
        with (
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as uds_server,
            selectors.DefaultSelector() as selector,
            ThreadPoolExecutor(max_workers=MAX_CONNECTION_WORKERS) as workers,
        ):
            uds_server.bind(str(path))
            path.chmod(0o600)
            uds_server.listen()
            selector.register(uds_server, selectors.EVENT_READ)
            metadata = transport_adapter.snapshot().as_dict()
            metadata["transport_requested"] = transport_requested
            _write_metadata(tcp_port=metadata.get("tcp_port"), extra=metadata)
            active_endpoint = _advertised_endpoint(
                active_endpoint=metadata.get("endpoint"),
                transport_host=str(metadata.get("tcp_host") or transport_host),
                tcp_port=metadata.get("tcp_port"),
                advertised_addresses=metadata.get("advertised_addresses"),
            )
            if not _invoke_runtime_endpoint_registration(endpoint=active_endpoint):
                LOGGER.warning("daemon endpoint was not registered by runtime")
            _refresh_runtime_routes(
                routing_table=routing_table, adapter=transport_adapter.name
            )
            should_stop = False
            while not should_stop:
                for future in tuple(futures):
                    if not future.done():
                        continue
                    futures.remove(future)
                    try:
                        should_stop = should_stop or future.result()
                    except Exception:
                        LOGGER.exception("daemon connection worker failed")
                timeout = outbound_scheduler.timeout()
                for key, _ in selector.select(timeout=timeout):
                    server = key.fileobj
                    if not isinstance(server, socket.socket):
                        continue
                    conn, _ = server.accept()
                    if len(futures) >= MAX_CONNECTION_WORKERS:
                        with conn:
                            conn.sendall(_response(status="error", error="transport_busy"))
                        continue
                    futures.add(
                        workers.submit(
                            _handle_connection,
                            conn,
                            transport="uds",
                            transport_adapter=transport_adapter,
                            routing_table=routing_table,
                            delivery_wake=outbound_scheduler.wake,
                            admission_wake=transport_adapter.admission_changed,
                        )
                    )
                if not should_stop:
                    outbound_scheduler.poll()
    finally:
        transport_adapter.stop()
        outbound_scheduler.stop()
        if path.exists():
            path.unlink()
    return 0


def main() -> int:
    """Run the daemon process entry point."""
    return serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "serve_forever"]
