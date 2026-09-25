"""
secrets_kit.daemon.transport

Provide the daemon-owned transport abstraction and its libp2p/direct TCP
implementations.

The runtime sees only opaque bytes and transport-neutral receipts. This module
is daemon-only; it must not open SQLite, parse application envelopes, or make
peer authorization decisions.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import urllib.parse
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

import psutil

from secrets_kit.daemon.routing import RoutingTable, TransportRouteError, _is_wildcard_endpoint
from secrets_kit.daemon.transports import (
    RouteObservation,
    TransportAdapter,
    TransportCapabilities,
    TransportConfig,
    TransportError,
    TransportReceipt,
    TransportRegistry,
    TransportServices,
    TransportSnapshot,
    TransportUnavailable,
)
from secrets_kit.protocol.rss_auth import (
    RSS_SESSION_AUTH_PROTOCOL,
    RSS_SESSION_READY_PROTOCOL,
    RSSAuthenticationChallenge,
    RSSAuthenticationError,
    RSSRelayClientCredentials,
    build_rss_session_proof,
    clear_consumed_rss_enrollment_token,
    encode_rss_auth_frame,
    load_rss_relay_credentials_from_environment,
    load_rss_relay_peers_from_profile,
    parse_rss_auth_response,
    perform_rss_https_enrollment,
    rss_auth_control_request,
)

LOGGER = logging.getLogger(__name__)
MAX_FRAME_BYTES = 1024 * 1024
# Keep one unreachable peer from blocking a bounded durable-delivery pass.
# Failed sends remain runtime-owned durable work and use one-shot retry timing.
TRANSPORT_IO_TIMEOUT_SECONDS = 3.0
RUNTIME_BINDING_TIMEOUT_SECONDS = 15.0
LOCAL_TRANSPORT_STARTUP_TIMEOUT_SECONDS = 10.0
RSS_TRANSPORT_STARTUP_TIMEOUT_SECONDS = 30.0
RSS_RELAY_MAINTENANCE_INTERVAL_SECONDS = 10.0
LAN_LISTENER_REFRESH_INTERVAL_SECONDS = 5.0
LIBP2P_UPGRADE_TIMEOUT_SECONDS = 30.0
LIBP2P_PROTOCOL = "/seckit/opaque/1.0.0"
IDENTITY_BINDING_PROTOCOL = "/seckit/identity-binding/1.0.0"
MAX_ROUTING_DIAGNOSTIC_EVENTS = 512
LIBP2P_IDENTITY_KEY_FILENAME = "libp2p-identity.key"
LOOPBACK_IPV4_ADDRESS = "127.0.0.1"


class _RemoteDeliveryRejected(TransportError):
    """The remote runtime replied but did not accept the opaque envelope."""


@dataclass(frozen=True)
class TransportPeer:
    """Peer identity supplied to the daemon for route resolution."""

    peer_id: str


# Compatibility name for callers that imported the pre-boundary type.  The
# object intentionally contains no endpoint information.
TransportDestination = TransportPeer


FrameHandler = Callable[[bytes, str], tuple[bytes, bool]]
Transport = TransportAdapter


def _default_ipv4_route_interfaces() -> list[str]:
    """Return OS-ordered IPv4 default-route interfaces without probing a peer."""
    if sys.platform == "darwin":
        try:
            completed = subprocess.run(
                ["/usr/sbin/netstat", "-rn", "-f", "inet"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1.0,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if completed.returncode != 0:
            return []
        interfaces: list[str] = []
        netif_index: int | None = None
        for line in completed.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            if fields[0] == "Destination" and "Netif" in fields:
                netif_index = fields.index("Netif")
                continue
            if (
                netif_index is not None
                and fields[0] == "default"
                and len(fields) > netif_index
            ):
                interfaces.append(fields[netif_index])
        return interfaces

    if sys.platform.startswith("linux"):
        routes: list[tuple[int, int, str]] = []
        try:
            with open("/proc/net/route", encoding="ascii") as route_table:
                for order, line in enumerate(route_table):
                    fields = line.split()
                    if len(fields) < 8 or fields[0] == "Iface":
                        continue
                    try:
                        destination = int(fields[1], 16)
                        flags = int(fields[3], 16)
                        metric = int(fields[6], 10)
                        mask = int(fields[7], 16)
                    except ValueError:
                        continue
                    if destination == 0 and mask == 0 and flags & 0x1:
                        routes.append((metric, order, fields[0]))
        except (OSError, UnicodeError):
            return []
        return [interface for _metric, _order, interface in sorted(routes)]

    return []


def _lan_ipv4_addresses() -> list[str]:
    """Return one active broadcast/multicast LAN address on a default route."""
    try:
        addresses_by_interface = psutil.net_if_addrs()
        stats_by_interface = psutil.net_if_stats()
    except (OSError, RuntimeError):
        return []

    for interface in _default_ipv4_route_interfaces():
        stats = stats_by_interface.get(interface)
        if stats is None or not stats.isup:
            continue
        raw_flags = getattr(stats, "flags", ())
        if isinstance(raw_flags, str):
            flags = {flag.strip().lower() for flag in raw_flags.split(",")}
        else:
            flags = {str(flag).strip().lower() for flag in raw_flags}
        if (
            "broadcast" not in flags
            or "multicast" not in flags
            or flags & {"loopback", "pointopoint", "point-to-point"}
        ):
            continue
        for address in addresses_by_interface.get(interface, ()):
            if address.family != socket.AF_INET:
                continue
            try:
                value = ipaddress.ip_address(address.address)
            except ValueError:
                continue
            if (
                value.version == 4
                and not value.is_loopback
                and not value.is_link_local
                and not value.is_multicast
                and not value.is_unspecified
            ):
                return [str(value)]
    return []


def _validate_payload(payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise TransportError("transport payload must be bytes")
    if len(payload) > MAX_FRAME_BYTES:
        raise TransportError("transport payload exceeds maximum frame size")


def _exception_chain(exc: BaseException) -> list[dict[str, str]]:
    """Return bounded nested exception evidence without changing handling."""
    chain: list[dict[str, str]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(chain) < 8:
        seen.add(id(current))
        chain.append(
            {
                "type": type(current).__name__,
                "message": str(current)[:1024],
                "repr": repr(current)[:1024],
            }
        )
        current = current.__cause__ or current.__context__
    return chain


def _response_bytes(*, status: str, error: str | None = None) -> bytes:
    value: dict[str, str] = {"status": status}
    if error is not None:
        value["error"] = error
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class DirectTCPTransport:
    """Explicitly selected compatibility transport for direct TCP endpoints."""

    name = "direct_tcp"
    capabilities = TransportCapabilities()

    def __init__(
        self, *, host: str, requested_port: int, routing_table: RoutingTable | None = None
    ) -> None:
        self._host = host
        self._requested_port = requested_port
        self._routing_table = routing_table or RoutingTable.from_environment(adapter=self.name)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._services: TransportServices | None = None
        self._port: int | None = None

    def start(self, *, services: TransportServices) -> None:
        if self._listener is not None:
            return
        self._services = services
        self._routing_table = services.routing_table
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        port = self._requested_port
        while port <= 65535:
            try:
                listener.bind((self._host, port))
                break
            except OSError:
                port += 1
        else:
            listener.close()
            raise TransportError("no available daemon tcp port")
        listener.listen()
        listener.settimeout(0.2)
        self._listener = listener
        self._port = int(listener.getsockname()[1])
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, name="seckit-direct-tcp", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            listener.close()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def admission_changed(self) -> None:
        """Direct TCP has no rejected discovery bindings to reconsider."""

    def send(self, *, peer_id: str, payload: bytes) -> TransportReceipt:
        _validate_payload(payload)
        try:
            destination = self._routing_table.resolve(peer_id=peer_id, adapter=self.name)
            host, port = _direct_tcp_endpoint(destination)
        except (TransportRouteError, TransportError) as exc:
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint="",
                error=str(exc),
            )
        try:
            with socket.create_connection(
                (host, port), timeout=TRANSPORT_IO_TIMEOUT_SECONDS
            ) as sock:
                sock.settimeout(TRANSPORT_IO_TIMEOUT_SECONDS)
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                response = b"".join(iter(lambda: sock.recv(4096), b""))
            value = json.loads(response.decode("utf-8"))
            if value.get("status") != "ok" or value.get("response") != "delivered":
                raise TransportError(str(value))
        except (OSError, ValueError, json.JSONDecodeError, TransportError) as exc:
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint=f"{host}:{port}",
                error=str(exc),
            )
        return TransportReceipt(
            delivered=True,
            transport=self.name,
            endpoint=f"{host}:{port}",
        )

    def snapshot(self) -> TransportSnapshot:
        """Return direct-TCP operational state through the common contract."""
        return TransportSnapshot(
            transport=self.name,
            running=self._listener is not None,
            capabilities=self.capabilities,
            endpoint=(f"tcp://{self._host}:{self._port}" if self._port else None),
            tcp_host=self._host,
            tcp_port=self._port,
            bound_addresses=(f"tcp://{self._host}:{self._port}",) if self._port else (),
            routes=_route_observations(
                self._routing_table,
                adapter=self.name,
                endpoint_parts=_direct_route_parts,
            ),
        )

    def metadata(self) -> dict[str, Any]:
        """Compatibility view for callers migrating to ``snapshot``."""
        return self.snapshot().as_dict()

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(
                target=self._handle_connection,
                args=(conn,),
                name="seckit-direct-tcp-connection",
                daemon=True,
            )
            worker.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(TRANSPORT_IO_TIMEOUT_SECONDS)
            chunks: list[bytes] = []
            total = 0
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_FRAME_BYTES:
                        conn.sendall(_response_bytes(status="error", error="request_too_large"))
                        return
                # Runtime handoff may outlive the bounded read timeout. Do
                # not let that deadline suppress the transport receipt after
                # the complete frame is received.
                conn.settimeout(None)
                services = self._services
                if services is None:
                    return
                response, _ = services.frame_handler(b"".join(chunks), self.name)
                conn.sendall(response)
            except (OSError, socket.timeout):
                return


class _LibP2PNotifee:
    """Translate libp2p connection loss into daemon route availability."""

    def __init__(self, *, transport: "PyLibP2PTransport") -> None:
        self._transport = transport

    async def opened_stream(self, network: Any, stream: Any) -> None:
        """Ignore stream-open observations."""
        _ = network, stream

    async def closed_stream(self, network: Any, stream: Any) -> None:
        """Ignore stream-close observations."""
        _ = network, stream

    async def connected(self, network: Any, conn: Any) -> None:
        """Authenticate a newly live connection through the existing binding path."""
        _ = network
        await self._transport._transport_connected(
            transport_peer_id=str(conn.muxed_conn.peer_id)
        )

    async def disconnected(self, network: Any, conn: Any) -> None:
        """Invalidate an existing binding only when its last peer connection closes."""
        peer_id = conn.muxed_conn.peer_id
        if any(
            remaining is not conn and not remaining.is_closed
            for remaining in network.get_connections(peer_id)
        ):
            return
        self._transport._transport_disconnected(
            transport_peer_id=str(peer_id)
        )

    async def listen(self, network: Any, multiaddr: Any) -> None:
        """Ignore listener-start observations already exposed by metadata."""
        _ = network, multiaddr

    async def listen_close(self, network: Any, multiaddr: Any) -> None:
        """Ignore listener-stop observations during normal daemon shutdown."""
        _ = network, multiaddr


def _create_noise_only_host(*, listen_addr: Any, bootstrap: list[str] | None) -> Any:
    _mplex_circuit_boundary_context()
    """Create a py-libp2p host with exactly the approved Noise profile."""
    from libp2p import new_host
    from libp2p.crypto.x25519 import create_new_key_pair as create_x25519_key_pair
    from libp2p.custom_types import TProtocol
    from libp2p.network.config import ConnectionConfig
    from libp2p.security.noise.transport import (
        PROTOCOL_ID as NOISE_PROTOCOL_ID,
    )
    from libp2p.security.noise.transport import (
        Transport as NoiseTransport,
    )

    identity_key_pair = _load_or_create_libp2p_identity()
    noise_key_pair = create_x25519_key_pair()
    security_options = {
        TProtocol(NOISE_PROTOCOL_ID): NoiseTransport(
            identity_key_pair,
            noise_privkey=noise_key_pair.private_key,
        )
    }
    return new_host(
        key_pair=identity_key_pair,
        sec_opt=security_options,
        listen_addrs=[listen_addr],
        enable_mDNS=False,
        bootstrap=bootstrap,
        connection_config=ConnectionConfig(
            inbound_upgrade_timeout=LIBP2P_UPGRADE_TIMEOUT_SECONDS,
            outbound_upgrade_timeout=LIBP2P_UPGRADE_TIMEOUT_SECONDS,
        ),
    )


def _load_or_create_libp2p_identity() -> Any:
    """Retain one operational identity in the daemon's stable runtime namespace.

    Foreground service-manager starts and detached CLI starts must resolve the
    same directory, including when no environment override was supplied.
    """
    from libp2p import generate_new_ed25519_identity
    from libp2p.crypto.ed25519 import create_new_key_pair

    from secrets_kit.daemon.client import runtime_dir

    runtime_path = runtime_dir()
    runtime_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    runtime_path.chmod(0o700)
    key_path = runtime_path / LIBP2P_IDENTITY_KEY_FILENAME
    if key_path.is_symlink():
        raise TransportUnavailable("libp2p identity key must not be a symbolic link")

    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = None
    if fd is not None:
        identity = generate_new_ed25519_identity()
        try:
            os.write(fd, identity.private_key.to_bytes())
            os.fsync(fd)
        finally:
            os.close(fd)
        return identity

    metadata = key_path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise TransportUnavailable("libp2p identity key must be a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise TransportUnavailable("libp2p identity key permissions must be 0600")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise TransportUnavailable("libp2p identity key must be owned by the daemon user")
    private_key = key_path.read_bytes()
    if len(private_key) != 32:
        raise TransportUnavailable("libp2p identity key has an invalid binary layout")
    try:
        return create_new_key_pair(seed=private_key)
    except (TypeError, ValueError) as exc:
        raise TransportUnavailable("libp2p identity key is invalid") from exc


def _mplex_circuit_boundary_context() -> Any:
    """Return the task-local switch that preserves circuit control frames."""
    from contextvars import ContextVar

    from libp2p.stream_muxer.mplex.mplex_stream import MplexStream

    context = getattr(MplexStream, "_seckit_circuit_boundary_context", None)
    if context is not None:
        return context
    context = ContextVar("seckit_mplex_circuit_boundary", default=False)
    original = MplexStream._read_return_when_blocked

    def _read_queued_messages(self: Any) -> bytearray:
        if context.get():
            return bytearray()
        return original(self)

    MplexStream._read_return_when_blocked = _read_queued_messages
    MplexStream._seckit_circuit_boundary_context = context
    return context


class PyLibP2PTransport:
    """Daemon transport adapter backed by py-libp2p's host and streams."""

    name = "libp2p"
    capabilities = TransportCapabilities(
        discovery=True,
        dynamic_endpoints=True,
        relay_client=True,
        authenticated_sessions=True,
        encrypted_sessions=True,
    )

    def __init__(
        self,
        *,
        host: str,
        requested_port: int,
        discovery: bool = True,
        bootstrap: list[str] | None = None,
        relay_peers: list[str] | None = None,
        relay_auth: RSSRelayClientCredentials | None = None,
        routing_table: RoutingTable | None = None,
        interfaces: Any = None,
    ) -> None:
        self._requested_host = host
        self._automatic_lan_host = host == "0.0.0.0"
        self._host: str | None = None if self._automatic_lan_host else host
        self._requested_port = requested_port
        self._discovery = discovery
        self._bootstrap = bootstrap or []
        self._relay_peers = relay_peers or []
        self._relay_auth = relay_auth
        self._mdns_interfaces = interfaces
        self._routing_table = routing_table or RoutingTable.from_environment(adapter=self.name)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._services: TransportServices | None = None
        self._state_lock = threading.RLock()
        self._host_object: Any = None
        self._host_generation = 0
        self._scope_nursery: Any = None
        self._endpoint: str | None = None
        self._peer_id: str | None = None
        self._trio_token: Any = None
        self._port: int | None = None
        self._relay_connected = 0
        self._relay_auth_refresh: tuple[Any, RSSRelayClientCredentials] | None = None
        self._relay_control_streams: dict[str, Any] = {}
        self._relay_endpoint_states: dict[str, str] = {}
        self._relay_candidate_ranks: dict[str, int] = {}
        self._circuit_dial_endpoints: dict[str, str] = {}
        self._relay_discovery_service: Any = None
        self._discovery_service: Any = None
        self._discovery_candidates: set[str] = set()
        self._candidate_infos: dict[str, Any] = {}
        self._mdns_candidate_infos: dict[str, Any] = {}
        self._notified_candidate_endpoints: dict[str, str] = {}
        self._candidate_lock = threading.RLock()
        self._binding_inflight: set[str] = set()
        self._binding_states: dict[str, tuple[str, str]] = {}
        self._delivery_retry_bindings: set[tuple[str, object]] = set()
        self._rejected_bindings = 0
        self._routing_events: deque[dict[str, Any]] = deque(
            maxlen=MAX_ROUTING_DIAGNOSTIC_EVENTS
        )

    def start(self, *, services: TransportServices) -> None:
        if self._thread is not None:
            return
        self._services = services
        self._routing_table = services.routing_table
        self._stop_event.clear()
        self._ready.clear()
        self._startup_error = None
        self._relay_connected = 0
        self._relay_auth_refresh = None
        self._circuit_dial_endpoints.clear()
        with self._candidate_lock:
            self._mdns_candidate_infos.clear()
            self._notified_candidate_endpoints.clear()
        self._thread = threading.Thread(target=self._run_thread, name="seckit-libp2p", daemon=True)
        self._thread.start()
        startup_timeout = (
            RSS_TRANSPORT_STARTUP_TIMEOUT_SECONDS
            if self._relay_peers
            else LOCAL_TRANSPORT_STARTUP_TIMEOUT_SECONDS
        )
        if not self._ready.wait(timeout=startup_timeout):
            self.stop()
            raise TransportError("libp2p host did not become ready")
        if self._startup_error is not None:
            error = self._startup_error
            self.stop()
            if isinstance(error, TransportError):
                raise error
            raise TransportUnavailable(f"libp2p transport unavailable: {error}") from error

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)

    def admission_changed(self) -> None:
        """Retry each still-known rejected candidate once for this mutation."""
        with self._state_lock:
            host = self._host_object
            token = self._trio_token
            generation = self._host_generation
        if host is None or token is None:
            return

        queued: list[tuple[str, str, Any]] = []
        with self._candidate_lock:
            for transport_peer_id, (endpoint, state) in tuple(
                self._binding_states.items()
            ):
                if state != "rejected":
                    continue
                candidate = self._candidate_infos.get(
                    transport_peer_id,
                    self._mdns_candidate_infos.get(transport_peer_id),
                )
                if candidate is None or _peer_endpoint(peer_info=candidate) != endpoint:
                    continue
                self._binding_states[transport_peer_id] = (endpoint, "retry_queued")
                queued.append((transport_peer_id, endpoint, candidate))
        if not queued:
            return

        def restore_rejected() -> None:
            with self._candidate_lock:
                for transport_peer_id, endpoint, _candidate in queued:
                    if self._binding_states.get(transport_peer_id) == (
                        endpoint,
                        "retry_queued",
                    ):
                        self._binding_states[transport_peer_id] = (
                            endpoint,
                            "rejected",
                        )

        def schedule() -> None:
            with self._state_lock:
                is_current = (
                    self._host_object is host
                    and self._host_generation == generation
                    and not self._stop_event.is_set()
                )
            if not is_current:
                restore_rejected()
                return
            for transport_peer_id, endpoint, candidate in queued:
                with self._candidate_lock:
                    if self._binding_states.get(transport_peer_id) != (
                        endpoint,
                        "retry_queued",
                    ):
                        continue
                self._spawn_scope_task(self._connect_and_bind, candidate)

        try:
            token.run_sync_soon(schedule)
        except RuntimeError:
            restore_rejected()

    def send(self, *, peer_id: str, payload: bytes) -> TransportReceipt:
        _validate_payload(payload)
        try:
            destination = self._routing_table.resolve(peer_id=peer_id, adapter=self.name)
        except TransportRouteError as exc:
            try:
                destination = self._routing_table.resolve_retained(
                    peer_id=peer_id,
                    adapter=self.name,
                )
            except TransportRouteError:
                return TransportReceipt(
                    delivered=False,
                    transport=self.name,
                    endpoint="",
                    error=str(exc),
                )
        if not destination.endpoint:
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint=f"{destination.host}:{destination.port}",
                error="libp2p destination requires a multiaddr endpoint",
            )
        with self._state_lock:
            host = self._host_object
            token = self._trio_token
            generation = self._host_generation
        if host is None or token is None:
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint=destination.endpoint,
                error="libp2p host is not running",
            )
        try:
            import trio

            retry_marker: tuple[str, object] | None = None
            if (
                not destination.reachable
                and destination.transport_peer_id is not None
            ):
                retry_marker = (destination.transport_peer_id, object())
                with self._candidate_lock:
                    self._delivery_retry_bindings.add(retry_marker)
            try:
                result = trio.from_thread.run(
                    self._send_async,
                    payload,
                    destination.endpoint,
                    generation,
                    trio_token=token,
                )
            finally:
                if retry_marker is not None:
                    with self._candidate_lock:
                        self._delivery_retry_bindings.discard(retry_marker)
        except _RemoteDeliveryRejected:
            self._routing_table.mark_contact(peer_id=peer_id)
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint=destination.endpoint,
                error="remote runtime rejected delivery",
            )
        except Exception as exc:
            self._routing_table.mark_unavailable(peer_id=peer_id)
            self._record_routing_event(
                event="route_unavailable",
                node_id=peer_id,
                reason_type="send_exception",
            )
            return TransportReceipt(
                delivered=False,
                transport=self.name,
                endpoint=destination.endpoint,
                error=str(exc),
            )
        if result is not None:
            if result.delivered:
                self._routing_table.mark_contact(peer_id=peer_id)
            else:
                self._routing_table.mark_unavailable(peer_id=peer_id)
                self._record_routing_event(
                    event="route_unavailable",
                    node_id=peer_id,
                    reason_type="undelivered_receipt",
                )
            return result
        self._routing_table.mark_contact(peer_id=peer_id)
        return TransportReceipt(delivered=True, transport=self.name, endpoint=destination.endpoint)

    def snapshot(self) -> TransportSnapshot:
        """Return libp2p state through the transport-neutral status contract."""
        with self._state_lock:
            host = self._host
            endpoint = self._endpoint
            peer_id = self._peer_id
            port = self._port
        routes = self._routing_table.routes(adapter=self.name)
        discovery = self._discovery_service
        advertised_addresses = (
            tuple(discovery.advertised_addresses)
            if discovery is not None
            else ()
        )
        with self._candidate_lock:
            candidate_count = len(
                self._discovery_candidates | set(self._mdns_candidate_infos)
            )
            routing_events = list(self._routing_events)
        capabilities = TransportCapabilities(
            discovery=self._discovery,
            dynamic_endpoints=True,
            relay_client=True,
            authenticated_sessions=True,
            encrypted_sessions=True,
        )
        return TransportSnapshot(
            transport=self.name,
            running=self._thread is not None and self._ready.is_set(),
            capabilities=capabilities,
            endpoint=endpoint,
            transport_identity=peer_id,
            tcp_host=host,
            tcp_port=port,
            discovery_state=(
                "running" if self._discovery_service is not None else "stopped"
            ),
            discovery_candidate_count=candidate_count,
            validated_route_count=self._routing_table.discovered_count(),
            rejected_binding_count=self._rejected_bindings,
            bound_addresses=(endpoint,) if endpoint else (),
            advertised_addresses=advertised_addresses,
            routes=_route_observations_from_routes(
                routes, endpoint_parts=_libp2p_route_parts
            ),
            diagnostics=tuple(routing_events),
            details={
                "security_protocols": ["/noise"],
                "bootstrap_count": len(self._bootstrap),
                "relay_configured": bool(self._relay_peers),
                "relay_connected": self._relay_connected,
            },
        )

    def metadata(self) -> dict[str, Any]:
        """Compatibility view for callers migrating to ``snapshot``."""
        return self.snapshot().as_dict()

    def _run_thread(self) -> None:
        try:
            import multiaddr
            import trio

            async def run() -> None:
                started_once = False
                while not self._stop_event.is_set():
                    selected_host = self._select_listener_host()
                    retry_needed = False
                    try:
                        await self._run_host_scope(
                            selected_host=selected_host,
                            multiaddr=multiaddr,
                            trio=trio,
                        )
                    except Exception as exc:
                        if not started_once:
                            raise
                        self._record_routing_event(
                            event="listener_recovery_failed",
                            host=selected_host,
                            reason_type=type(exc).__name__,
                        )
                        retry_needed = True
                    else:
                        started_once = True
                    if self._stop_event.is_set():
                        return
                    if not retry_needed:
                        continue
                    retry_at = (
                        trio.current_time()
                        + LAN_LISTENER_REFRESH_INTERVAL_SECONDS
                    )
                    while (
                        not self._stop_event.is_set()
                        and trio.current_time() < retry_at
                    ):
                        await trio.sleep(0.1)

            trio.run(run)
        except BaseException as exc:
            self._startup_error = TransportUnavailable(str(exc))
            self._ready.set()

    def _select_listener_host(self) -> str:
        """Select one concrete listener address without VPN or wildcard fallback."""
        if not self._automatic_lan_host:
            return self._requested_host
        addresses = _lan_ipv4_addresses()
        return addresses[0] if addresses else LOOPBACK_IPV4_ADDRESS

    async def _run_host_scope(
        self,
        *,
        selected_host: str,
        multiaddr: Any,
        trio: Any,
    ) -> None:
        """Run one listener generation until stop or automatic address change."""
        listen_addr = multiaddr.Multiaddr(
            f"/ip4/{selected_host}/tcp/{self._requested_port}"
        )
        # py-libp2p 0.7 starts mDNS before a dynamic port resolves. Keep its
        # built-in service disabled and start the daemon service after bind.
        host = _create_noise_only_host(
            listen_addr=listen_addr,
            bootstrap=self._bootstrap or None,
        )
        peer_id = str(host.get_id())
        host.get_network().register_notifee(_LibP2PNotifee(transport=self))
        host.set_stream_handler(LIBP2P_PROTOCOL, self._handle_stream)
        host.set_stream_handler(IDENTITY_BINDING_PROTOCOL, self._handle_binding_stream)
        async with host.run(listen_addrs=[listen_addr]):
            try:
                bound_address, bound_port = _bound_listener_address(
                    addresses=host.get_addrs(),
                    selected_host=selected_host,
                )
                with self._state_lock:
                    self._host = selected_host
                    self._host_object = host
                    self._peer_id = peer_id
                    self._endpoint = f"{bound_address}/p2p/{peer_id}"
                    self._port = bound_port
                    self._trio_token = trio.lowlevel.current_trio_token()
                    self._host_generation += 1
                async with AsyncExitStack() as services:
                    async with trio.open_nursery() as nursery:
                        self._scope_nursery = nursery
                        try:
                            if self._discovery and self._should_start_mdns(
                                bound_host=selected_host
                            ):
                                self._start_mdns_discovery(
                                    host=host,
                                    trio=trio,
                                    bound_host=selected_host,
                                )
                            if self._bootstrap:
                                self._queue_bootstrap_candidates(multiaddr=multiaddr)
                            if self._relay_peers:
                                await self._start_relay_services(
                                    host=host,
                                    multiaddr=multiaddr,
                                    services=services,
                                )
                            self._ready.set()
                            await self._maintain_host_scope(
                                host=host,
                                selected_host=selected_host,
                                trio=trio,
                            )
                        finally:
                            await self._retire_host_scope(host=host, trio=trio)
                            nursery.cancel_scope.cancel()
            finally:
                self._clear_host_state(host=host)

    async def _maintain_host_scope(
        self,
        *,
        host: Any,
        selected_host: str,
        trio: Any,
    ) -> None:
        """Maintain RSS while polling automatic LAN selection."""
        next_listener_refresh = (
            trio.current_time() + LAN_LISTENER_REFRESH_INTERVAL_SECONDS
        )
        next_relay_auth_refresh = (
            trio.current_time() + RSS_RELAY_MAINTENANCE_INTERVAL_SECONDS
        )
        while not self._stop_event.is_set():
            now = trio.current_time()
            if self._automatic_lan_host and now >= next_listener_refresh:
                if self._select_listener_host() != selected_host:
                    return
                next_listener_refresh = (
                    now + LAN_LISTENER_REFRESH_INTERVAL_SECONDS
                )
            if (
                self._relay_auth_refresh is not None
                and now >= next_relay_auth_refresh
            ):
                relay_targets, credentials = self._relay_auth_refresh
                try:
                    credentials = await self._authenticate_relay_targets(
                        host=host,
                        relay_targets=list(relay_targets),
                        credentials=credentials,
                    )
                    self._relay_auth_refresh = (relay_targets, credentials)
                except TransportUnavailable:
                    pass
                discovery = self._relay_discovery_service
                if discovery is not None:
                    for relay_info, _ in relay_targets:
                        peer_id = str(relay_info.peer_id)
                        if (
                            self._relay_endpoint_states.get(peer_id)
                            != "authenticated"
                        ):
                            continue
                        reserved = False
                        with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS):
                            if discovery.get_relay_info(relay_info.peer_id) is None:
                                await discovery._add_relay(relay_info.peer_id)
                            reserved = await discovery.make_reservation(
                                relay_info.peer_id
                            )
                        self._record_routing_event(
                            event=(
                                "rss_reservation_active"
                                if reserved
                                else "rss_reservation_failed"
                            ),
                            transport_peer_id=peer_id,
                        )
                next_relay_auth_refresh = (
                    now + RSS_RELAY_MAINTENANCE_INTERVAL_SECONDS
                )
            await trio.sleep(0.1)

    def _should_start_mdns(self, *, bound_host: str) -> bool:
        """Keep automatic loopback fallback private while preserving overrides."""
        return (
            not self._automatic_lan_host
            or _lan_ipv4_addresses() == [bound_host]
        )

    def _spawn_scope_task(self, callback: Callable[..., Any], *args: Any) -> None:
        """Start transport work only inside the current host generation."""
        nursery = self._scope_nursery
        if nursery is not None:
            nursery.start_soon(callback, *args)

    async def _retire_host_scope(self, *, host: Any, trio: Any) -> None:
        """Withdraw discovery and clear generation-owned candidate state."""
        discovery = self._discovery_service
        self._discovery_service = None
        if discovery is not None:
            discovery.stop()
        nursery = self._scope_nursery
        self._scope_nursery = None
        self._clear_host_state(host=host)
        with self._candidate_lock:
            self._discovery_candidates.clear()
            self._candidate_infos.clear()
            self._mdns_candidate_infos.clear()
            self._relay_candidate_ranks.clear()
            self._notified_candidate_endpoints.clear()
            self._binding_inflight.clear()
            self._binding_states.clear()
        self._circuit_dial_endpoints.clear()
        if nursery is not None:
            nursery.cancel_scope.cancel()
        streams = tuple(self._relay_control_streams.values())
        self._relay_control_streams.clear()
        with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS, shield=True):
            for stream in streams:
                try:
                    await stream.close()
                except Exception:
                    pass
        self._relay_connected = 0
        self._relay_auth_refresh = None
        self._relay_discovery_service = None
        self._relay_endpoint_states.clear()

    def _clear_host_state(self, *, host: Any) -> None:
        """Make a retired host unreachable before its context closes."""
        with self._state_lock:
            if self._host_object is not host:
                return
            self._host_object = None
            self._trio_token = None
            self._endpoint = None
            self._port = None
            self._host_generation += 1
            if self._automatic_lan_host:
                self._host = None
        self._ready.clear()

    def _transport_disconnected(self, *, transport_peer_id: str) -> None:
        """Apply a libp2p disconnect observation to ephemeral route state."""
        with self._candidate_lock:
            # A circuit switch closes the previous connection from inside the
            # replacement bind. That bind still owns its endpoint state.
            if transport_peer_id not in self._binding_inflight:
                self._binding_states.pop(transport_peer_id, None)
                self._notified_candidate_endpoints.pop(transport_peer_id, None)
        self._routing_table.mark_transport_unavailable(
            transport_peer_id=transport_peer_id
        )
        self._record_routing_event(
            event="route_unavailable",
            transport_peer_id=transport_peer_id,
            reason_type="last_connection_closed",
        )

    async def _transport_connected(self, *, transport_peer_id: str) -> None:
        """Bind one newly live connection when candidate endpoint evidence exists."""
        if transport_peer_id == self._peer_id or any(
            endpoint.rstrip("/").endswith(f"/p2p/{transport_peer_id}")
            for endpoint in self._relay_peers
        ):
            return
        with self._candidate_lock:
            candidate = self._candidate_infos.get(
                transport_peer_id,
                self._mdns_candidate_infos.get(transport_peer_id),
            )
        if candidate is None:
            host = self._host_object
            if host is None:
                return
            try:
                endpoint = _peerstore_endpoint(
                    host=host,
                    transport_peer_id=transport_peer_id,
                )
            except TransportError:
                return
            if not endpoint:
                return
            try:
                import multiaddr
                from libp2p.peer.peerinfo import info_from_p2p_addr

                candidate = info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            except Exception:
                return
        await self._connect_and_bind(candidate)

    async def _start_relay_services(
        self,
        *,
        host: Any,
        multiaddr: Any,
        services: AsyncExitStack,
    ) -> None:
        """Attach configured relay services; unavailable RSS must not disable local IPC/LAN.

        Keep credentials and targets for maintenance retries. Reservations remain
        gated on successful RSS authentication, including after initial denial.
        Invalid local configuration still aborts startup.
        """
        import trio
        from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
        from libp2p.relay.circuit_v2 import CircuitV2Protocol, CircuitV2Transport
        from libp2p.relay.circuit_v2.config import RelayConfig, RelayRole
        from libp2p.relay.circuit_v2.discovery import RelayDiscovery
        from libp2p.tools.anyio_service import background_trio_service

        adapter = self

        class RSSClientCircuitV2Protocol(CircuitV2Protocol):
            async def _send_stop_status(
                self,
                stream: Any,
                code: int,
                message: str,
                senderRecord: Any = None,
            ) -> None:
                # py-libp2p 0.7 supplies the source peer's record in the STOP
                # response, while the HOP validates it as the destination's
                # record and tears down the circuit. The record is optional;
                # omit it and retain Noise authentication on both legs plus
                # the end-to-end Noise upgrade through the opaque circuit.
                _ = senderRecord
                await super()._send_stop_status(stream, code, message, None)

        class RSSClientCircuitV2Transport(CircuitV2Transport):
            def listen_order(self) -> int:
                # TransportManager uses this ordering for dialing as well.
                return -100

            async def _dial_via_circuit_addr(self, circuit_ma: Any, peer_info: Any) -> Any:
                # py-libp2p 0.7's cached-address path reads until EOF, but an
                # accepted circuit must stay open for the Noise upgrade.
                import trio
                from libp2p.connection_types import ConnectionType
                from libp2p.network.connection.raw_connection import RawConnection
                from libp2p.relay.circuit_v2.transport import (
                    PROTOCOL_ID,
                    HopMessage,
                    RelayConnectionError,
                    StatusCode,
                    TrackedRawConnection,
                )

                relay_ma, destination = self.parse_circuit_ma(circuit_ma)
                if destination != peer_info.peer_id:
                    raise ConnectionError("circuit destination does not match peer")
                relay = info_from_p2p_addr(relay_ma)
                stream = await self.host.new_stream(relay.peer_id, [PROTOCOL_ID])
                try:
                    with trio.fail_after(TRANSPORT_IO_TIMEOUT_SECONDS):
                        await stream.write(HopMessage(
                            type=HopMessage.CONNECT, peer=destination.to_bytes(),
                        ).SerializeToString())
                        response = HopMessage()
                        response.ParseFromString(await stream.read(1024))
                    if response.status.code != StatusCode.OK:
                        raise RelayConnectionError(
                            "RSS circuit request rejected",
                            status_code=response.status.code,
                            status_msg="RSS circuit request rejected",
                        )
                    return TrackedRawConnection(
                        wrapped=RawConnection(
                            stream=stream, initiator=True,
                            connection_type=ConnectionType.RELAYED,
                            addresses=[circuit_ma],
                        ),
                        relay_id=relay.peer_id, tracker=self.performance_tracker,
                    )
                except BaseException:
                    with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS, shield=True):
                        await stream.reset()
                    raise

            async def dial(self, maddr: Any) -> Any:
                # py-libp2p 0.7 upgrades the circuit inside ``dial`` even
                # though Swarm also upgrades every ITransport result. Return
                # the raw circuit here and let Swarm perform the single
                # end-to-end Noise and muxer upgrade.
                relay_address, destination_peer_id = self.parse_circuit_ma(maddr)
                relay_info = info_from_p2p_addr(relay_address)
                adapter._record_routing_event(
                    event="rss_circuit_dial_started",
                    relay_peer_id=str(relay_info.peer_id),
                    transport_peer_id=str(destination_peer_id),
                )
                boundary_context = _mplex_circuit_boundary_context()
                token = boundary_context.set(True)
                try:
                    connection = await self.dial_peer_info(
                        PeerInfo(destination_peer_id, [maddr]),
                        relay_info=relay_info,
                    )
                    adapter._record_routing_event(
                        event="rss_circuit_established",
                        relay_peer_id=str(relay_info.peer_id),
                        transport_peer_id=str(destination_peer_id),
                    )
                    return connection
                finally:
                    boundary_context.reset(token)

        relay_config = RelayConfig(roles=RelayRole.CLIENT)
        protocol = RSSClientCircuitV2Protocol(host, allow_hop=False)
        relay_transport = RSSClientCircuitV2Transport(host, protocol, relay_config)
        # py-libp2p 0.7's TCP transport also claims composite circuit
        # multiaddrs. Give the more-specific circuit transport precedence so
        # the TCP prefix is not dialed as if it belonged to the destination.
        host.get_network().transport_manager.add_transport(relay_transport)
        await services.enter_async_context(background_trio_service(protocol))
        credentials = self._relay_auth or load_rss_relay_credentials_from_environment()
        if credentials is None:
            raise TransportUnavailable("RSS relay authentication is not configured")
        relay_targets = []
        for index, relay_address in enumerate(self._relay_peers):
            relay_info = info_from_p2p_addr(multiaddr.Multiaddr(relay_address))
            enrollment_primary = index == 0
            relay_targets.append((relay_info, enrollment_primary))
        try:
            credentials = await self._authenticate_relay_targets(
                host=host,
                relay_targets=relay_targets,
                credentials=credentials,
            )
        except TransportUnavailable:
            self._record_routing_event(event="rss_startup_unavailable")
        self._relay_auth_refresh = (tuple(relay_targets), credentials)
        # Discovery must not reserve independently of our authentication checks.
        discovery = RelayDiscovery(host, auto_reserve=False)
        relay_transport.discovery = discovery
        reserved = 0
        for relay_info, _ in relay_targets:
            if self._relay_endpoint_states.get(str(relay_info.peer_id)) != "authenticated":
                continue
            with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS):
                await discovery._add_relay(relay_info.peer_id)
                await discovery.make_reservation(relay_info.peer_id)
            relay_state = discovery.get_relay_info(relay_info.peer_id)
            if relay_state is not None and relay_state.has_reservation:
                reserved += 1
                self._record_routing_event(
                    event="rss_reservation_active",
                    transport_peer_id=str(relay_info.peer_id),
                )
        if reserved < 1:
            self._record_routing_event(event="rss_reservation_unavailable")
        self._relay_discovery_service = discovery
        await services.enter_async_context(background_trio_service(discovery))

    async def _authenticate_relay_targets(
        self,
        *,
        host: Any,
        relay_targets: list[tuple[Any, bool]],
        credentials: RSSRelayClientCredentials,
    ) -> RSSRelayClientCredentials:
        """Authenticate ordered endpoints while retaining failures and fallback state.

        ``auth_phases`` holds only the current stage label for each relay in
        this call. Failure events copy that label for a task exception and for
        a parent deadline that leaves the relay checking. Labels are
        ``host.connect`` or a control-exchange stage. The label is removed
        before HTTPS enrollment so that wait is not reported as the finished
        control read. Credentials, challenges, proofs, and payloads are not
        stored here.
        """
        import trio

        authenticated = 0
        completed = 0
        returned_credentials = credentials
        route_responses: list[tuple[Any, Mapping[str, Any]]] = []
        timed_out: set[str] = set()
        auth_phases: dict[str, str] = {}
        send_channel, receive_channel = trio.open_memory_channel[
            tuple[str, bool, RSSRelayClientCredentials | None]
        ](len(relay_targets))

        def record_authentication_failed(peer_id: str, error: str) -> None:
            """Record one failed attempt without adding secret material."""
            phase = auth_phases.get(peer_id)
            if phase is None:
                self._record_routing_event(
                    event="rss_authentication_failed",
                    transport_peer_id=peer_id,
                    error=error,
                )
                return
            self._record_routing_event(
                event="rss_authentication_failed",
                transport_peer_id=peer_id,
                error=error,
                phase=phase,
            )

        async def authenticate_one(relay_info: Any, enrollment_primary: bool) -> None:
            peer_id = str(relay_info.peer_id)
            result_credentials: RSSRelayClientCredentials | None = None
            succeeded = False
            try:
                auth_phases[peer_id] = "host.connect"
                await host.connect(relay_info)
                enrolled = await self._authenticate_rss_relay(
                    host=host,
                    relay_info=relay_info,
                    credentials=credentials,
                    allow_enrollment=enrollment_primary,
                    route_responses=route_responses,
                    auth_phases=auth_phases,
                )
                result_credentials = credentials
                # Primary authentication also completes an enrollment whose
                # response was lost; fallback alone must not consume the RET.
                if (enrolled or enrollment_primary) and credentials.enrollment_token_file:
                    clear_consumed_rss_enrollment_token(
                        token_path=credentials.enrollment_token_file
                    )
                    result_credentials = replace(
                        credentials,
                        enrollment_token=None,
                        enrollment_token_file=None,
                    )
                self._relay_endpoint_states[peer_id] = "authenticated"
                self._record_routing_event(
                    event="rss_authenticated",
                    transport_peer_id=peer_id,
                )
                succeeded = True
            except Exception as exc:
                if isinstance(exc, trio.TooSlowError) or isinstance(exc.__cause__, trio.TooSlowError):
                    timed_out.add(peer_id)
                self._relay_endpoint_states[peer_id] = f"failed:{exc}"
                record_authentication_failed(peer_id, str(exc))
            try:
                await send_channel.send((peer_id, succeeded, result_credentials))
            except (trio.BrokenResourceError, trio.ClosedResourceError):
                pass

        with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS * 2):
            async with trio.open_nursery() as nursery:
                for relay_info, enrollment_primary in relay_targets:
                    peer_id = str(relay_info.peer_id)
                    self._relay_endpoint_states[peer_id] = "checking"
                    auth_phases[peer_id] = "host.connect"
                    nursery.start_soon(
                        authenticate_one, relay_info, enrollment_primary
                    )
                while completed < len(relay_targets):
                    _peer_id, succeeded, result_credentials = await receive_channel.receive()
                    completed += 1
                    if succeeded:
                        authenticated += 1
                        # A secondary finishing later holds the original input;
                        # it must not restore a RET already cleared by primary.
                        if result_credentials is not None and result_credentials.enrollment_token_file is None:
                            returned_credentials = result_credentials

        await receive_channel.aclose()
        for relay_info, _ in relay_targets:
            peer_id = str(relay_info.peer_id)
            if self._relay_endpoint_states.get(peer_id) == "checking":
                timed_out.add(peer_id)
                error = "RSS authentication exchange timed out"
                self._relay_endpoint_states[peer_id] = f"failed:{error}"
                record_authentication_failed(peer_id, error)
        async def retire_timed_out(relay_info: Any) -> None:
            """Discard one failed relay's ephemeral state; never touch stored envelopes."""
            peer_id = str(relay_info.peer_id)
            self._relay_control_streams.pop(peer_id, None)
            discovery = self._relay_discovery_service
            if discovery is not None:
                state = discovery.get_relay_info(relay_info.peer_id)
                if state is not None:
                    state.has_reservation = False
                    state.reservation_expires_at = None
            try:
                # Closing the peer also disposes its streams. Do not let a stuck
                # close prevent healthy alternate endpoints from being used.
                with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS, shield=True) as cleanup:
                    await host.get_network().close_peer(relay_info.peer_id)
                event = "rss_connection_retirement_timeout" if cleanup.cancelled_caught else "rss_connection_retired"
            except Exception:
                event = "rss_connection_retirement_failed"
            self._record_routing_event(event=event, transport_peer_id=peer_id)

        async with trio.open_nursery() as cleanup_nursery:
            for relay_info, _ in relay_targets:
                if str(relay_info.peer_id) in timed_out:
                    cleanup_nursery.start_soon(retire_timed_out, relay_info)

        # A fast secondary must not be discarded while a stalled primary is
        # still "checking". Select routes only after all outcomes are known.
        for relay_info, response in route_responses:
            peer_id = str(relay_info.peer_id)
            if self._relay_endpoint_states.get(peer_id) != "authenticated":
                continue
            try:
                self._queue_rss_route_candidates(host=host, relay_info=relay_info, response=response)
            except TransportUnavailable as exc:
                self._relay_endpoint_states[peer_id] = f"failed:{exc}"
                authenticated -= 1
                self._record_routing_event(event="rss_authentication_failed", transport_peer_id=peer_id, error=str(exc))
        self._relay_connected = authenticated
        if authenticated < 1:
            raise TransportUnavailable("no configured RSS endpoint authenticated")
        return returned_credentials

    async def _authenticate_rss_relay(
        self,
        *,
        host: Any,
        relay_info: Any,
        credentials: RSSRelayClientCredentials,
        allow_enrollment: bool = False,
        route_responses: list[tuple[Any, Mapping[str, Any]]] | None = None,
        auth_phases: dict[str, str] | None = None,
    ) -> bool:
        """Authenticate to one RSS host before its reservation service starts."""
        enrollment_response_was_used = False
        response = await self._rss_auth_exchange(
            host=host,
            relay_info=relay_info,
            request=rss_auth_control_request(
                operation="session_challenge",
                entitlement_id=credentials.entitlement_id,
                connection_id=credentials.connection_id,
            ),
            proof_builder=lambda challenge: build_rss_session_proof(
                challenge=challenge,
                credentials=credentials,
                transport_identity=str(host.get_id()),
            ),
            expected_challenge_protocol=RSS_SESSION_AUTH_PROTOCOL,
            auth_phases=auth_phases,
        )
        if response.get("status") == "enrollment_required":
            if not allow_enrollment:
                raise TransportUnavailable("RSS projection is not available on this endpoint")
            token = credentials.enrollment_token
            if token is None:
                raise TransportUnavailable("RSS enrollment is required")
            import trio

            # The control read already finished. Do not keep that stage label
            # across the separate HTTPS enrollment wait.
            if auth_phases is not None:
                auth_phases.pop(str(relay_info.peer_id), None)
            try:
                await trio.to_thread.run_sync(
                    lambda: perform_rss_https_enrollment(credentials=credentials)
                )
            except RSSAuthenticationError as exc:
                raise TransportUnavailable(str(exc)) from exc
            enrollment_response_was_used = True
            response = await self._rss_auth_exchange(
                host=host,
                relay_info=relay_info,
                request=rss_auth_control_request(
                    operation="session_challenge",
                    entitlement_id=credentials.entitlement_id,
                    connection_id=credentials.connection_id,
                ),
                proof_builder=lambda challenge: build_rss_session_proof(
                    challenge=challenge,
                    credentials=credentials,
                    transport_identity=str(host.get_id()),
                ),
                expected_challenge_protocol=RSS_SESSION_AUTH_PROTOCOL,
                auth_phases=auth_phases,
            )
        if response.get("protocol") != RSS_SESSION_READY_PROTOCOL or response.get("status") != "ok":
            raise TransportUnavailable("RSS session authentication did not become ready")
        if route_responses is None:
            self._queue_rss_route_candidates(host=host, relay_info=relay_info, response=response)
        else:
            route_responses.append((relay_info, response))
        return enrollment_response_was_used

    def _queue_rss_route_candidates(
        self, *, host: Any, relay_info: Any, response: Mapping[str, Any]
    ) -> None:
        """Queue same-entitlement circuit routes returned by an authenticated RSS."""
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        peer_ids = response.get("peer_transport_ids", [])
        if (
            not isinstance(peer_ids, list)
            or len(peer_ids) > 64
            or any(not isinstance(peer_id, str) or not peer_id for peer_id in peer_ids)
        ):
            raise TransportUnavailable("RSS peer route response is invalid")
        if not peer_ids:
            return
        relay_peer_id = str(relay_info.peer_id)
        relay_rank = next(
            (
                index
                for index, endpoint in enumerate(self._relay_peers)
                if f"/p2p/{relay_peer_id}" in endpoint
            ),
            len(self._relay_peers),
        )
        relay_base = str(relay_info.addrs[0]).rstrip("/")
        for peer_id in peer_ids:
            if peer_id == self._peer_id:
                continue
            endpoint = (
                f"{relay_base}/p2p/{relay_peer_id}"
                f"/p2p-circuit/p2p/{peer_id}"
            )
            try:
                candidate = info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            except Exception as exc:
                raise TransportUnavailable("RSS peer route response is invalid") from exc
            with self._candidate_lock:
                current_rank = self._relay_candidate_ranks.get(peer_id)
                notified_endpoint = self._notified_candidate_endpoints.get(peer_id)
                selected_candidate = self._candidate_infos.get(peer_id)
                # Candidate state is the selection evidence; notification state
                # is cleared on a disconnected idle route so it can be retried.
                selected_endpoint = (
                    _peer_endpoint(peer_info=selected_candidate)
                    if selected_candidate is not None
                    else notified_endpoint
                )
                if (
                    current_rank is not None
                    and selected_endpoint is not None
                    and current_rank < relay_rank
                ):
                    current_relay_endpoint = selected_endpoint.split(
                        "/p2p-circuit/", 1
                    )[0]
                    current_relay_peer_id = current_relay_endpoint.rsplit(
                        "/p2p/", 1
                    )[-1]
                    current_state = self._relay_endpoint_states.get(
                        current_relay_peer_id, ""
                    )
                    if not current_state.startswith("failed:"):
                        continue
                if notified_endpoint == endpoint:
                    continue
                self._relay_candidate_ranks[peer_id] = relay_rank
                self._discovery_candidates.add(peer_id)
                self._candidate_infos[peer_id] = candidate
                self._notified_candidate_endpoints[peer_id] = endpoint
            self._record_routing_event(
                event="rss_route_discovered",
                transport_peer_id=peer_id,
                relay_transport_peer_id=relay_peer_id,
            )
            self._spawn_scope_task(self._connect_and_bind, candidate)

    async def _rss_auth_exchange(
        self,
        *,
        host: Any,
        relay_info: Any,
        request: dict[str, object],
        proof_builder: Callable[[RSSAuthenticationChallenge], dict[str, object]] | None = None,
        expected_challenge_protocol: str | None = None,
        auth_phases: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Run one bounded RSS control exchange over a Noise-authenticated stream.

        When ``auth_phases`` is supplied, this relay's entry is the in-flight
        stage: ``opening_rss_stream``, ``writing_request``,
        ``reading_challenge``, ``writing_proof``, ``reading_response``, or
        ``closing_prior_retained_stream``. Only that label is stored.
        """
        import trio

        from secrets_kit.protocol.rss_auth import RSS_AUTH_STREAM_PROTOCOL

        stream = None
        retain_stream = False
        peer_id = str(relay_info.peer_id)

        def mark(phase: str) -> None:
            if auth_phases is not None:
                auth_phases[peer_id] = phase

        try:
            with trio.fail_after(TRANSPORT_IO_TIMEOUT_SECONDS):
                mark("opening_rss_stream")
                stream = await host.new_stream(
                    relay_info.peer_id, [RSS_AUTH_STREAM_PROTOCOL]
                )
                mark("writing_request")
                await stream.write(encode_rss_auth_frame(request))
                mark("reading_challenge")
                response = parse_rss_auth_response(await _read_stream_frame(stream))
                if proof_builder is None:
                    return response
                if response.get("status") != "challenge":
                    return response
                raw_challenge = response.get("challenge")
                if not isinstance(raw_challenge, dict) or expected_challenge_protocol is None:
                    raise RSSAuthenticationError("RSS authentication challenge is missing")
                challenge = RSSAuthenticationChallenge.from_mapping(
                    raw_challenge,
                    expected_protocol=expected_challenge_protocol,
                )
                mark("writing_proof")
                await stream.write(encode_rss_auth_frame(proof_builder(challenge)))
                mark("reading_response")
                response = parse_rss_auth_response(await _read_stream_frame(stream))
                if response.get("protocol") == RSS_SESSION_READY_PROTOCOL and response.get("status") == "ok":
                    previous = self._relay_control_streams.get(peer_id)
                    self._relay_control_streams[peer_id] = stream
                    retain_stream = True
                    if previous is not None and previous is not stream:
                        mark("closing_prior_retained_stream")
                        try:
                            await previous.close()
                        except Exception:
                            pass
                return response
        except trio.TooSlowError as exc:
            raise TransportUnavailable("RSS authentication exchange timed out") from exc
        except RSSAuthenticationError as exc:
            raise TransportUnavailable(str(exc)) from exc
        finally:
            if stream is not None and not retain_stream:
                # The ordered-endpoint deadline may already have cancelled us.
                # Still release this stream, within the existing cleanup bound.
                with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS, shield=True):
                    await stream.close()

    async def _send_async(
        self,
        payload: bytes,
        endpoint: str,
        generation: int | None = None,
    ) -> TransportReceipt:
        import multiaddr
        import trio
        from libp2p.peer.peerinfo import info_from_p2p_addr

        with self._state_lock:
            host = self._host_object
            current_generation = self._host_generation
        if host is None or (
            generation is not None and generation != current_generation
        ):
            raise TransportError("libp2p host is not running")
        route_address = multiaddr.Multiaddr(endpoint)
        peer_info = info_from_p2p_addr(route_address)
        stream = None
        try:
            with trio.fail_after(TRANSPORT_IO_TIMEOUT_SECONDS):
                if "/p2p-circuit/" in endpoint:
                    # ``BasicHost.connect`` treats the TCP prefix as a direct address and
                    # therefore authenticates the relay socket as the destination peer.
                    # Preserve the complete circuit address so the transport manager
                    # selects CircuitV2Transport and Noise terminates at the destination.
                    host.get_peerstore().add_addrs(
                        peer_info.peer_id,
                        [route_address],
                        120,
                    )
                else:
                    await host.connect(peer_info)
                stream = await host.new_stream(peer_info.peer_id, [LIBP2P_PROTOCOL])
                await stream.write(struct.pack(">I", len(payload)) + payload)
                response = await _read_stream_frame(stream)
                value = json.loads(response.decode("utf-8"))
                if (
                    value.get("status") == "error"
                    and value.get("error") == "runtime_handoff_failed"
                ):
                    raise _RemoteDeliveryRejected(
                        "remote runtime rejected delivery"
                    )
                if value.get("status") != "ok":
                    raise TransportError(str(value))
                return TransportReceipt(
                    delivered=True,
                    transport=self.name,
                    endpoint=endpoint,
                )
        except trio.TooSlowError as exc:
            raise TransportUnavailable("libp2p send timed out") from exc
        finally:
            if stream is not None:
                # A send deadline or caller cancellation may already be active.
                # Shield cleanup, but retain a bound so cleanup cannot become
                # another permanently stuck transport task.
                with trio.move_on_after(
                    TRANSPORT_IO_TIMEOUT_SECONDS,
                    shield=True,
                ):
                    try:
                        await stream.close()
                    except Exception:
                        reset = getattr(stream, "reset", None)
                        if reset is not None:
                            try:
                                await reset()
                            except Exception:
                                pass

    def _start_mdns_discovery(
        self,
        *,
        host: Any,
        trio: Any,
        bound_host: str | None = None,
    ) -> None:
        """Advertise the bound port and own lifecycle-scoped LAN candidates."""
        bound_host = bound_host or self._host
        if bound_host is None:
            raise TransportError("mDNS discovery requires a bound listener host")
        token = self._trio_token

        def advertised_listener_addresses() -> list[str]:
            with self._state_lock:
                is_current_host = (
                    self._host_object is host and self._host == bound_host
                )
            if not is_current_host:
                return []
            if (
                self._automatic_lan_host
                and _lan_ipv4_addresses() != [bound_host]
            ):
                return []
            return [bound_host]

        def discovered(peer_info: Any) -> None:
            if (
                self._host_object is not host
                or self._discovery_service is None
                or str(peer_info.peer_id) == self._peer_id
            ):
                return
            with self._candidate_lock:
                peer_id = str(peer_info.peer_id)
                self._mdns_candidate_infos[peer_id] = peer_info
                retry_candidate = self._candidate_infos.get(peer_id, peer_info)
                candidate_endpoint = _peer_endpoint(peer_info=retry_candidate)
                if (
                    self._notified_candidate_endpoints.get(peer_id)
                    == candidate_endpoint
                ):
                    return
                state = self._binding_states.get(peer_id)
                if (
                    state is not None
                    and state[0] == candidate_endpoint
                    and state[1] in {"healthy", "inflight", "rejected"}
                ):
                    return
                self._notified_candidate_endpoints[peer_id] = candidate_endpoint
            addresses = _peer_addresses(peer_info=peer_info)
            self._record_routing_event(
                event="mdns_advertisement_received",
                transport_peer_id=peer_id,
                addresses=addresses,
            )

            def schedule() -> None:
                with self._candidate_lock:
                    if self._host_object is not host or self._discovery_service is None:
                        return
                    current = self._candidate_infos.get(
                        peer_id,
                        self._mdns_candidate_infos.get(peer_id),
                    )
                    if current is not retry_candidate:
                        return
                self._spawn_scope_task(self._connect_and_bind, retry_candidate)

            try:
                if token is not None:
                    token.run_sync_soon(schedule)
            except (RuntimeError, trio.RunFinishedError):
                LOGGER.debug("discarded mDNS event after libp2p shutdown")

        def removed(peer_id: str) -> None:
            if self._host_object is not host or self._discovery_service is None:
                return
            with self._candidate_lock:
                self._mdns_candidate_infos.pop(peer_id, None)
            self._record_routing_event(
                event="mdns_advertisement_removed",
                transport_peer_id=peer_id,
            )

        options: dict[str, Any] = {}
        if self._mdns_interfaces is not None:
            options["interfaces"] = self._mdns_interfaces
        discovery = None
        try:
            from secrets_kit.daemon.mdns import DaemonMDNS

            discovery = DaemonMDNS(
                peer_id=str(self._peer_id),
                port=int(self._port or 0),
                addresses=advertised_listener_addresses,
                on_candidate=discovered,
                on_remove=removed,
                **options,
            )
            self._discovery_service = discovery
            discovery.start()
        except Exception as exc:
            self._discovery_service = None
            if discovery is not None:
                try:
                    discovery.stop()
                except Exception:
                    LOGGER.debug("mDNS cleanup failed after startup error", exc_info=True)
            LOGGER.error("mDNS discovery unavailable: %s", exc)
            self._record_routing_event(
                event="mdns_advertisement_unavailable",
                error=(
                    f"{type(exc).__name__}:{exc.errno}"
                    if isinstance(exc, OSError)
                    else type(exc).__name__
                ),
            )
            return
        advertised_addresses = list(discovery.advertised_addresses)
        self._record_routing_event(
            event="mdns_advertisement_started",
            transport_peer_id=str(self._peer_id),
            addresses=advertised_addresses,
            port=int(self._port or 0),
        )

    def _queue_bootstrap_candidates(self, *, multiaddr: Any) -> None:
        """Bind configured libp2p bootstrap candidates after host startup."""
        from libp2p.peer.peerinfo import info_from_p2p_addr

        for endpoint in self._bootstrap:
            peer_info = info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            transport_peer_id = str(peer_info.peer_id)
            if transport_peer_id == self._peer_id:
                continue
            with self._candidate_lock:
                self._discovery_candidates.add(transport_peer_id)
                self._candidate_infos[transport_peer_id] = peer_info
            self._spawn_scope_task(self._connect_and_bind, peer_info)

    async def _connect_and_bind(self, peer_info: Any) -> None:
        """Bound candidate connection and authentication so discovery can retry."""
        import trio

        with trio.move_on_after(RUNTIME_BINDING_TIMEOUT_SECONDS) as deadline:
            await self._bind_candidate(peer_info)
        if deadline.cancelled_caught:
            self._record_routing_event(
                event="identity_binding_timeout",
                direction="outbound",
                transport_peer_id=str(peer_info.peer_id),
            )

    async def _bind_candidate(self, peer_info: Any) -> None:
        """Connect one discovered peer and establish its admitted node mapping.

        Cancellation removes only this attempt's inflight tuple when that same
        object is still stored, and forgets a notification cache entry only when
        it still names this attempt's endpoint. A newer binding tuple, healthy
        or rejected state, or different notification endpoint is left in place.
        This method does not schedule another attempt.
        """
        host = self._host_object
        if host is None:
            return
        transport_peer_id = str(peer_info.peer_id)
        addresses = _peer_addresses(peer_info=peer_info)
        endpoint = _peer_endpoint(peer_info=peer_info)
        with self._candidate_lock:
            selected_candidate = self._candidate_infos.get(transport_peer_id)
            if (
                transport_peer_id in self._relay_candidate_ranks
                and selected_candidate is not None
                and _peer_endpoint(peer_info=selected_candidate) != endpoint
            ):
                return
            # Endpoint-specific binding state is insufficient here: primary and
            # secondary RSS callbacks identify the same destination peer.
            if transport_peer_id in self._binding_inflight:
                return
            state = self._binding_states.get(transport_peer_id)
            if state is not None and state[0] == endpoint and state[1] in {
                "healthy",
                "inflight",
                "rejected",
            }:
                return
            self._binding_inflight.add(transport_peer_id)
            owned_state = (endpoint, "inflight")
            self._binding_states[transport_peer_id] = owned_state
        phase = "connect"
        self._record_routing_event(
            event="identity_binding_started",
            direction="outbound",
            transport_peer_id=transport_peer_id,
            addresses=addresses,
        )
        try:
            circuit_addresses = [
                address
                for address in peer_info.addrs
                if "/p2p-circuit" in str(address)
            ]
            if circuit_addresses:
                import multiaddr

                endpoint = _peer_endpoint(peer_info=peer_info)
                previous = self._circuit_dial_endpoints.get(transport_peer_id)
                if previous is not None and previous != endpoint:
                    # new_stream otherwise reuses the previous relay's cached
                    # connection without dialing the newly selected circuit.
                    phase = "close_previous_circuit"
                    self._record_routing_event(
                        event="circuit_route_switch_started",
                        transport_peer_id=transport_peer_id,
                    )
                    await host.get_network().close_peer(peer_info.peer_id)
                _replace_selected_peerstore_address(
                    peerstore=host.get_peerstore(),
                    peer_id=peer_info.peer_id,
                    address=multiaddr.Multiaddr(endpoint),
                )
                self._circuit_dial_endpoints[transport_peer_id] = endpoint
            else:
                await host.connect(peer_info)
                self._record_routing_event(
                    event="transport_connected",
                    direction="outbound",
                    transport_peer_id=transport_peer_id,
                    addresses=addresses,
                )
                phase = "identify"
                await self._wait_for_identify(peer_id=peer_info.peer_id)
                self._record_routing_event(
                    event="identify_completed",
                    direction="outbound",
                    transport_peer_id=transport_peer_id,
                    addresses=addresses,
                    protocols=[
                        str(protocol)
                        for protocol in host.get_peerstore().get_protocols(peer_info.peer_id)
                    ],
                )
            phase = "open_binding_stream"
            stream = await host.new_stream(peer_info.peer_id, [IDENTITY_BINDING_PROTOCOL])
            challenge = secrets.token_hex(32)
            phase = "read_remote_claim"
            await stream.write(_frame(_json_bytes({"version": 1, "challenge": challenge})))
            response = _json_object(await _read_stream_frame(stream))
            phase = "verify_remote_claim"
            remote_node_id = await self._verify_claim(
                claim=response.get("claim"),
                challenge=challenge,
                transport_identity=transport_peer_id,
            )
            self._record_routing_event(
                event="identity_binding_verified",
                direction="outbound",
                transport_peer_id=transport_peer_id,
                node_id=remote_node_id,
                addresses=addresses,
            )
            remote_challenge = response.get("challenge")
            if not isinstance(remote_challenge, str):
                raise TransportError("transport binding response omitted challenge")
            phase = "sign_local_claim"
            local_claim = await self._sign_claim(
                challenge=remote_challenge,
                transport_identity=str(self._peer_id),
            )
            phase = "await_remote_acceptance"
            await stream.write(_frame(_json_bytes({"version": 1, "claim": local_claim})))
            accepted = _json_object(await _read_stream_frame(stream))
            await stream.close()
            if accepted.get("status") != "accepted":
                raise TransportError("transport binding was not accepted")
            phase = "install_route"
            route = self._routing_table.install_discovered(
                peer_id=remote_node_id,
                endpoint=endpoint,
                transport_peer_id=transport_peer_id,
                adapter=self.name,
                source="libp2p_discovery",
            )
            with self._candidate_lock:
                if self._binding_states.get(transport_peer_id) is owned_state:
                    self._binding_states[transport_peer_id] = (endpoint, "healthy")
            self._record_route_available(
                direction="outbound",
                transport_peer_id=transport_peer_id,
                node_id=remote_node_id,
                addresses=addresses,
                endpoint=route.endpoint,
                source=route.source,
            )
        except Exception as exc:
            with self._candidate_lock:
                if self._binding_states.get(transport_peer_id) is owned_state:
                    self._binding_states[transport_peer_id] = (endpoint, "rejected")
            self._rejected_bindings += 1
            self._record_routing_event(
                event="identity_binding_rejected",
                direction="outbound",
                transport_peer_id=transport_peer_id,
                addresses=addresses,
                phase=phase,
                reason=str(exc),
                reason_type=type(exc).__name__,
                reason_repr=repr(exc)[:1024],
                reason_chain=_exception_chain(exc),
            )
            LOGGER.info("discovered peer was not admitted for routing: peer=%s error=%s", transport_peer_id, exc)
        except BaseException:
            # Trio nursery cancellation can arrive as a BaseExceptionGroup.
            # Drop only this attempt's inflight tuple and its matching
            # notification, then propagate. A later RSS event can queue again.
            with self._candidate_lock:
                if self._binding_states.get(transport_peer_id) is owned_state:
                    owned_endpoint = owned_state[0]
                    self._binding_states.pop(transport_peer_id, None)
                    if (
                        self._notified_candidate_endpoints.get(transport_peer_id)
                        == owned_endpoint
                    ):
                        self._notified_candidate_endpoints.pop(transport_peer_id, None)
            self._record_routing_event(
                event="identity_binding_interrupted",
                direction="outbound",
                transport_peer_id=transport_peer_id,
                phase=phase,
            )
            raise
        finally:
            pending_candidate = None
            with self._candidate_lock:
                self._binding_inflight.discard(transport_peer_id)
                selected_candidate = self._candidate_infos.get(transport_peer_id)
                if selected_candidate is not None:
                    selected_endpoint = _peer_endpoint(
                        peer_info=selected_candidate
                    )
                    if (
                        selected_endpoint != endpoint
                        and self._notified_candidate_endpoints.get(
                            transport_peer_id
                        )
                        == selected_endpoint
                    ):
                        pending_candidate = selected_candidate
            if pending_candidate is not None:
                # The preferred endpoint changed while this peer was busy.
                self._spawn_scope_task(
                    self._connect_and_bind,
                    pending_candidate,
                )

    async def _wait_for_identify(self, *, peer_id: Any) -> None:
        """Wait until built-in Identify advertises the binding protocol."""
        import trio

        host = self._host_object
        if host is None:
            raise TransportError("libp2p host is not running")
        deadline = trio.current_time() + TRANSPORT_IO_TIMEOUT_SECONDS
        while trio.current_time() < deadline:
            protocols = host.get_peerstore().get_protocols(peer_id)
            if IDENTITY_BINDING_PROTOCOL in protocols:
                return
            await trio.sleep(0.05)
        raise TransportError("libp2p Identify did not complete before binding")

    async def _handle_binding_stream(self, stream: Any) -> None:
        """Authenticate one inbound binding stream and install its route.

        The stream supplies the post-Identify peer and control frames. A verified
        claim installs a discovered route; an authentication failure records a
        rejection. An outbound attempt that is still in flight does not discard
        this exchange before challenge, signature, or admission checks.
        ``RUNTIME_BINDING_TIMEOUT_SECONDS`` bounds the exchange and
        ``TRANSPORT_IO_TIMEOUT_SECONDS`` bounds stream close. Cancellation
        propagates after this attempt releases only the inflight tuple object it
        still owns. The deadline does not skip challenge, signature,
        transport-identity, or admission checks, and it does not replace a
        verified circuit route. A missing, expired, or empty peerstore record
        supplies no reverse route and is not refreshed; the exchange continues
        with an empty endpoint. After admission, a proven relayed connection
        does not install an Identify listen address. It reuses the selected
        full circuit already stored for that transport peer. Relayed metadata
        without that selection completes admission and installs no reverse
        route. A direct connection, unknown type, or missing connection
        metadata keeps the peerstore endpoint and does not adopt a circuit
        that was only selected.
        """
        import trio

        remote_transport_id = str(stream.muxed_conn.peer_id)
        endpoint = ""
        addresses: list[str] = []
        phase = "peerstore_endpoint"
        owned_state: tuple[str, str] | None = None
        self._record_routing_event(
            event="identity_binding_started",
            direction="inbound",
            transport_peer_id=remote_transport_id,
            addresses=addresses,
        )

        def release_owned_inflight() -> None:
            """Drop this attempt's inflight tuple without replacing a newer one."""
            if owned_state is None:
                return
            with self._candidate_lock:
                if self._binding_states.get(remote_transport_id) is not owned_state:
                    return
                self._binding_states[remote_transport_id] = (
                    owned_state[0],
                    "rejected",
                )

        try:
            with trio.move_on_after(RUNTIME_BINDING_TIMEOUT_SECONDS) as deadline:
                try:
                    # This helper raises TransportError only when address
                    # evidence is missing, expired, or empty. Other failures
                    # still reject the exchange. Do not refresh that record.
                    try:
                        endpoint = _peerstore_endpoint(
                            host=self._host_object,
                            transport_peer_id=stream.muxed_conn.peer_id,
                        )
                    except TransportError:
                        endpoint = ""
                    addresses = [endpoint]
                    # Take this attempt's tuple and authenticate even when an
                    # outbound attempt already published an inflight tuple.
                    # Success, rejection, and cancellation still mutate state
                    # only while that same object remains stored.
                    with self._candidate_lock:
                        owned_state = (endpoint, "inflight")
                        self._binding_states[remote_transport_id] = owned_state
                    phase = "read_binding_request"
                    request = _json_object(await _read_stream_frame(stream))
                    challenge = request.get("challenge")
                    if not isinstance(challenge, str):
                        raise TransportError("transport binding request omitted challenge")
                    phase = "sign_local_claim"
                    local_claim = await self._sign_claim(
                        challenge=challenge,
                        transport_identity=str(self._peer_id),
                    )
                    response_challenge = secrets.token_hex(32)
                    phase = "read_remote_claim"
                    await stream.write(
                        _frame(
                            _json_bytes(
                                {
                                    "version": 1,
                                    "challenge": response_challenge,
                                    "claim": local_claim,
                                }
                            )
                        )
                    )
                    response = _json_object(await _read_stream_frame(stream))
                    phase = "verify_remote_claim"
                    remote_node_id = await self._verify_claim(
                        claim=response.get("claim"),
                        challenge=response_challenge,
                        transport_identity=remote_transport_id,
                    )
                    self._record_routing_event(
                        event="identity_binding_verified",
                        direction="inbound",
                        transport_peer_id=remote_transport_id,
                        node_id=remote_node_id,
                        addresses=addresses,
                    )
                    phase = "install_route"
                    # Identify listen addresses are authenticated advertisements,
                    # not the path this stream used. Keep an already verified
                    # circuit. Otherwise a proven relay reuses the selected full
                    # circuit for this peer, or installs nothing. Direct and
                    # unknown connections keep the peerstore endpoint.
                    current = self._routing_table.discovered(
                        peer_id=remote_node_id,
                        adapter=self.name,
                    )
                    if (
                        current is not None
                        and current.transport_peer_id == remote_transport_id
                        and "/p2p-circuit/" in current.endpoint
                        and "/p2p-circuit/" not in endpoint
                    ):
                        endpoint = str(current.endpoint)
                    elif "/p2p-circuit/" not in endpoint and _proven_relayed_circuit(
                        stream=stream,
                        transport_peer_id=remote_transport_id,
                    ):
                        endpoint = _selected_circuit_for_peer(
                            selected=self._circuit_dial_endpoints.get(
                                remote_transport_id, ""
                            ),
                            transport_peer_id=remote_transport_id,
                        )
                    if endpoint:
                        route = self._routing_table.install_discovered(
                            peer_id=remote_node_id,
                            endpoint=endpoint,
                            transport_peer_id=remote_transport_id,
                            adapter=self.name,
                            source="libp2p_discovery",
                        )
                        self._record_route_available(
                            direction="inbound",
                            transport_peer_id=remote_transport_id,
                            node_id=remote_node_id,
                            addresses=addresses,
                            endpoint=route.endpoint,
                            source=route.source,
                        )
                    with self._candidate_lock:
                        if self._binding_states.get(remote_transport_id) is owned_state:
                            self._binding_states[remote_transport_id] = (
                                endpoint,
                                "healthy",
                            )
                    await stream.write(
                        _frame(_json_bytes({"version": 1, "status": "accepted"}))
                    )
                except Exception as exc:
                    release_owned_inflight()
                    self._rejected_bindings += 1
                    self._record_routing_event(
                        event="identity_binding_rejected",
                        direction="inbound",
                        transport_peer_id=remote_transport_id,
                        addresses=addresses,
                        phase=phase,
                        reason=str(exc),
                        reason_type=type(exc).__name__,
                        reason_repr=repr(exc)[:1024],
                        reason_chain=_exception_chain(exc),
                    )
                    LOGGER.info(
                        "rejected transport identity binding: peer=%s error=%s",
                        remote_transport_id,
                        exc,
                    )
                    try:
                        await stream.write(
                            _frame(_json_bytes({"version": 1, "status": "rejected"}))
                        )
                    except Exception:
                        pass
                except BaseException:
                    # Cancellation and the binding deadline both arrive here.
                    # Release only this attempt, then preserve the interruption.
                    release_owned_inflight()
                    self._record_routing_event(
                        event="identity_binding_interrupted",
                        direction="inbound",
                        transport_peer_id=remote_transport_id,
                        phase=phase,
                    )
                    raise
            if deadline.cancelled_caught:
                self._record_routing_event(
                    event="identity_binding_timeout",
                    direction="inbound",
                    transport_peer_id=remote_transport_id,
                )
        finally:
            # A deadline or caller cancellation may already be active. Shield
            # close, but keep it bounded so cleanup cannot stall the handler.
            with trio.move_on_after(TRANSPORT_IO_TIMEOUT_SECONDS, shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass

    def _record_route_available(
        self,
        *,
        transport_peer_id: str,
        **details: Any,
    ) -> None:
        """Record authenticated availability without waking retry work recursively."""
        with self._candidate_lock:
            retry_driven = any(
                peer_id == transport_peer_id
                for peer_id, _marker in self._delivery_retry_bindings
            )
        self._record_routing_event(
            event="route_installed",
            notify=not retry_driven,
            transport_peer_id=transport_peer_id,
            **details,
        )

    def _record_routing_event(
        self,
        *,
        event: str,
        notify: bool = True,
        **details: Any,
    ) -> None:
        """Retain one bounded, secret-free routing decision for diagnosis."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **details,
        }
        with self._candidate_lock:
            self._routing_events.append(record)
        services = self._services
        if services is not None and notify:
            services.observe(record)

    async def _sign_claim(self, *, challenge: str, transport_identity: str) -> dict[str, Any]:
        """Ask the runtime-owned service to sign opaque binding material."""
        import trio

        services = self._services
        if services is None:
            raise TransportError("transport services are unavailable")
        return await trio.to_thread.run_sync(
            services.sign_transport_binding,
            challenge,
            transport_identity,
        )

    async def _verify_claim(
        self,
        *,
        claim: object,
        challenge: str,
        transport_identity: str,
    ) -> str:
        """Ask the runtime to validate a remote admitted-node signature."""
        import trio

        if not isinstance(claim, dict):
            raise TransportError("transport binding response omitted claim")
        if claim.get("transport_identity") != transport_identity:
            raise TransportError("transport binding identity does not match connection")
        services = self._services
        if services is None:
            raise TransportError("transport services are unavailable")
        return await trio.to_thread.run_sync(
            services.verify_transport_binding,
            claim,
            challenge,
            transport_identity,
        )

    async def _handle_stream(self, stream: Any) -> None:
        try:
            payload = await _read_stream_frame(stream)
            services = self._services
            if services is None:
                response = _response_bytes(status="error", error="transport_not_ready")
            else:
                response, _ = services.frame_handler(payload, self.name)
            await stream.write(_frame(response))
        except Exception as exc:
            LOGGER.warning("libp2p opaque stream failed: %s", exc)
            try:
                await stream.write(_frame(_response_bytes(status="error", error="transport_failed")))
            except Exception:
                pass
        finally:
            try:
                await stream.close()
            except Exception:
                pass


def _frame(payload: bytes) -> bytes:
    _validate_payload(payload)
    return struct.pack(">I", len(payload)) + payload


def _json_bytes(value: dict[str, Any]) -> bytes:
    """Serialize one bounded transport-control message."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_object(payload: bytes) -> dict[str, Any]:
    """Decode one transport-control object without accepting application data."""
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict) or value.get("version") != 1:
        raise TransportError("invalid transport binding control message")
    return value


def _runtime_sign_binding(challenge: str, transport_identity: str) -> dict[str, Any]:
    """Invoke the transport-neutral runtime signing operation."""
    value = _invoke_runtime_binding(
        operation="sign-transport-binding",
        request={"challenge": challenge, "transport_identity": transport_identity},
    )
    claim = value.get("claim")
    if not isinstance(claim, dict):
        raise TransportError("runtime returned no transport binding claim")
    return claim


def _runtime_verify_binding(claim: object, challenge: str, transport_identity: str) -> str:
    """Invoke the transport-neutral runtime binding-verification operation."""
    value = _invoke_runtime_binding(
        operation="verify-transport-binding",
        request={
            "claim": claim,
            "expected_challenge": challenge,
            "expected_transport_identity": transport_identity,
        },
    )
    node_id = value.get("node_id")
    if not isinstance(node_id, str):
        raise TransportError("runtime rejected transport identity binding")
    return node_id


def _invoke_runtime_binding(*, operation: str, request: dict[str, Any]) -> dict[str, Any]:
    """Call a bounded hidden runtime operation without importing runtime code."""
    completed = subprocess.run(
        [sys.executable, "-m", "secrets_kit.cli", "internal", operation],
        input=_json_bytes(request),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=RUNTIME_BINDING_TIMEOUT_SECONDS,
        check=False,
        env=dict(os.environ),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 512:
            detail = detail[:512] + "..."
        raise TransportError(
            detail or "runtime transport binding operation rejected request"
        )
    return _json_object(completed.stdout)


def _peer_endpoint(*, peer_info: Any) -> str:
    """Return the first discovered address with its authenticated peer ID."""
    if not peer_info.addrs:
        raise TransportError("discovered peer has no address")
    return _append_peer_id(endpoint=str(peer_info.addrs[0]), peer_id=str(peer_info.peer_id))


def _peer_addresses(*, peer_info: Any) -> list[str]:
    """Return discovered candidate multiaddrs as safe diagnostic strings."""
    return [str(address) for address in getattr(peer_info, "addrs", ())]


def _replace_selected_peerstore_address(*, peerstore: Any, peer_id: Any, address: Any) -> None:
    """Replace stored dial addresses with one selected address.

    Inputs are the host peerstore, the libp2p peer id, and the exact multiaddr
    to dial. The side effect is local peerstore state only. It does not admit
    the peer, touch a signed payload, or change binding retry policy.

    ``clear_addrs`` drops a signed record by calling ``addrs()``. After the
    record TTL, that lookup raises ``PeerStoreError`` and the selected address
    is never stored. Refreshing the existing entry with an empty address list
    uses the public peerstore API so the clear finishes, the signed record is
    removed, and no previous address remains.
    """
    peerstore.add_addrs(peer_id, [], 120)
    peerstore.clear_addrs(peer_id)
    peerstore.add_addrs(peer_id, [address], 120)


def _peerstore_endpoint(*, host: Any, transport_peer_id: Any) -> str:
    """Select a usable peerstore route, preferring a known RSS circuit.

    Identify can advertise listener wildcards ahead of a circuit address.
    Those are not dial targets and must never replace an established route.
    An empty result permits authenticated inbound binding without inventing
    a reverse route; outbound discovery can supply that route independently.
    This selection does not grant peer admission or inspect application data.
    A missing or expired record is the same unavailable-endpoint condition as
    an empty address list. Callers ignore that ``TransportError`` and must not
    see ``PeerStoreError`` from a connection notification.
    """
    from libp2p.peer.peerstore import PeerStoreError

    try:
        addrs = host.get_peerstore().addrs(transport_peer_id)
    except PeerStoreError as exc:
        raise TransportError("connected peer has no peerstore address") from exc
    if not addrs:
        raise TransportError("connected peer has no peerstore address")
    usable = [str(addr) for addr in addrs if not _is_wildcard_endpoint(endpoint=str(addr))]
    if not usable:
        return ""
    endpoint = next((addr for addr in usable if "/p2p-circuit" in addr), usable[0])
    return _append_peer_id(endpoint=endpoint, peer_id=str(transport_peer_id))


def _append_peer_id(*, endpoint: str, peer_id: str) -> str:
    """Append a libp2p PeerID exactly once to one candidate multiaddr."""
    suffix = f"/p2p/{peer_id}"
    return endpoint if endpoint.endswith(suffix) else endpoint + suffix


def _proven_relayed_circuit(*, stream: Any, transport_peer_id: str) -> bool:
    """Return whether this stream's public connection metadata is a relay to this peer.

    Inputs are the binding stream and the authenticated transport peer id.
    The result is true only when ``get_connection_type`` is ``RELAYED`` and
    ``get_transport_addresses`` includes a circuit multiaddr for that peer.
    There is no side effect and no admission decision.

    ``SwarmConn.get_transport_addresses`` returns peerstore addresses when
    actual transport metadata was never recorded, while ``get_connection_type``
    stays ``UNKNOWN``. A circuit string from that fallback is not proof.
    ``DIRECT``, ``UNKNOWN``, a missing connection, or a relay type without a
    circuit for this peer are not proof either.
    """
    swarm_conn = getattr(stream, "swarm_conn", None)
    if swarm_conn is None:
        return False
    connection_type = getattr(swarm_conn, "get_connection_type", None)
    transport_addresses = getattr(swarm_conn, "get_transport_addresses", None)
    if not callable(connection_type) or not callable(transport_addresses):
        return False
    try:
        from libp2p.connection_types import ConnectionType

        if connection_type() != ConnectionType.RELAYED:
            return False
        observed = transport_addresses()
    except Exception:
        return False
    if not isinstance(observed, (list, tuple)):
        return False
    suffix = f"/p2p/{transport_peer_id}"
    return any(
        "/p2p-circuit" in str(address) and str(address).endswith(suffix)
        for address in observed
    )


def _selected_circuit_for_peer(*, selected: str, transport_peer_id: str) -> str:
    """Return one previously selected full circuit for this peer, or an empty string.

    The input is the dial address stored before the binding stream, not an
    Identify listen address. It is usable only when it is a circuit multiaddr
    for this transport peer. The function does not read the peerstore, invent
    an underlay, or admit the peer.
    """
    suffix = f"/p2p/{transport_peer_id}"
    if "/p2p-circuit/" in selected and selected.endswith(suffix):
        return selected
    return ""


def _route_observations(
    routing_table: RoutingTable,
    *,
    adapter: str,
    endpoint_parts: Callable[[Any], tuple[str | None, int | None]],
) -> tuple[RouteObservation, ...]:
    """Convert shared daemon routes into transport-neutral status records."""
    return _route_observations_from_routes(
        routing_table.routes(adapter=adapter), endpoint_parts=endpoint_parts
    )


def _direct_tcp_endpoint(route: Any) -> tuple[str, int]:
    """Resolve one direct-TCP route without exposing its syntax to shared routing."""
    if route.host is not None and route.port is not None:
        return str(route.host), int(route.port)
    endpoint = route.endpoint
    if not isinstance(endpoint, str):
        raise TransportError("direct TCP route has no endpoint")
    if endpoint.startswith("tcp://"):
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.hostname and parsed.port is not None:
            return parsed.hostname, parsed.port
    else:
        host, separator, raw_port = endpoint.rpartition(":")
        if separator and host:
            try:
                port = int(raw_port)
            except ValueError:
                port = 0
            if 1 <= port <= 65535:
                return host, port
    raise TransportError("direct TCP endpoint must use host:port or tcp://host:port")


def _direct_route_parts(route: Any) -> tuple[str | None, int | None]:
    """Return direct-TCP endpoint parts for status without raising."""
    try:
        return _direct_tcp_endpoint(route)
    except TransportError:
        return None, None


def _libp2p_route_parts(route: Any) -> tuple[str | None, int | None]:
    """Return IP/DNS and TCP components from an adapter-owned multiaddr string."""
    endpoint = route.endpoint
    if not isinstance(endpoint, str):
        return None, None
    components = endpoint.strip("/").split("/")
    host: str | None = None
    port: int | None = None
    for index, component in enumerate(components[:-1]):
        value = components[index + 1]
        if component in {"ip4", "ip6", "dns", "dns4", "dns6"}:
            host = value
        elif component == "tcp":
            try:
                port = int(value)
            except ValueError:
                port = None
    return host, port


def _bound_listener_address(
    *,
    addresses: Any,
    selected_host: str,
) -> tuple[str, int]:
    """Return the concrete selected listener and its actual bound TCP port."""
    for address in addresses:
        value = str(address)
        components = value.strip("/").split("/")
        try:
            host_index = components.index("ip4")
            tcp_index = components.index("tcp")
            host = components[host_index + 1]
            port = int(components[tcp_index + 1])
        except (IndexError, ValueError):
            continue
        if host == selected_host and 1 <= port <= 65535:
            return value, port
    raise TransportUnavailable(
        "libp2p host reported no bound address for the selected listener"
    )


def _route_observations_from_routes(
    routes: Any,
    *,
    endpoint_parts: Callable[[Any], tuple[str | None, int | None]],
) -> tuple[RouteObservation, ...]:
    """Convert an iterable of daemon routes without exposing adapter types."""
    observations: list[RouteObservation] = []
    for route in routes:
        host, port = endpoint_parts(route)
        observations.append(
            RouteObservation(
                peer_id=route.peer_id,
                adapter=route.adapter,
                endpoint=(
                    route.endpoint
                    or (f"{host}:{port}" if host is not None and port is not None else None)
                ),
                transport_identity=route.transport_peer_id,
                source=route.source,
                connected=route.connected,
                reachable=route.reachable,
                last_contact=route.last_contact,
                host=host,
                port=port,
            )
        )
    return tuple(observations)


async def _read_stream_frame(stream: Any) -> bytes:
    header = await _read_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if size > MAX_FRAME_BYTES:
        raise TransportError("transport frame exceeds maximum size")
    return await _read_exact(stream, size)


async def _read_exact(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = await stream.read(remaining)
        if not chunk:
            raise TransportError("transport stream closed before frame completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _direct_tcp_factory(
    config: TransportConfig, routing_table: RoutingTable
) -> TransportAdapter:
    return DirectTCPTransport(
        host=config.host,
        requested_port=config.requested_port,
        routing_table=routing_table,
    )


def _py_libp2p_factory(
    config: TransportConfig, routing_table: RoutingTable
) -> TransportAdapter:
    return PyLibP2PTransport(
        host=config.host,
        requested_port=config.requested_port,
        discovery=config.discovery,
        bootstrap=list(config.bootstrap),
        relay_peers=list(config.relay_peers),
        relay_auth=load_rss_relay_credentials_from_environment(),
        routing_table=routing_table,
    )


BUILTIN_TRANSPORTS = TransportRegistry()
BUILTIN_TRANSPORTS.register(name="direct_tcp", factory=_direct_tcp_factory)
BUILTIN_TRANSPORTS.register(name="libp2p", factory=_py_libp2p_factory)


def transport_mode() -> str:
    """Return the explicitly selected registered adapter name."""
    value = os.environ.get("SECKIT_DAEMON_TRANSPORT", "libp2p").strip().lower()
    if value == "direct_tcp" and os.environ.get("SECKIT_UNSAFE_TEST_DIRECT_TCP") != "1":
        raise TransportError("direct_tcp requires SECKIT_UNSAFE_TEST_DIRECT_TCP=1; test transport only")
    if value not in BUILTIN_TRANSPORTS.names():
        available = ", ".join(BUILTIN_TRANSPORTS.names())
        raise TransportError(
            f"SECKIT_DAEMON_TRANSPORT must name a registered adapter: {available}"
        )
    return value


def create_transport(
    *, host: str, requested_port: int, routing_table: RoutingTable | None = None
) -> Transport:
    """Create the selected reviewed adapter without importing runtime code."""
    selected = transport_mode()
    bootstrap = [
        value.strip()
        for value in os.environ.get("SECKIT_DAEMON_BOOTSTRAP", "").split(",")
        if value.strip()
    ]
    relay_peers = [
        value.strip()
        for value in os.environ.get("SECKIT_DAEMON_RELAY_PEERS", "").split(",")
        if value.strip()
    ]
    if not relay_peers:
        relay_peers = list(load_rss_relay_peers_from_profile())
    config = TransportConfig(
        name=selected,
        host=host,
        requested_port=requested_port,
        discovery=os.environ.get("SECKIT_DAEMON_DISCOVERY", "1") == "1",
        bootstrap=tuple(bootstrap),
        relay_peers=tuple(relay_peers),
    )
    return BUILTIN_TRANSPORTS.create(
        config=config,
        routing_table=routing_table or RoutingTable.from_environment(adapter=selected),
    )


# Compatibility alias retained while internal callers migrate to the explicit
# implementation name.
LibP2PTransport = PyLibP2PTransport


__all__ = [
    "DirectTCPTransport",
    "FrameHandler",
    "IDENTITY_BINDING_PROTOCOL",
    "LIBP2P_PROTOCOL",
    "LibP2PTransport",
    "PyLibP2PTransport",
    "Transport",
    "TransportAdapter",
    "TransportCapabilities",
    "TransportConfig",
    "TransportDestination",
    "TransportPeer",
    "TransportError",
    "TransportReceipt",
    "TransportServices",
    "TransportSnapshot",
    "TransportUnavailable",
    "create_transport",
    "transport_mode",
]
