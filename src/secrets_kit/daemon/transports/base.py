"""Transport-neutral contracts owned by the Secrets Kit daemon."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class TransportError(RuntimeError):
    """Raised when a daemon transport cannot start or move opaque bytes."""


class TransportUnavailable(TransportError):
    """Raised when the selected transport adapter is unavailable."""


@dataclass(frozen=True)
class TransportConfig:
    """Transport-neutral daemon configuration supplied to one adapter."""

    name: str
    host: str
    requested_port: int
    discovery: bool = False
    bootstrap: tuple[str, ...] = ()
    relay_peers: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransportCapabilities:
    """Capabilities implemented by one adapter without exposing its library types."""

    discovery: bool = False
    dynamic_endpoints: bool = True
    relay_client: bool = False
    authenticated_sessions: bool = False
    encrypted_sessions: bool = False

    def as_dict(self) -> dict[str, bool]:
        """Return a JSON-safe capability mapping."""
        return {
            "discovery": self.discovery,
            "dynamic_endpoints": self.dynamic_endpoints,
            "relay_client": self.relay_client,
            "authenticated_sessions": self.authenticated_sessions,
            "encrypted_sessions": self.encrypted_sessions,
        }


@dataclass(frozen=True)
class TransportReceipt:
    """Receipt for transport movement, never a protocol acknowledgement."""

    delivered: bool
    transport: str
    endpoint: str
    error: str | None = None


@dataclass(frozen=True)
class RouteObservation:
    """Transport-neutral operational state for one adapter route."""

    peer_id: str
    adapter: str
    endpoint: str | None
    transport_identity: str | None
    source: str
    connected: bool
    reachable: bool
    last_contact: str | None = None
    host: str | None = None
    port: int | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-safe route mapping."""
        return {
            "peer_id": self.peer_id,
            "adapter": self.adapter,
            "endpoint": self.endpoint,
            "transport_peer_id": self.transport_identity,
            "source": self.source,
            "connected": self.connected,
            "reachable": self.reachable,
            "last_contact": self.last_contact,
            "host": self.host,
            "port": self.port,
        }


@dataclass(frozen=True)
class TransportSnapshot:
    """Standard operational status returned by every transport adapter."""

    transport: str
    running: bool
    capabilities: TransportCapabilities
    endpoint: str | None = None
    transport_identity: str | None = None
    tcp_host: str | None = None
    tcp_port: int | None = None
    discovery_state: str = "unsupported"
    discovery_candidate_count: int = 0
    validated_route_count: int = 0
    rejected_binding_count: int = 0
    bound_addresses: tuple[str, ...] = ()
    advertised_addresses: tuple[str, ...] = ()
    routes: tuple[RouteObservation, ...] = ()
    diagnostics: tuple[Mapping[str, Any], ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Return the stable daemon-status representation."""
        value = {
            "transport": self.transport,
            "running": self.running,
            "capabilities": self.capabilities.as_dict(),
            "endpoint": self.endpoint,
            "peer_id": self.transport_identity,
            "transport_identity": self.transport_identity,
            "tcp_host": self.tcp_host,
            "tcp_port": self.tcp_port,
            "discovery": self.capabilities.discovery,
            "discovery_state": self.discovery_state,
            "discovery_candidate_count": self.discovery_candidate_count,
            "validated_route_count": self.validated_route_count,
            "rejected_binding_count": self.rejected_binding_count,
            "bound_addresses": list(self.bound_addresses),
            "advertised_addresses": list(self.advertised_addresses),
            "routes": [route.as_dict() for route in self.routes],
            "routing_events": [dict(item) for item in self.diagnostics],
        }
        value.update(self.details)
        return value


FrameHandler = Callable[[bytes, str], tuple[bytes, bool]]
BindingSigner = Callable[[str, str], dict[str, Any]]
BindingVerifier = Callable[[object, str, str], str]
ObservationSink = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True)
class TransportServices:
    """Daemon services available to adapters without transferring authority."""

    frame_handler: FrameHandler
    routing_table: Any
    sign_transport_binding: BindingSigner
    verify_transport_binding: BindingVerifier
    observe: ObservationSink = lambda observation: None


class TransportAdapter(Protocol):
    """Stable adapter contract for moving opaque application bytes."""

    name: str

    def admission_changed(self) -> None:
        """Retry rejected known bindings after a local admission mutation."""

    def start(self, *, services: TransportServices) -> None:
        """Start the adapter with daemon-owned neutral services."""

    def stop(self) -> None:
        """Stop listeners and workers."""

    def send(self, *, peer_id: str, payload: bytes) -> TransportReceipt:
        """Move opaque bytes toward one Secrets Kit peer identity."""

    def snapshot(self) -> TransportSnapshot:
        """Return transport-neutral operational state."""


__all__ = [
    "BindingSigner",
    "BindingVerifier",
    "FrameHandler",
    "ObservationSink",
    "RouteObservation",
    "TransportAdapter",
    "TransportCapabilities",
    "TransportConfig",
    "TransportError",
    "TransportReceipt",
    "TransportServices",
    "TransportSnapshot",
    "TransportUnavailable",
]
