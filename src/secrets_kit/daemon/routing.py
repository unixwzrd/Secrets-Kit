"""
secrets_kit.daemon.routing

Daemon-owned transport bootstrap and routing state.

Routes are operational data.  They are correlated with peer identities, but
they never grant admission or application-level authorization.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from secrets_kit.identifiers import validate_identifier

LOGGER = logging.getLogger(__name__)


class TransportRouteError(ValueError):
    """Raised when daemon transport bootstrap configuration is malformed."""


@dataclass(frozen=True)
class PeerRoute:
    """One daemon-owned operational route for an admitted peer identity."""

    peer_id: str
    host: str | None = None
    port: int | None = None
    endpoint: str | None = None
    adapter: str = "direct_tcp"
    source: str = "bootstrap"
    transport_peer_id: str | None = None
    connected: bool = False
    reachable: bool = True
    last_contact: str | None = None


class RoutingTable:
    """In-memory route cache keyed only by peer identity."""

    def __init__(self, routes: list[PeerRoute] | tuple[PeerRoute, ...] = ()) -> None:
        self._lock = threading.RLock()
        self._bootstrap_routes = {
            route.peer_id: _with_source(route=route, source="bootstrap") for route in routes
        }
        self._runtime_routes: dict[str, PeerRoute] = {}
        self._discovered_routes: dict[str, PeerRoute] = {}

    @classmethod
    def from_environment(cls, *, adapter: str | None = None) -> "RoutingTable":
        return cls(routes=configured_peer_routes(adapter=adapter))

    def resolve(self, *, peer_id: str, adapter: str) -> PeerRoute:
        with self._lock:
            route = self._selected_route(peer_id=peer_id, adapter=adapter)
        if route is None:
            raise TransportRouteError(f"no transport route for peer_id={peer_id}")
        return route

    def resolve_retained(self, *, peer_id: str, adapter: str) -> PeerRoute:
        """Return only a previously authenticated locator for an explicit retry.

        Availability remains unchanged. Runtime and bootstrap locators are never
        considered here because neither is authenticated route evidence.
        """
        with self._lock:
            route = self._discovered_routes.get(peer_id)
            if route is not None and route.adapter == adapter:
                return route
        raise TransportRouteError(
            f"no authenticated transport route for peer_id={peer_id}"
        )

    def routes(self, *, adapter: str | None = None) -> tuple[PeerRoute, ...]:
        """Return the highest-priority route for every known peer."""
        with self._lock:
            peer_ids = (
                set(self._bootstrap_routes)
                | set(self._runtime_routes)
                | set(self._discovered_routes)
            )
            return tuple(
                route
                for peer_id in sorted(peer_ids)
                if (route := self._selected_route(peer_id=peer_id, adapter=adapter)) is not None
            )

    def replace_from_runtime(
        self, *, records: list[dict[str, object]], adapter: str
    ) -> None:
        """Replace the operational route cache from runtime endpoint records."""
        routes: list[PeerRoute] = []
        for record in records:
            peer_id = record.get("peer_id")
            endpoint = record.get("endpoint")
            if not isinstance(peer_id, str) or not isinstance(endpoint, str):
                continue
            if _is_wildcard_endpoint(endpoint=endpoint):
                LOGGER.warning(
                    "runtime endpoint is a non-routable bind address: peer_id=%s",
                    peer_id,
                )
                continue
            try:
                routes.append(
                    PeerRoute(
                        peer_id=validate_identifier(
                            value=peer_id, expected_type="node", field="peer_id"
                        ),
                        endpoint=endpoint,
                        adapter=adapter,
                    )
                )
            except TransportRouteError:
                LOGGER.warning("runtime endpoint is not routable: peer_id=%s", peer_id)
        dynamic = {
            route.peer_id: _with_source(route=route, source="runtime_endpoint")
            for route in routes
        }
        with self._lock:
            self._runtime_routes = dynamic

    def install_discovered(
        self,
        *,
        peer_id: str,
        endpoint: str,
        transport_peer_id: str,
        adapter: str,
        source: str = "discovery",
    ) -> PeerRoute:
        """Install one validated ephemeral adapter route."""
        discovered = PeerRoute(
            peer_id=validate_identifier(
                value=peer_id, expected_type="node", field="peer_id"
            ),
            endpoint=endpoint,
            adapter=adapter,
            source=source,
            transport_peer_id=transport_peer_id,
            connected=True,
            reachable=True,
            last_contact=_now(),
        )
        with self._lock:
            self._discovered_routes[peer_id] = discovered
        return discovered

    def mark_contact(self, *, peer_id: str) -> None:
        """Mark a discovered route connected after successful transport I/O."""
        with self._lock:
            route = self._discovered_routes.get(peer_id)
            if route is not None:
                self._discovered_routes[peer_id] = _route_state(
                    route=route, connected=True, reachable=True
                )

    def discovered(self, *, peer_id: str, adapter: str) -> PeerRoute | None:
        """Return retained authenticated route evidence regardless of availability."""
        with self._lock:
            route = self._discovered_routes.get(peer_id)
            if route is None or route.adapter != adapter:
                return None
            return route

    def mark_unavailable(self, *, peer_id: str) -> None:
        """Keep route evidence but make an unavailable discovery route ineligible."""
        with self._lock:
            route = self._discovered_routes.get(peer_id)
            if route is not None:
                self._discovered_routes[peer_id] = _route_state(
                    route=route, connected=False, reachable=False
                )

    def mark_transport_unavailable(self, *, transport_peer_id: str) -> None:
        """Mark routes for one disconnected authenticated transport identity unavailable."""
        with self._lock:
            for peer_id, route in tuple(self._discovered_routes.items()):
                if route.transport_peer_id == transport_peer_id:
                    self._discovered_routes[peer_id] = _route_state(
                        route=route, connected=False, reachable=False
                    )

    def discovered_count(self) -> int:
        """Return the number of connected, validated discovery routes."""
        with self._lock:
            return sum(
                1
                for route in self._discovered_routes.values()
                if route.connected and route.reachable
            )

    def _selected_route(self, *, peer_id: str, adapter: str | None) -> PeerRoute | None:
        discovered = self._discovered_routes.get(peer_id)
        if discovered is not None and (
            adapter is None or discovered.adapter == adapter
        ):
            if discovered.connected and discovered.reachable:
                return discovered
            # A disconnected authenticated binding is stronger evidence than a
            # stale runtime/bootstrap locator. Keep identity while preventing
            # network calls until a genuine route recovery event.
            return None
        for route in (
            self._runtime_routes.get(peer_id),
            self._bootstrap_routes.get(peer_id),
        ):
            if route is not None and (adapter is None or route.adapter == adapter):
                return route
        return None


def _is_wildcard_endpoint(*, endpoint: str) -> bool:
    """Reject listener bind addresses that cannot be used as peer routes."""
    normalized = endpoint.strip().lower()
    return (
        normalized.startswith("tcp://0.0.0.0:")
        or normalized.startswith("tcp://[::]:")
        or normalized.startswith("/ip4/0.0.0.0/")
        or normalized.startswith("/ip6/::/")
    )


def configured_peer_routes(*, adapter: str | None = None) -> list[PeerRoute]:
    """Read daemon bootstrap routes without authorizing any peer."""
    raw = os.environ.get("SECKIT_DAEMON_PEERS")
    if raw is None:
        try:
            from secrets_kit.cli.config_defaults import load_config_defaults

            configured = load_config_defaults().get("daemon_peers")
        except Exception:
            configured = None
        if isinstance(configured, list):
            values = [str(item) for item in configured]
        elif configured is not None:
            values = str(configured).split(",")
        else:
            values = []
    else:
        values = raw.split(",")

    routes: list[PeerRoute] = []
    for value in values:
        text = value.strip()
        if not text:
            continue
        peer_id, separator, endpoint = text.partition("@")
        if not separator or not peer_id or not endpoint:
            raise TransportRouteError(
                "daemon peer entries must use node:<uuid>@<opaque-endpoint>"
            )
        peer_id = validate_identifier(value=peer_id, expected_type="node", field="peer_id")
        routes.append(
            PeerRoute(
                peer_id=peer_id,
                endpoint=endpoint,
                adapter=(adapter or os.environ.get("SECKIT_DAEMON_TRANSPORT", "libp2p")),
            )
        )
    return routes


def _with_source(*, route: PeerRoute, source: str) -> PeerRoute:
    """Copy one route while assigning its operational source."""
    return PeerRoute(
        peer_id=route.peer_id,
        host=route.host,
        port=route.port,
        endpoint=route.endpoint,
        adapter=route.adapter,
        source=source,
        transport_peer_id=route.transport_peer_id,
        connected=route.connected,
        reachable=route.reachable,
        last_contact=route.last_contact,
    )


def _route_state(*, route: PeerRoute, connected: bool, reachable: bool) -> PeerRoute:
    """Return an immutable route with refreshed connection observations."""
    return PeerRoute(
        peer_id=route.peer_id,
        host=route.host,
        port=route.port,
        endpoint=route.endpoint,
        adapter=route.adapter,
        source=route.source,
        transport_peer_id=route.transport_peer_id,
        connected=connected,
        reachable=reachable,
        last_contact=_now(),
    )


def _now() -> str:
    """Return an ISO timestamp for ephemeral route observations."""
    return datetime.now(timezone.utc).isoformat()


__all__ = ["PeerRoute", "RoutingTable", "TransportRouteError", "configured_peer_routes"]
