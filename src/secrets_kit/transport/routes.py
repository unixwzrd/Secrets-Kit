"""Compatibility exports for daemon-owned transport route parsing."""

from __future__ import annotations

from dataclasses import dataclass

from secrets_kit.daemon.routing import (
    TransportRouteError,
    configured_peer_routes,
)


@dataclass(frozen=True)
class PeerDestination:
    """Legacy test/config value; daemon routing uses :class:`PeerRoute`."""

    host: str | None
    port: int | None
    node_id: str
    endpoint: str | None = None
    adapter: str = "direct_tcp"


def configured_peer_destinations() -> list[PeerDestination]:
    """Return legacy route objects for compatibility callers."""
    return [
        PeerDestination(
            host=route.host,
            port=route.port,
            node_id=route.peer_id,
            endpoint=route.endpoint,
            adapter=route.adapter,
        )
        for route in configured_peer_routes()
    ]


__all__ = [
    "PeerDestination",
    "TransportRouteError",
    "configured_peer_destinations",
]
