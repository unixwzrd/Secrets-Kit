"""Transport-neutral routing metadata."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class RouteMetadata:
    """Routing metadata visible to direct peers or relay forwarders."""

    destination_peer: str
    next_hop: Optional[str] = None
    route_hint: Optional[str] = None
    relay_session_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RouteMetadata":
        dest = str(raw.get("destination_peer", "")).strip()
        if not dest:
            raise ValueError("route.destination_peer is required")
        return cls(
            destination_peer=dest,
            next_hop=_optional_str(raw.get("next_hop")),
            route_hint=_optional_str(raw.get("route_hint")),
            relay_session_id=_optional_str(raw.get("relay_session_id")),
        )


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    out = str(value).strip()
    return out or None

