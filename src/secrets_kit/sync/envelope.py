"""Minimal transport **message** wrapper helpers (no network I/O).

This is **not** sync bundle v1 JSON, **not** a session record, and **not** a
protocol runtime. Intermediaries must ignore ``payload_type`` for routing; it is
informational for endpoints only.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

# Normative JSON keys for the Phase 4 conceptual wrapper (wire framing is separate).
KEY_MESSAGE_ID = "message_id"
KEY_SOURCE_PEER = "source_peer"
KEY_DESTINATION_PEER = "destination_peer"
KEY_TIMESTAMP = "timestamp"
KEY_PAYLOAD_TYPE = "payload_type"
KEY_PAYLOAD = "payload"
KEY_ROUTE_TOKEN = "route_token"
KEY_TTL = "ttl"


def build_transport_message(
    *,
    source_peer: str,
    destination_peer: str,
    timestamp: str,
    payload_type: str,
    payload: str,
    message_id: Optional[str] = None,
    forward_token: Optional[str] = None,
    ttl: Optional[int] = None,
) -> dict[str, Any]:
    """Build a minimal routed-transport message dict (opaque ``payload`` slot)."""
    msg: dict[str, Any] = {
        KEY_SOURCE_PEER: source_peer,
        KEY_DESTINATION_PEER: destination_peer,
        KEY_TIMESTAMP: timestamp,
        KEY_PAYLOAD_TYPE: payload_type,
        KEY_PAYLOAD: payload,
    }
    if message_id is not None:
        msg[KEY_MESSAGE_ID] = message_id
    if forward_token is not None:
        msg[KEY_ROUTE_TOKEN] = forward_token
    if ttl is not None:
        msg[KEY_TTL] = int(ttl)
    return msg


def forwarding_subset(message: Mapping[str, Any]) -> dict[str, Any]:
    """Return the minimal subset a dumb forwarder may observe for delivery.

    Intentionally excludes ``payload_type`` and payload body. Unknown keys are
    not copied; this is **not** a generic JSON projection.
    """
    dest = message.get(KEY_DESTINATION_PEER)
    if dest is None or not str(dest).strip():
        raise ValueError("destination_peer is required for forwarding subset")
    out: dict[str, Any] = {KEY_DESTINATION_PEER: str(dest)}
    if KEY_MESSAGE_ID in message and message[KEY_MESSAGE_ID] is not None:
        out[KEY_MESSAGE_ID] = str(message[KEY_MESSAGE_ID])
    if KEY_ROUTE_TOKEN in message and message[KEY_ROUTE_TOKEN] is not None:
        out[KEY_ROUTE_TOKEN] = str(message[KEY_ROUTE_TOKEN])
    return out


def relay_visible_routing_subset(message: Mapping[str, Any]) -> dict[str, Any]:
    """Compatibility alias for :func:`forwarding_subset`."""
    return forwarding_subset(message)
