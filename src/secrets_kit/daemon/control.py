"""
secrets_kit.daemon.control

Define daemon-owned transport control messages and local routing frames.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from secrets_kit.identifiers import validate_identifier

CONTROL_VERSION = 1
CONTROL_KIND = "control"
ROUTE_KIND = "route"
RUNTIME_ACCESS_KIND = "runtime_access"


class ControlMessageError(ValueError):
    """Raised when a daemon control or local route frame is malformed."""


@dataclass(frozen=True)
class RouteFrame:
    """Local transport request carrying an opaque application payload."""

    peer_id: str
    payload: bytes


def control_message_bytes(*, operation: str) -> bytes:
    """Serialize one daemon-directed control message."""
    return json.dumps(
        {"version": CONTROL_VERSION, "kind": CONTROL_KIND, "operation": operation},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def runtime_access_message_bytes(*, operation: str, arguments: dict[str, Any]) -> bytes:
    """Serialize an opaque local request for the runtime authority worker."""
    return json.dumps(
        {
            "version": CONTROL_VERSION,
            "kind": RUNTIME_ACCESS_KIND,
            "operation": operation,
            "arguments": arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def route_frame_bytes(*, peer_id: str, payload: bytes) -> bytes:
    """Serialize one local route request without interpreting its payload."""
    value: dict[str, Any] = {
        "version": CONTROL_VERSION,
        "kind": ROUTE_KIND,
        "peer_id": peer_id,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_daemon_message(*, data: bytes) -> dict[str, Any] | None:
    """Parse a daemon-owned JSON message, returning ``None`` for opaque bytes."""
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("kind") not in {
        CONTROL_KIND,
        ROUTE_KIND,
        RUNTIME_ACCESS_KIND,
    }:
        return None
    if value.get("version") != CONTROL_VERSION:
        raise ControlMessageError("unsupported daemon control version")
    return value


def parse_route_frame(*, value: dict[str, Any]) -> RouteFrame:
    """Validate and decode a local opaque-payload route request."""
    if value.get("kind") != ROUTE_KIND:
        raise ControlMessageError("daemon message is not a route request")
    peer_id = value.get("peer_id")
    payload_b64 = value.get("payload_b64")
    if not isinstance(peer_id, str) or not peer_id.startswith("node:"):
        raise ControlMessageError("route peer_id is required")
    try:
        peer_id = validate_identifier(value=peer_id, expected_type="node", field="peer_id")
    except ValueError as exc:
        raise ControlMessageError(f"route peer_id is invalid: {exc}") from exc
    if not isinstance(payload_b64, str):
        raise ControlMessageError("route payload_b64 is required")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except ValueError as exc:
        raise ControlMessageError("route payload_b64 is invalid") from exc
    return RouteFrame(peer_id=peer_id, payload=payload)


__all__ = [
    "CONTROL_KIND",
    "CONTROL_VERSION",
    "ControlMessageError",
    "ROUTE_KIND",
    "RUNTIME_ACCESS_KIND",
    "RouteFrame",
    "control_message_bytes",
    "parse_daemon_message",
    "parse_route_frame",
    "route_frame_bytes",
    "runtime_access_message_bytes",
]
