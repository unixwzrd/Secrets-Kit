"""Length-prefixed JSON framing for local Unix socket messages."""

from __future__ import annotations

import json
from typing import Any, Mapping

MAX_FRAME_BYTES = 64 * 1024 * 1024


class FramingError(ValueError):
    """Invalid or oversized frame."""


def frame_json(obj: Mapping[str, Any] | Any) -> bytes:
    """Serialize to UTF-8 JSON and length-prefix (uint32 big-endian)."""
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FramingError("JSON body exceeds maximum frame size")
    return len(body).to_bytes(4, "big") + body


def read_frame(conn: Any) -> bytes:
    """Read one length-prefixed frame from a connected socket-like object."""
    hdr = _recv_exact(conn, 4)
    n = int.from_bytes(hdr, "big")
    if n > MAX_FRAME_BYTES:
        raise FramingError("frame too large")
    return _recv_exact(conn, n)


def parse_json_object(body: bytes) -> dict[str, Any]:
    """Decode JSON object from frame bytes."""
    try:
        text = body.decode("utf-8")
        val = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FramingError(f"invalid JSON: {exc}") from exc
    if not isinstance(val, dict):
        raise FramingError("top-level JSON must be an object")
    return val


def _recv_exact(conn: Any, n: int) -> bytes:
    parts: list[bytes] = []
    remaining = n
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise FramingError("connection closed before frame complete")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)
