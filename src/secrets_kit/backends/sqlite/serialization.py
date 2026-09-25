"""
secrets_kit.backends.sqlite.serialization

Deterministic JSON serialization for canonical transaction payloads.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError


def canonical_json_bytes(*, payload: Mapping[str, Any]) -> bytes:
    """
    Serialize payload data as canonical JSON bytes.

    Args:
        payload:
            JSON mapping to serialize.

    Returns:
        UTF-8 encoded canonical JSON bytes.

    Raises:
        SQLiteValidationError:
            Payload cannot be serialized as deterministic JSON.

    Side Effects:
        None.
    """
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SQLiteValidationError(f"payload must be canonical JSON serializable: {exc}") from exc


def load_canonical_json(*, payload_bytes: bytes) -> dict[str, Any]:
    """
    Decode stored canonical JSON payload bytes.

    Args:
        payload_bytes:
            UTF-8 encoded canonical JSON bytes.

    Returns:
        Decoded payload mapping.

    Raises:
        SQLiteValidationError:
            Stored payload is not valid JSON mapping data.

    Side Effects:
        None.
    """
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SQLiteValidationError(f"stored payload is not valid canonical JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SQLiteValidationError("stored payload must be a JSON object")
    return payload


__all__ = ["canonical_json_bytes", "load_canonical_json"]
