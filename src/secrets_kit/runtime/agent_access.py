"""
secrets_kit.runtime.agent_access

Resolve narrow read-only agent requests inside protected authority handling.

The daemon forwards request and response bytes without importing this module or
opening a datastore. Secret material is returned only by the explicit
``resolve_secret`` operation and is never included in diagnostics.
"""

from __future__ import annotations

import json
from typing import Any

from secrets_kit.backends.common import BACKEND_CHOICES, BackendError, normalize_backend
from secrets_kit.backends.dispatch import (
    list_secret_metadata,
    read_metadata_for_backend,
    read_secret_value,
)
from secrets_kit.models import EntryMetadata, validate_key_name

RUNTIME_ACCESS_VERSION = 1
RUNTIME_ACCESS_KIND = "runtime_access"


def _response(
    *, status: str, data: dict[str, Any] | None = None, error: str | None = None
) -> bytes:
    """Encode a bounded response without exception text or implicit secret output."""
    payload: dict[str, Any] = {"version": RUNTIME_ACCESS_VERSION, "status": status}
    if data is not None:
        payload["data"] = data
    if error is not None:
        payload["error"] = error
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _required_text(arguments: dict[str, Any], field: str) -> str:
    """Return one required non-empty request string without echoing its value."""
    value = arguments.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_{field}")
    return value.strip()


def _optional_text(arguments: dict[str, Any], field: str) -> str | None:
    """Return one optional non-empty request string."""
    value = arguments.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid_{field}")
    return value.strip()


def _public_metadata(metadata: EntryMetadata) -> dict[str, Any]:
    """Project metadata fields intended for an authorized agent listing."""
    return {
        "entry_id": metadata.entry_id,
        "name": metadata.name,
        "service": metadata.service,
        "account": metadata.account,
        "type": metadata.entry_type,
        "kind": metadata.entry_kind,
        "tags": list(metadata.tags),
        "updated_at": metadata.updated_at,
    }


def handle_runtime_access_request(*, data: bytes) -> bytes:
    """
    Handle one local read-only request and return a redaction-safe envelope.

    ``list_metadata`` returns no authority value. ``resolve_secret`` is the
    sole materialization operation and requires an explicit full locator.
    Failures use stable codes and never include backend exception text.
    """
    try:
        request = json.loads(data.decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("invalid_request")
        if request.get("version") != RUNTIME_ACCESS_VERSION:
            raise ValueError("unsupported_version")
        if request.get("kind") != RUNTIME_ACCESS_KIND:
            raise ValueError("invalid_request")
        operation = request.get("operation")
        arguments = request.get("arguments")
        if not isinstance(arguments, dict):
            raise ValueError("invalid_arguments")
        try:
            backend = normalize_backend(_required_text(arguments, "backend"))
        except BackendError:
            raise ValueError("invalid_backend") from None
        if backend not in BACKEND_CHOICES:
            raise ValueError("invalid_backend")

        if operation == "list_metadata":
            entries = list_secret_metadata(
                backend=backend,
                service=_optional_text(arguments, "service"),
                account=_optional_text(arguments, "account"),
            )
            projected = sorted(
                (_public_metadata(item) for item in entries),
                key=lambda item: (item["service"], item["account"], item["name"]),
            )
            return _response(status="ok", data={"entries": projected})

        if operation == "resolve_secret":
            service = _required_text(arguments, "service")
            account = _required_text(arguments, "account")
            name = validate_key_name(name=_required_text(arguments, "name"))
            if read_metadata_for_backend(
                backend=backend,
                service=service,
                account=account,
                name=name,
            ) is None:
                return _response(status="error", error="not_found")
            value = read_secret_value(
                backend=backend,
                service=service,
                account=account,
                name=name,
            )
            return _response(status="ok", data={"value": value})
        return _response(status="error", error="unsupported_operation")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _response(status="error", error="invalid_request")
    except ValueError as exc:
        code = str(exc)
        allowed = {
            "invalid_request",
            "unsupported_version",
            "invalid_arguments",
            "invalid_backend",
            "invalid_service",
            "invalid_account",
            "invalid_name",
        }
        return _response(status="error", error=code if code in allowed else "invalid_request")
    except Exception:
        return _response(status="error", error="access_denied_or_unavailable")


__all__ = ["handle_runtime_access_request"]
