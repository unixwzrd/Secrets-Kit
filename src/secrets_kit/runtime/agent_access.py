"""
secrets_kit.runtime.agent_access

Resolve narrow agent requests inside protected authority handling.

The daemon forwards request and response bytes without importing this module or
opening a datastore. Secret material is returned only by the explicit
``resolve_secret`` operation and is never included in diagnostics.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from secrets_kit.backends.common import BACKEND_CHOICES, BackendError, normalize_backend
from secrets_kit.backends.dispatch import (
    list_secret_metadata,
    read_metadata_for_backend,
    read_secret_value,
)
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.secrets_api import (
    create_sqlite_secret,
    delete_sqlite_secret,
    get_sqlite_metadata,
    get_sqlite_secret_revisions,
    update_sqlite_secret,
)
from secrets_kit.models import EntryMetadata, ValidationError, now_utc_iso, validate_key_name

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


def _required_value(arguments: dict[str, Any]) -> str:
    """Read one bounded non-empty MCP write value without reflecting it."""
    value = arguments.get("value")
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 262_144:
        raise ValueError("invalid_value")
    return value


def _required_revision(arguments: dict[str, Any]) -> str:
    """Read one bounded opaque revision supplied from authorized metadata."""
    value = arguments.get("revision")
    if not isinstance(value, str) or not value or len(value) > 80:
        raise ValueError("invalid_revision")
    return value


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


def _write_scope(arguments: dict[str, Any]) -> tuple[str, str, str]:
    """Validate the fixed SQLite write locator without exposing supplied values."""
    service = _required_text(arguments, "service")
    account = _required_text(arguments, "account")
    name = validate_key_name(name=_required_text(arguments, "name"))
    return service, account, name


def handle_runtime_access_request(*, data: bytes) -> bytes:
    """
    Handle one local request and return a redaction-safe envelope.

    ``list_metadata`` and write operations return no authority value.
    ``resolve_secret`` is the sole materialization operation and requires an
    explicit full locator. The MCP process enforces its owner-only policy
    before forwarding write operations; this runtime handler does not receive
    that policy, so any process with same-user UDS access has the same authority
    boundary as the local CLI. Writes execute canonical SQLite transactions.
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
            raw_revision_names = arguments.get("revision_names", [])
            if not isinstance(raw_revision_names, list) or len(raw_revision_names) > 128:
                raise ValueError("invalid_arguments")
            try:
                revision_names = frozenset(
                    validate_key_name(name=item)
                    for item in raw_revision_names
                    if isinstance(item, str)
                )
            except ValidationError:
                raise ValueError("invalid_arguments") from None
            if len(revision_names) != len(raw_revision_names):
                raise ValueError("invalid_arguments")
            if revision_names and backend != "sqlite":
                raise ValueError("invalid_backend")
            service = _optional_text(arguments, "service")
            account = _optional_text(arguments, "account")
            entries = list_secret_metadata(
                backend=backend,
                service=service,
                account=account,
            )
            revisions: dict[str, str] = {}
            if revision_names and service is not None and account is not None:
                revisions = get_sqlite_secret_revisions(
                    service=service, account=account, names=revision_names
                )
            projected = []
            for item in entries:
                public = _public_metadata(item)
                if item.name in revisions and item.service == service and item.account == account:
                    public["revision"] = revisions[item.name]
                projected.append(public)
            projected.sort(key=lambda item: (item["service"], item["account"], item["name"]))
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

        if operation in {"create_secret", "update_secret", "delete_secret"}:
            if backend != "sqlite":
                raise ValueError("invalid_backend")
            service, account, name = _write_scope(arguments)
            if operation == "create_secret":
                if set(arguments) != {"backend", "service", "account", "name", "value"}:
                    raise ValueError("invalid_arguments")
                revision = create_sqlite_secret(
                    service=service,
                    account=account,
                    name=name,
                    value=_required_value(arguments),
                    metadata=EntryMetadata(
                        name=name,
                        service=service,
                        account=account,
                        source="mcp",
                    ),
                )
                return _response(status="ok", data={"created": True, "revision": revision})

            expected_revision = _required_revision(arguments)
            if operation == "update_secret":
                if set(arguments) != {
                    "backend", "service", "account", "name", "value", "revision"
                }:
                    raise ValueError("invalid_arguments")
                metadata = get_sqlite_metadata(
                    service=service, account=account, name=name
                )
                metadata = dataclasses.replace(metadata, updated_at=now_utc_iso())
                revision = update_sqlite_secret(
                    service=service,
                    account=account,
                    name=name,
                    value=_required_value(arguments),
                    metadata=metadata,
                    expected_revision=expected_revision,
                )
                return _response(status="ok", data={"updated": True, "revision": revision})

            if set(arguments) != {
                "backend", "service", "account", "name", "revision"
            }:
                raise ValueError("invalid_arguments")
            metadata = get_sqlite_metadata(service=service, account=account, name=name)
            delete_sqlite_secret(
                service=service,
                account=account,
                name=name,
                metadata=metadata,
                expected_revision=expected_revision,
            )
            return _response(status="ok", data={"deleted": True})
        return _response(status="error", error="unsupported_operation")
    except SQLiteBackendError as exc:
        safe_error = {
            "secret already exists": "secret_already_exists",
            "secret revision conflict": "secret_revision_conflict",
        }.get(str(exc), "access_denied_or_unavailable")
        return _response(status="error", error=safe_error)
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
            "invalid_value",
            "invalid_revision",
        }
        return _response(status="error", error=code if code in allowed else "invalid_request")
    except Exception:
        return _response(status="error", error="access_denied_or_unavailable")


__all__ = ["handle_runtime_access_request"]
