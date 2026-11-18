"""
secrets_kit.mcp_server

Expose policy-scoped Secrets Kit operations over MCP stdio.

This process never imports datastore backends. It uses the same-user daemon
client, emits no logs, and returns authority values only from the explicitly
invoked ``seckit_get_secret`` tool.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secrets_kit import __version__
from secrets_kit.daemon.client import (
    DaemonError,
    request_daemon_status,
    request_secret_create,
    request_secret_delete,
    request_secret_metadata,
    request_secret_update,
    request_secret_value,
)
from secrets_kit.models import ValidationError, validate_key_name

MCP_PROTOCOL_VERSION = "2025-06-18"
# Default/generated policies stay on v1; the loader also accepts opt-in v2.
MCP_POLICY_VERSION = 1
MAX_POLICY_BYTES = 64 * 1024
POLICY_KEYS = {
    "version",
    "backend",
    "service",
    "account",
    "metadata_names",
    "retrieval_names",
}
WRITE_POLICY_KEYS = POLICY_KEYS | {"create_names", "update_names", "delete_names"}


class McpPolicyError(ValueError):
    """Raised when the same-user MCP policy is missing or unsafe."""


class McpPolicyDenied(PermissionError):
    """Raised when an otherwise valid request is outside the fixed policy."""


@dataclass(frozen=True)
class McpPolicy:
    """Fixed same-user authority scope for one MCP process."""

    backend: str
    service: str
    account: str
    metadata_names: frozenset[str]
    retrieval_names: frozenset[str]
    policy_version: int = 1
    create_names: frozenset[str] = frozenset()
    update_names: frozenset[str] = frozenset()
    delete_names: frozenset[str] = frozenset()


def default_policy_path() -> Path:
    """Return the owner-controlled default MCP policy path."""
    configured = os.environ.get("SECKIT_MCP_POLICY")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "seckit" / "mcp-policy.json"


def _scope_text(value: object) -> str:
    """Validate a fixed service or account selector without reflecting it."""
    if not isinstance(value, str):
        raise McpPolicyError("invalid MCP policy")
    stripped = value.strip()
    if not stripped or len(stripped) > 128 or any(ord(char) < 32 for char in stripped):
        raise McpPolicyError("invalid MCP policy")
    return stripped


def _policy_names(value: object, *, allow_empty: bool = False) -> frozenset[str]:
    """Validate one bounded unique policy name list."""
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > 128:
        raise McpPolicyError("invalid MCP policy")
    try:
        names = [validate_key_name(name=item) for item in value if isinstance(item, str)]
    except ValidationError as exc:
        raise McpPolicyError("invalid MCP policy") from exc
    if len(names) != len(value) or len(names) != len(set(names)):
        raise McpPolicyError("invalid MCP policy")
    return frozenset(names)


def load_policy(path: Path | None = None) -> McpPolicy:
    """Load an owner-only fixed MCP scope and fail closed on every mismatch."""
    selected = path or default_policy_path()
    try:
        info = selected.lstat()
        parent = selected.parent.lstat()
    except OSError as exc:
        raise McpPolicyError("MCP policy unavailable") from exc
    if (
        selected.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
        or info.st_size > MAX_POLICY_BYTES
    ):
        raise McpPolicyError("unsafe MCP policy")
    if selected.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode):
        raise McpPolicyError("unsafe MCP policy directory")
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise McpPolicyError("unsafe MCP policy directory")
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpPolicyError("invalid MCP policy") from exc
    if not isinstance(payload, dict):
        raise McpPolicyError("invalid MCP policy")
    version = payload.get("version")
    if type(version) is not int or version not in {1, 2}:
        raise McpPolicyError("unsupported MCP policy")
    expected_keys = POLICY_KEYS if version == 1 else WRITE_POLICY_KEYS
    if set(payload) != expected_keys:
        raise McpPolicyError("invalid MCP policy")
    backend = payload.get("backend")
    if backend == "keychain":
        raise McpPolicyError("Keychain is retired; migrate credentials and change this MCP policy to sqlite")
    if backend != "sqlite":
        raise McpPolicyError("invalid MCP policy")
    metadata_names = _policy_names(payload.get("metadata_names"))
    raw_retrieval = payload.get("retrieval_names")
    if not isinstance(raw_retrieval, list) or len(raw_retrieval) > 128:
        raise McpPolicyError("invalid MCP policy")
    if raw_retrieval:
        retrieval_names = _policy_names(raw_retrieval)
    else:
        retrieval_names = frozenset()
    if not retrieval_names.issubset(metadata_names):
        raise McpPolicyError("invalid MCP policy")
    create_names = (
        _policy_names(payload.get("create_names"), allow_empty=True)
        if version == 2
        else frozenset()
    )
    update_names = (
        _policy_names(payload.get("update_names"), allow_empty=True)
        if version == 2
        else frozenset()
    )
    delete_names = (
        _policy_names(payload.get("delete_names"), allow_empty=True)
        if version == 2
        else frozenset()
    )
    if not (create_names | update_names | delete_names).issubset(metadata_names):
        raise McpPolicyError("invalid MCP policy")
    return McpPolicy(
        backend=str(backend),
        service=_scope_text(payload.get("service")),
        account=_scope_text(payload.get("account")),
        metadata_names=metadata_names,
        retrieval_names=retrieval_names,
        policy_version=version,
        create_names=create_names,
        update_names=update_names,
        delete_names=delete_names,
    )


def _tools(policy: McpPolicy | None = None) -> list[dict[str, Any]]:
    """Return read-only tools plus only explicitly granted v2 write tools."""
    read_only = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
    tools = [
        {
            "name": "seckit_status",
            "description": "Check local Secrets Kit availability and runtime health.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": read_only,
        },
        {
            "name": "seckit_list_secrets",
            "description": "List authorized Secrets Kit metadata; no secret values are returned.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "annotations": read_only,
        },
        {
            "name": "seckit_get_secret",
            "description": "Retrieve one explicitly identified authorized secret from local Secrets Kit.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "pattern": "^[A-Z0-9_]+$"},
                },
                "required": ["name"],
                "additionalProperties": False,
            },
            "annotations": read_only,
        },
    ]
    if policy is None or policy.policy_version != 2:
        return tools
    if policy.create_names:
        tools.append({
            "name": "seckit_create_secret",
            "description": "Create one secret in the fixed MCP service and account scope. The supplied value is visible to the MCP host and may be model-visible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": sorted(policy.create_names)},
                    "value": {"type": "string", "minLength": 1, "maxLength": 262144},
                },
                "required": ["name", "value"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        })
    if policy.update_names:
        tools.append({
            "name": "seckit_update_secret",
            "description": "Replace one revision-matched secret in the fixed MCP service and account scope. The supplied value is visible to the MCP host and may be model-visible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": sorted(policy.update_names)},
                    "value": {"type": "string", "minLength": 1, "maxLength": 262144},
                    "revision": {"type": "string", "pattern": "^rev1:[0-9a-f]{64}$"},
                },
                "required": ["name", "value", "revision"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        })
    if policy.delete_names:
        tools.append({
            "name": "seckit_delete_secret",
            "description": "Delete one revision-matched secret from the fixed MCP service and account scope.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "enum": sorted(policy.delete_names)},
                    "revision": {"type": "string", "pattern": "^rev1:[0-9a-f]{64}$"},
                },
                "required": ["name", "revision"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
        })
    return tools


def _tool_result(value: Any, *, is_error: bool = False) -> dict[str, Any]:
    """Build an MCP result; values reach output only after an explicit tool call."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    else:
        result["structuredContent"] = value
    return result


def _require_arguments(params: object) -> tuple[str, dict[str, Any]]:
    """Validate the MCP tool-call envelope without reflecting supplied values."""
    if not isinstance(params, dict):
        raise ValueError("invalid tool request")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not isinstance(arguments, dict):
        raise ValueError("invalid tool request")
    return name, arguments


def _required(arguments: dict[str, Any], key: str) -> str:
    """Read a required string tool argument without echoing it on failure."""
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid tool arguments")
    return value.strip()


def _required_revision(arguments: dict[str, Any]) -> str:
    """Read a required opaque revision without reflecting it on failure."""
    value = arguments.get("revision")
    if not isinstance(value, str) or not re.fullmatch(r"rev1:[0-9a-f]{64}", value):
        raise ValueError("invalid tool arguments")
    return value


def _required_write_value(arguments: dict[str, Any]) -> str:
    """Read one bounded write value; it is never echoed in results or errors."""
    value = arguments.get("value")
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 262_144:
        raise ValueError("invalid tool arguments")
    return value


def _call_tool(params: object, *, policy: McpPolicy | None) -> dict[str, Any]:
    """Dispatch one policy-scoped MCP call through the local daemon client."""
    try:
        name, arguments = _require_arguments(params)
        if policy is None:
            raise McpPolicyDenied
        if name == "seckit_status":
            if arguments:
                raise ValueError("invalid tool arguments")
            status = request_daemon_status(timeout=5.0)
            return _tool_result(
                {
                    "available": True,
                    "overall": status.get("overall"),
                    "daemon_health": status.get("daemon_health"),
                    "peer_discovery": status.get("peer_discovery"),
                    "backend": status.get("backend"),
                    "daemon": status.get("daemon"),
                }
            )
        if name == "seckit_list_secrets":
            if arguments:
                raise ValueError("invalid tool arguments")
            revision_names = sorted(policy.update_names | policy.delete_names)
            entries = request_secret_metadata(
                backend=policy.backend,
                service=policy.service,
                account=policy.account,
                revision_names=revision_names,
            )
            revision_names = policy.update_names | policy.delete_names
            scoped = []
            for entry in entries:
                if (
                    entry.get("service") != policy.service
                    or entry.get("account") != policy.account
                ):
                    raise McpPolicyDenied
                entry_name = entry.get("name")
                if entry_name not in policy.metadata_names:
                    continue
                if entry_name not in revision_names:
                    entry = {key: value for key, value in entry.items() if key != "revision"}
                scoped.append(entry)
            return _tool_result({"entries": scoped})
        if name == "seckit_get_secret":
            if set(arguments) != {"name"}:
                raise ValueError("invalid tool arguments")
            requested_name = _required(arguments, "name")
            try:
                requested_name = validate_key_name(name=requested_name)
            except ValidationError as exc:
                raise ValueError("invalid tool arguments") from exc
            if requested_name not in policy.retrieval_names:
                raise McpPolicyDenied
            value = request_secret_value(
                backend=policy.backend,
                service=policy.service,
                account=policy.account,
                name=requested_name,
            )
            return _tool_result({"value": value})
        if name in {"seckit_create_secret", "seckit_update_secret", "seckit_delete_secret"}:
            if policy.policy_version != 2:
                raise McpPolicyDenied
            if name == "seckit_create_secret":
                if set(arguments) != {"name", "value"}:
                    raise ValueError("invalid tool arguments")
                requested_name = validate_key_name(name=_required(arguments, "name"))
                if requested_name not in policy.create_names:
                    raise McpPolicyDenied
                revision = request_secret_create(
                    service=policy.service,
                    account=policy.account,
                    name=requested_name,
                    value=_required_write_value(arguments),
                )
                return _tool_result({"created": True, "revision": revision})
            if name == "seckit_update_secret":
                if set(arguments) != {"name", "value", "revision"}:
                    raise ValueError("invalid tool arguments")
                requested_name = validate_key_name(name=_required(arguments, "name"))
                if requested_name not in policy.update_names:
                    raise McpPolicyDenied
                revision = _required_revision(arguments)
                updated_revision = request_secret_update(
                    service=policy.service,
                    account=policy.account,
                    name=requested_name,
                    value=_required_write_value(arguments),
                    revision=revision,
                )
                return _tool_result({"updated": True, "revision": updated_revision})
            if set(arguments) != {"name", "revision"}:
                raise ValueError("invalid tool arguments")
            requested_name = validate_key_name(name=_required(arguments, "name"))
            if requested_name not in policy.delete_names:
                raise McpPolicyDenied
            request_secret_delete(
                service=policy.service,
                account=policy.account,
                name=requested_name,
                revision=_required_revision(arguments),
            )
            return _tool_result({"deleted": True})
        return _tool_result({"error": "unknown_tool"}, is_error=True)
    except DaemonError as exc:
        safe_error = {
            "secret_revision_conflict": "write_conflict",
            "secret_already_exists": "already_exists",
        }.get(str(exc), "secrets_kit_unavailable_or_denied")
        return _tool_result({"error": safe_error}, is_error=True)
    except (McpPolicyDenied, OSError):
        return _tool_result({"error": "secrets_kit_unavailable_or_denied"}, is_error=True)
    except ValueError:
        return _tool_result({"error": "invalid_tool_arguments"}, is_error=True)


def handle_message(message: object, *, policy: McpPolicy | None = None) -> dict[str, Any] | None:
    """Handle one MCP JSON-RPC request or notification."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "secrets-kit", "version": __version__},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tools(policy)}}
    if method == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": _call_tool(message.get("params"), policy=policy),
        }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def main() -> int:
    """Serve newline-delimited MCP JSON-RPC over standard input and output."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=None)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
    except McpPolicyError as exc:
        if str(exc).startswith("Keychain is retired"):
            print(str(exc), file=sys.stderr)
        else:
            print("Secrets Kit MCP policy is unavailable or invalid", file=sys.stderr)
        return 78
    for line in sys.stdin:
        try:
            message = json.loads(line)
            response = handle_message(message, policy=policy)
        except json.JSONDecodeError:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
        if response is not None:
            sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["McpPolicy", "McpPolicyError", "handle_message", "load_policy", "main"]
