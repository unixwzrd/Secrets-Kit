"""
secrets_kit.mcp_server

Expose narrow read-only Secrets Kit operations over MCP stdio.

This process never imports datastore backends. It uses the same-user daemon
client, emits no logs, and returns authority values only from the explicitly
invoked ``seckit_get_secret`` tool.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secrets_kit import __version__
from secrets_kit.daemon.client import (
    DaemonError,
    request_daemon_status,
    request_secret_metadata,
    request_secret_value,
)
from secrets_kit.models import ValidationError, validate_key_name

MCP_PROTOCOL_VERSION = "2025-06-18"
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


def _policy_names(value: object) -> frozenset[str]:
    """Validate one bounded unique policy name list."""
    if not isinstance(value, list) or not value or len(value) > 128:
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
    if not isinstance(payload, dict) or set(payload) != POLICY_KEYS:
        raise McpPolicyError("invalid MCP policy")
    if payload.get("version") != MCP_POLICY_VERSION:
        raise McpPolicyError("unsupported MCP policy")
    backend = payload.get("backend")
    if backend not in {"keychain", "sqlite"}:
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
    return McpPolicy(
        backend=str(backend),
        service=_scope_text(payload.get("service")),
        account=_scope_text(payload.get("account")),
        metadata_names=metadata_names,
        retrieval_names=retrieval_names,
    )


def _tools() -> list[dict[str, Any]]:
    """Return the fixed read-only tool catalog without secret-bearing text."""
    read_only = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
    return [
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


def _call_tool(params: object, *, policy: McpPolicy | None) -> dict[str, Any]:
    """Dispatch one explicit read-only call through the local daemon client."""
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
            entries = request_secret_metadata(
                backend=policy.backend,
                service=policy.service,
                account=policy.account,
            )
            scoped = [entry for entry in entries if entry.get("name") in policy.metadata_names]
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
        return _tool_result({"error": "unknown_tool"}, is_error=True)
    except (DaemonError, McpPolicyDenied, OSError):
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
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tools()}}
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
    except McpPolicyError:
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
