"""
secrets_kit.cli.commands.info

Environment and backend status for operators.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Dict, Optional

from secrets_kit import __version__
from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE, normalize_backend
from secrets_kit.backends.keychain import (
    BackendError,
    check_security_cli,
    keychain_accessible,
    keychain_path,
    keychain_policy,
)
from secrets_kit.backends.sqlite import is_sqlite_backend
from secrets_kit.backends.sqlite.gate import (
    SQLITE_DEVELOPER_MODE_ENV,
    SQLITE_PATH_ENV,
    SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV,
    sqlite_path,
)
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION
from secrets_kit.cli.defaults import _CONFIG_STORABLE_KEYS, _load_defaults
from secrets_kit.cli.selection import _keychain_arg
from secrets_kit.locale import msg
from secrets_kit.registry import (
    RegistryError,
    defaults_path,
    ensure_defaults_storage,
    registry_path,
)


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _keychain_status_dict(*, path: Optional[str] = None) -> Dict[str, object]:
    """Build keychain status fields (macOS ``security`` CLI only)."""
    if not _is_macos():
        return {
            "supported": False,
            "platform": sys.platform,
            "reason": msg("cli.info.keychain_macos_only"),
        }
    if not check_security_cli():
        return {
            "supported": True,
            "available": False,
            "error": msg("errors.security_cli_not_found"),
        }
    target = keychain_path(path=path)
    try:
        policy = keychain_policy(path=target)
    except BackendError as exc:
        return {
            "supported": True,
            "available": True,
            "path": target,
            "accessible": False,
            "error": str(exc),
        }
    return {
        "supported": True,
        "available": True,
        "path": target,
        "accessible": keychain_accessible(path=target),
        "no_timeout": policy["no_timeout"],
        "lock_on_sleep": policy["lock_on_sleep"],
        "timeout_seconds": policy["timeout_seconds"],
        "raw": policy["raw"],
    }


def _sqlite_status_dict() -> Dict[str, object]:
    """Build SQLite developer-store status (path, schema, env gates)."""
    spath = sqlite_path()
    status: Dict[str, object] = {
        "path": str(spath),
        "exists": spath.exists(),
        "schema_version_expected": SCHEMA_VERSION,
        "developer_mode_env": SQLITE_DEVELOPER_MODE_ENV,
        "path_env": SQLITE_PATH_ENV,
        "suppress_warning_env": SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV,
    }
    if spath.exists():
        try:
            conn = sqlite3.connect(str(spath))
            try:
                row = conn.execute("PRAGMA user_version").fetchone()
                status["user_version"] = row[0] if row else None
            finally:
                conn.close()
        except sqlite3.Error as exc:
            status["error"] = str(exc)
    return status


def _effective_backend(*, args: argparse.Namespace) -> str:
    if getattr(args, "backend", None):
        try:
            return normalize_backend(args.backend)
        except BackendError:
            return BACKEND_SQLITE if not _is_macos() else BACKEND_KEYCHAIN
    defaults = _load_defaults()
    raw = defaults.get("backend")
    if raw:
        try:
            return normalize_backend(str(raw))
        except BackendError:
            pass
    return BACKEND_SQLITE if not _is_macos() else BACKEND_KEYCHAIN


def build_info_dict(*, args: Optional[argparse.Namespace] = None) -> Dict[str, object]:
    """Build a JSON-safe status dict (no secret values)."""
    args = args or argparse.Namespace()
    backend = _effective_backend(args=args)
    info: Dict[str, object] = {
        "version": __version__,
        "platform": sys.platform,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "backend": backend,
        "backend_availability": {
            "keychain": _is_macos(),
            "sqlite": True,
        },
    }
    try:
        ensure_defaults_storage()
        info["defaults_path"] = str(defaults_path())
        info["registry_path"] = str(registry_path())
        merged = _load_defaults()
        safe = {k: merged[k] for k in _CONFIG_STORABLE_KEYS if k in merged}
        info["defaults"] = {str(k): safe[k] for k in sorted(safe.keys(), key=str)}
    except (RegistryError, OSError, TypeError, ValueError):
        info["defaults_path"] = None
        info["registry_path"] = None
        info["defaults"] = {}

    info["keychain"] = _keychain_status_dict(
        path=_keychain_arg(args) if hasattr(args, "keychain") else None
    )
    if is_sqlite_backend(backend=backend) or not _is_macos():
        info["sqlite"] = _sqlite_status_dict()
    else:
        info["sqlite"] = {
            "included": False,
            "reason": msg("cli.info.sqlite_inactive_backend", backend=backend),
        }
    return info


def _print_keychain_warnings(*, keychain: Dict[str, object]) -> None:
    if keychain.get("supported") and keychain.get("no_timeout"):
        target = keychain.get("path", "")
        print(msg("cli.keychain_status.warning.relaxed_policy", target=target), file=sys.stderr)


def _print_info_text(*, data: Dict[str, object]) -> None:
    lines = [
        f"version: {data['version']}",
        f"platform: {data['platform']}",
        f"python: {data['python']}",
        f"backend: {data.get('backend')}",
    ]
    dp = data.get("defaults_path")
    lines.append(f"defaults_path: {dp if dp else '(unknown)'}")
    rp = data.get("registry_path")
    lines.append(f"registry_path: {rp if rp else '(unknown)'}")
    defaults = data.get("defaults") or {}
    if defaults:
        lines.append("defaults:")
        for k in sorted(defaults.keys(), key=str):
            lines.append(f"  {k}: {defaults[k]!r}")
    else:
        lines.append("defaults: (none)")
    ba = data.get("backend_availability") or {}
    lines.append(
        "backend_availability: " + ", ".join(f"{k}={ba[k]}" for k in sorted(ba.keys(), key=str))
    )
    kc = data.get("keychain") or {}
    lines.append("keychain:")
    if kc.get("supported") is False:
        lines.append(f"  note: {kc.get('reason')}")
    elif not kc.get("available", True):
        lines.append(f"  error: {kc.get('error', 'unavailable')}")
    else:
        lines.append(f"  path: {kc.get('path')}")
        lines.append(f"  accessible: {kc.get('accessible')}")
        lines.append(f"  no_timeout: {kc.get('no_timeout')}")
        lines.append(f"  lock_on_sleep: {kc.get('lock_on_sleep')}")
        lines.append(f"  timeout_seconds: {kc.get('timeout_seconds')}")
    sqlite = data.get("sqlite") or {}
    lines.append("sqlite:")
    if sqlite.get("included") is False:
        lines.append(f"  note: {sqlite.get('reason')}")
    else:
        lines.append(f"  path: {sqlite.get('path')}")
        lines.append(f"  exists: {sqlite.get('exists')}")
        if "user_version" in sqlite:
            lines.append(f"  user_version: {sqlite.get('user_version')}")
        lines.append(f"  schema_version_expected: {sqlite.get('schema_version_expected')}")
    print("\n".join(lines))


def cmd_info(*, args: argparse.Namespace) -> int:
    data = build_info_dict(args=args)
    if getattr(args, "info_json", False):
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        _print_info_text(data=data)
    kc = data.get("keychain")
    if isinstance(kc, dict):
        _print_keychain_warnings(keychain=kc)
    return 0


__all__ = ["build_info_dict", "cmd_info"]
