"""Operator defaults (defaults.json, env, legacy config merge)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from typing import Dict

from secrets_kit.backends.security import (
    BACKEND_SECURE,
    BackendError,
    is_secure_backend,
    is_sqlite_backend,
    normalize_backend,
)
from secrets_kit.models.core import ENTRY_KIND_VALUES, ValidationError
from secrets_kit.registry.core import (
    RegistryError,
    defaults_path,
    load_defaults,
    registry_dir,
    save_defaults,
)

CONFIG_STORABLE_KEYS: frozenset[str] = frozenset(
    {
        "service",
        "account",
        "type",
        "kind",
        "tags",
        "backend",
        "sqlite_db",
        "default_rotation_days",
        "rotation_warn_days",
    }
)


def _load_default_config() -> Dict[str, object]:
    defaults: Dict[str, object] = {}
    dpath = defaults_path()
    if dpath.exists():
        try:
            defaults.update(load_defaults())
        except RegistryError as exc:
            raise ValidationError(str(exc)) from exc
    legacy_path = registry_dir() / "config.json"
    if legacy_path.exists():
        try:
            payload = json.loads(legacy_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid config json: {legacy_path} ({exc})") from exc
        if not isinstance(payload, dict):
            raise ValidationError(f"invalid config json: {legacy_path} (top-level must be object)")
        for key, value in payload.items():
            defaults.setdefault(str(key), value)
    return defaults


def _load_defaults() -> Dict[str, object]:
    defaults: Dict[str, object] = {}
    defaults.update(_load_default_config())
    env_map = {
        "service": "SECKIT_DEFAULT_SERVICE",
        "account": "SECKIT_DEFAULT_ACCOUNT",
        "type": "SECKIT_DEFAULT_TYPE",
        "kind": "SECKIT_DEFAULT_KIND",
        "tags": "SECKIT_DEFAULT_TAGS",
        "backend": "SECKIT_DEFAULT_BACKEND",
        "sqlite_db": "SECKIT_SQLITE_DB",
        "default_rotation_days": "SECKIT_DEFAULT_ROTATION_DAYS",
        "rotation_warn_days": "SECKIT_DEFAULT_ROTATION_WARN_DAYS",
    }
    for key, env_var in env_map.items():
        value = os.getenv(env_var)
        if value:
            if key == "backend":
                try:
                    defaults[key] = normalize_backend(value)
                except BackendError as exc:
                    raise ValidationError(str(exc)) from exc
            else:
                defaults[key] = value
    return defaults


def _current_os_account() -> str:
    return getpass.getuser() or "default"


def _apply_defaults(*, args: argparse.Namespace) -> None:
    defaults = _load_defaults()
    if hasattr(args, "backend") and not getattr(args, "backend", None):
        raw_backend = defaults.get("backend")
        if raw_backend:
            try:
                args.backend = normalize_backend(str(raw_backend))
            except BackendError as exc:
                raise ValidationError(str(exc)) from exc
        else:
            args.backend = BACKEND_SECURE
    if hasattr(args, "service") and not args.service:
        args.service = defaults.get("service")
    if hasattr(args, "account") and not args.account:
        args.account = defaults.get("account")
    if hasattr(args, "account") and not args.account:
        args.account = _current_os_account()
    if hasattr(args, "type") and not args.type:
        args.type = defaults.get("type")
    if hasattr(args, "kind") and not args.kind:
        args.kind = defaults.get("kind")
    if hasattr(args, "tags") and not args.tags:
        args.tags = defaults.get("tags")
    if hasattr(args, "tag") and not args.tag:
        args.tag = defaults.get("tags")
    if hasattr(args, "rotation_days") and getattr(args, "rotation_days", None) is None and defaults.get("default_rotation_days"):
        args.rotation_days = int(str(defaults["default_rotation_days"]))
    if hasattr(args, "rotation_warn_days") and getattr(args, "rotation_warn_days", None) is None and defaults.get("rotation_warn_days"):
        args.rotation_warn_days = int(str(defaults["rotation_warn_days"]))

    if hasattr(args, "db") and not getattr(args, "db", None):
        raw_db = defaults.get("sqlite_db")
        if raw_db:
            args.db = os.path.expanduser(str(raw_db).strip())

    if hasattr(args, "type") and not args.type:
        if args.command in {"set", "import", "migrate"}:
            args.type = "secret"

    if hasattr(args, "kind") and args.kind is None:
        if args.command in {"import", "migrate"}:
            args.kind = defaults.get("kind") or "auto"
        elif args.command == "set":
            args.kind = defaults.get("kind") or "api_key"

    if hasattr(args, "service") and not args.service:
        sync_export = args.command == "sync" and getattr(args, "sync_command", None) == "export"
        migrate_recover = args.command == "migrate" and getattr(args, "migrate_command", None) == "recover-registry"
        if (
            args.command in {"set", "get", "delete", "export", "import", "migrate", "run"}
            or sync_export
        ) and not migrate_recover:
            raise ValidationError(
                "service is required. Set --service or define SECKIT_DEFAULT_SERVICE / config.json"
            )
    if hasattr(args, "from_account") and not getattr(args, "from_account", None):
        args.from_account = args.account or _current_os_account()
    if hasattr(args, "to_account") and not getattr(args, "to_account", None):
        args.to_account = args.from_account or args.account or _current_os_account()
    if hasattr(args, "backend") and getattr(args, "backend", None):
        try:
            normalized = normalize_backend(args.backend)
        except BackendError as exc:
            raise ValidationError(str(exc)) from exc
        if hasattr(args, "keychain") and getattr(args, "keychain", None):
            if not (is_secure_backend(normalized) or is_sqlite_backend(normalized)):
                raise ValidationError("--keychain is only supported with --backend secure (alias: local) or sqlite")
        if hasattr(args, "db") and getattr(args, "db", None) and not is_sqlite_backend(normalized):
            raise ValidationError("--db is only supported with --backend sqlite")
        args.backend = normalized


def _validate_config_entry(*, key: str, value: str) -> object:
    """Coerce CLI string value for a defaults.json key."""
    v = value.strip()
    if key == "backend":
        try:
            return normalize_backend(v)
        except BackendError as exc:
            raise ValidationError(str(exc)) from exc
    if key == "sqlite_db":
        if not v:
            raise ValidationError("sqlite_db cannot be empty")
        return os.path.expanduser(v)
    if key == "type":
        if v not in {"secret", "pii"}:
            raise ValidationError("type must be secret or pii")
        return v
    if key == "kind":
        if v not in ENTRY_KIND_VALUES and v != "auto":
            raise ValidationError(f"invalid kind {v!r}")
        return v
    if key in {"default_rotation_days", "rotation_warn_days"}:
        try:
            n = int(v, 10)
        except ValueError as exc:
            raise ValidationError(f"{key} must be an integer") from exc
        if n < 0:
            raise ValidationError(f"{key} must be non-negative")
        return n
    return v
