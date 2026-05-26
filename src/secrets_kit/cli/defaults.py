"""
secrets_kit.cli.defaults

Merge order for CLI defaults: ``defaults.json`` (registry storage) + ``config.json``
+ environment variables, then applied to argparse before command dispatch.
"""

from __future__ import annotations

import argparse
import getpass
import os
from typing import Dict

from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BACKEND_SQLITE,
    BackendError,
    is_keychain_backend,
    normalize_backend,
)
from secrets_kit.cli.config_defaults import load_config_defaults
from secrets_kit.models import ENTRY_KIND_VALUES, ValidationError
from secrets_kit.registry import RegistryError, defaults_path, load_defaults

_CONFIG_STORABLE_KEYS: frozenset[str] = frozenset(
    {
        "service",
        "account",
        "type",
        "kind",
        "tags",
        "backend",
        "default_rotation_days",
        "rotation_warn_days",
    }
)
_SQLITE_PHASE5A_COMMANDS: frozenset[str] = frozenset(
    {"set", "get", "list", "delete", "explain", "export", "import", "run", "doctor"}
)


def _load_default_config() -> Dict[str, object]:
    defaults: Dict[str, object] = {}
    dpath = defaults_path()
    if dpath.exists():
        try:
            defaults.update(load_defaults())
        except RegistryError as exc:
            raise ValidationError(str(exc)) from exc
    # config.json is an active secondary defaults source. defaults.json wins
    # when both files define the same key.
    for key, value in load_config_defaults().items():
        defaults.setdefault(key, value)
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
        "default_rotation_days": "SECKIT_DEFAULT_ROTATION_DAYS",
        "rotation_warn_days": "SECKIT_DEFAULT_ROTATION_WARN_DAYS",
    }
    for key, env_var in env_map.items():
        value = os.getenv(env_var)
        if value:
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
            args.backend = BACKEND_KEYCHAIN
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
    if (
        hasattr(args, "rotation_days")
        and getattr(args, "rotation_days", None) is None
        and defaults.get("default_rotation_days")
    ):
        args.rotation_days = int(str(defaults["default_rotation_days"]))
    if (
        hasattr(args, "rotation_warn_days")
        and getattr(args, "rotation_warn_days", None) is None
        and defaults.get("rotation_warn_days")
    ):
        args.rotation_warn_days = int(str(defaults["rotation_warn_days"]))

    if hasattr(args, "type") and not args.type:
        if args.command in {"set", "import", "migrate"}:
            args.type = "secret"

    if hasattr(args, "kind") and args.kind is None:
        if args.command in {"import", "migrate"}:
            args.kind = defaults.get("kind") or "auto"
        elif args.command == "set":
            args.kind = defaults.get("kind") or "api_key"

    if hasattr(args, "service") and not args.service:
        if args.command in {"set", "get", "delete", "export", "import", "migrate", "run"}:
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
        if (
            hasattr(args, "keychain")
            and getattr(args, "keychain", None)
            and not is_keychain_backend(normalized)
        ):
            raise ValidationError("--keychain is only supported with backend=keychain")
        if (
            normalized == BACKEND_SQLITE
            and getattr(args, "command", None) not in _SQLITE_PHASE5A_COMMANDS
        ):
            raise ValidationError(
                "backend=sqlite currently supports set/get/list/delete/explain/export/import/run/doctor operations"
            )
        args.backend = normalized


def _validate_config_entry(*, key: str, value: str) -> object:
    """Coerce CLI string value for a defaults.json key."""
    v = value.strip()
    if key == "backend":
        try:
            return normalize_backend(v)
        except BackendError as exc:
            raise ValidationError(str(exc)) from exc
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
