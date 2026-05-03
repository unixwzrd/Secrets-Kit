"""CLI entrypoint for seckit."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from secrets_kit.native_helper import (
    helper_status,
    icloud_backend_available,
    icloud_backend_error,
)
from secrets_kit.crypto import CryptoUnavailable, build_plain_export, decrypt_payload, encrypt_payload, ensure_crypto_available
from secrets_kit.exporters import export_dotenv_placeholders, export_shell_lines
from secrets_kit.importers import (
    ImportCandidate,
    candidates_from_dotenv,
    candidates_from_env,
    candidates_from_file,
    read_dotenv,
)
from secrets_kit.keychain_backend import (
    BACKEND_CHOICES,
    BACKEND_ICLOUD_HELPER,
    BACKEND_SECURE,
    BackendError,
    check_security_cli,
    create_keychain,
    delete_keychain,
    delete_secret,
    doctor_roundtrip,
    get_secret,
    get_secret_metadata,
    harden_keychain,
    is_secure_backend,
    keychain_accessible,
    keychain_policy,
    keychain_path,
    lock_keychain,
    make_temp_keychain,
    normalize_backend,
    secret_exists,
    set_secret,
    unlock_keychain,
)
from secrets_kit.models import (
    ENTRY_KIND_VALUES,
    METADATA_SCHEMA_VERSION,
    EntryMetadata,
    ValidationError,
    now_utc_iso,
    normalize_custom,
    normalize_domains,
    normalize_tags,
    validate_entry_kind,
    validate_entry_type,
    validate_key_name,
)

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
from secrets_kit.registry import (
    RegistryError,
    delete_metadata,
    defaults_path,
    ensure_registry_storage,
    ensure_defaults_storage,
    load_registry,
    load_defaults,
    save_defaults,
    upsert_metadata,
)


def _fatal(*, message: str, code: int = 2) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return code


def _cli_version() -> str:
    try:
        return package_version("seckit")
    except PackageNotFoundError:
        return "0.1.0"


def _confirm(*, prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _read_value(*, value: Optional[str], use_stdin: bool, allow_empty: bool) -> str:
    if use_stdin:
        data = sys.stdin.read()
    else:
        data = value or ""
    if not allow_empty and not data.strip():
        raise ValidationError("value cannot be empty unless --allow-empty is set")
    return data.strip()


def _read_password(*, value: Optional[str], use_stdin: bool, prompt: str = "password: ") -> str:
    if use_stdin:
        data = sys.stdin.read()
        return data.strip()
    if value:
        return value
    return getpass.getpass(prompt)


def _format_tags(*, tags: List[str]) -> str:
    return ",".join(tags) if tags else "-"

def _print_table(*, headers: List[str], rows: List[List[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def fmt(values: List[str]) -> str:
        return "  ".join(value.ljust(widths[idx]) for idx, value in enumerate(values))

    print(fmt(headers))
    for row in rows:
        print(fmt(row))


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _load_default_config() -> Dict[str, object]:
    defaults: Dict[str, object] = {}
    dpath = defaults_path()
    if dpath.exists():
        try:
            defaults.update(load_defaults())
        except RegistryError as exc:
            raise ValidationError(str(exc)) from exc
    legacy_path = Path("~/.config/seckit/config.json").expanduser()
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
        args.backend = normalize_backend(str(raw_backend)) if raw_backend else BACKEND_SECURE
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
        normalized = normalize_backend(args.backend)
        if normalized not in {BACKEND_SECURE, BACKEND_ICLOUD_HELPER}:
            raise ValidationError(
                f"backend must be one of: {BACKEND_SECURE}, {BACKEND_ICLOUD_HELPER} (aliases: local, icloud)"
            )
        if hasattr(args, "keychain") and getattr(args, "keychain", None) and normalized == BACKEND_ICLOUD_HELPER:
            raise ValidationError(
                "--keychain is only supported with --backend secure (alias: local)"
            )
        if normalized == BACKEND_ICLOUD_HELPER and not icloud_backend_available():
            raise ValidationError(icloud_backend_error())
        args.backend = normalized


def _validate_config_entry(*, key: str, value: str) -> object:
    """Coerce CLI string value for a defaults.json key."""
    v = value.strip()
    if key == "backend":
        normalized = normalize_backend(v)
        if normalized not in {BACKEND_SECURE, BACKEND_ICLOUD_HELPER}:
            raise ValidationError(
                f"backend must be one of: {BACKEND_SECURE}, {BACKEND_ICLOUD_HELPER} (aliases: local, icloud)"
            )
        return normalized
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


def cmd_config_show(*, args: argparse.Namespace) -> int:
    """Print defaults.json or effective defaults (file + legacy + env)."""
    try:
        if getattr(args, "effective", False):
            merged = _load_defaults()
            print(
                json.dumps(
                    {
                        "source": "effective",
                        "defaults_path": str(defaults_path()),
                        "config": merged,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        ensure_defaults_storage()
        on_disk = dict(load_defaults())
        print(
            json.dumps(
                {
                    "source": "file",
                    "defaults_path": str(defaults_path()),
                    "config": on_disk,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (ValidationError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_config_set(*, args: argparse.Namespace) -> int:
    """Persist one key to defaults.json."""
    try:
        key = str(args.key)
        if key not in _CONFIG_STORABLE_KEYS:
            allowed = ", ".join(sorted(_CONFIG_STORABLE_KEYS))
            raise ValidationError(f"unknown key {key!r}; allowed: {allowed}")
        coerced = _validate_config_entry(key=key, value=str(args.value))
        ensure_defaults_storage()
        data = dict(load_defaults())
        data[key] = coerced
        save_defaults(payload=data)
        print(
            json.dumps(
                {"saved": True, "key": key, "value": data[key], "defaults_path": str(defaults_path())},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (ValidationError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_config_unset(*, args: argparse.Namespace) -> int:
    """Remove one key from defaults.json."""
    try:
        key = str(args.key)
        if key not in _CONFIG_STORABLE_KEYS:
            allowed = ", ".join(sorted(_CONFIG_STORABLE_KEYS))
            raise ValidationError(f"unknown key {key!r}; allowed: {allowed}")
        ensure_defaults_storage()
        data = dict(load_defaults())
        if key not in data:
            print(f"key {key!r} not present in {defaults_path()}", file=sys.stderr)
            return 0
        del data[key]
        save_defaults(payload=data)
        print(json.dumps({"saved": True, "removed": key, "defaults_path": str(defaults_path())}, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_config_path(*, args: argparse.Namespace) -> int:
    """Print path to defaults.json."""
    try:
        ensure_defaults_storage()
        print(defaults_path())
        return 0
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)


def _keychain_arg(args: argparse.Namespace) -> Optional[str]:
    return getattr(args, "keychain", None)


def _backend_arg(args: argparse.Namespace) -> str:
    return getattr(args, "backend", BACKEND_SECURE)


def _parse_meta_pairs(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValidationError(f"invalid --meta value '{item}'; expected key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValidationError("custom metadata key cannot be empty")
        out[key] = value.strip()
    return out


def _resolve_domains(*, domain: Optional[List[str]], domains_csv: Optional[str]) -> List[str]:
    items: List[str] = []
    if domains_csv:
        items.extend(domains_csv.split(","))
    if domain:
        items.extend(domain)
    return normalize_domains(items)


def _select_entries(
    *,
    args: argparse.Namespace,
    require_explicit_selection: bool,
) -> List[EntryMetadata]:
    entries = load_registry()
    selected: Dict[str, EntryMetadata] = {}
    names = {validate_key_name(name=item) for item in args.names.split(",")} if getattr(args, "names", None) else set()

    if names:
        for name in sorted(names):
            resolved = _read_metadata(
                service=args.service,
                account=args.account,
                name=name,
                registry=entries,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
            if not resolved:
                continue
            meta = resolved["metadata"]
            if isinstance(meta, EntryMetadata):
                selected[meta.key()] = meta
        return sorted(selected.values(), key=lambda item: item.name)

    explicit_filter = bool(
        getattr(args, "tag", None)
        or getattr(args, "type", None)
        or getattr(args, "kind", None)
        or getattr(args, "all", False)
    )
    for indexed in entries.values():
        if args.service and indexed.service != args.service:
            continue
        if args.account and indexed.account != args.account:
            continue
        if getattr(args, "type", None) and indexed.entry_type != args.type:
            continue
        if getattr(args, "kind", None) and indexed.entry_kind != args.kind:
            continue
        if getattr(args, "tag", None) and args.tag not in indexed.tags:
            continue
        if require_explicit_selection and not explicit_filter:
            continue
        resolved = _read_metadata(
            service=indexed.service,
            account=indexed.account,
            name=indexed.name,
            registry=entries,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if not resolved:
            continue
        meta = resolved["metadata"]
        if isinstance(meta, EntryMetadata):
            selected[meta.key()] = meta

    return sorted(selected.values(), key=lambda item: item.name)


def _build_env_map(*, entries: List[EntryMetadata], args: argparse.Namespace) -> Dict[str, str]:
    env_map: Dict[str, str] = {}
    for meta in entries:
        try:
            env_map[meta.name] = get_secret(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
        except BackendError as exc:
            raise BackendError(
                f"failed to read secret for run: service={meta.service} account={meta.account} "
                f"name={meta.name}. Use --names/--tag to narrow the injected set if this command "
                f"does not need every entry in the scope. Underlying error: {exc}"
            ) from exc
    return env_map


def _child_command_args(raw_args: List[str]) -> List[str]:
    args = list(raw_args)
    if args and args[0] == "--":
        args = args[1:]
    return args


def _exec_child(*, argv: List[str], env: Dict[str, str]) -> int:
    os.execvpe(argv[0], argv, env)
    return 0


def _build_metadata(*, args: argparse.Namespace, name: str, source: str) -> EntryMetadata:
    registry = load_registry()
    existing = _read_metadata(
        service=args.service,
        account=args.account,
        name=name,
        registry=registry,
        path=_keychain_arg(args),
        backend=_backend_arg(args),
    )
    created_at = existing["metadata"].created_at if existing else now_utc_iso()
    last_rotated_at = now_utc_iso()
    if existing and existing["metadata"].last_rotated_at:
        last_rotated_at = existing["metadata"].last_rotated_at
    if existing and existing["metadata"].source == source:
        last_rotated_at = existing["metadata"].last_rotated_at or last_rotated_at
    return EntryMetadata(
        name=name,
        entry_type=validate_entry_type(entry_type=args.type),
        entry_kind=validate_entry_kind(entry_kind=args.kind),
        tags=normalize_tags(tags_csv=args.tags),
        comment=args.comment or "",
        service=args.service,
        account=args.account,
        created_at=created_at,
        updated_at=now_utc_iso(),
        source=source,
        schema_version=METADATA_SCHEMA_VERSION,
        source_url=getattr(args, "source_url", "") or "",
        source_label=getattr(args, "source_label", "") or "",
        rotation_days=getattr(args, "rotation_days", None),
        rotation_warn_days=getattr(args, "rotation_warn_days", None),
        last_rotated_at=last_rotated_at,
        expires_at=getattr(args, "expires_at", "") or "",
        domains=_resolve_domains(domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None)),
        custom=normalize_custom(_parse_meta_pairs(getattr(args, "meta", None))),
    )


def _resolve_status(*, metadata: EntryMetadata) -> List[str]:
    now = datetime.now(timezone.utc)
    statuses: List[str] = []

    rotation_days = metadata.rotation_days
    if rotation_days:
        rotated_at = _parse_timestamp(metadata.last_rotated_at or metadata.updated_at or metadata.created_at)
        if rotated_at:
            due_at = rotated_at + timedelta(days=rotation_days)
            warn_days = metadata.rotation_warn_days or 7
            if due_at <= now:
                statuses.append("rotation-overdue")
            elif due_at <= now + timedelta(days=warn_days):
                statuses.append("rotation-soon")

    expires_at = _parse_timestamp(metadata.expires_at)
    if expires_at:
        if expires_at <= now:
            statuses.append("expired")
        elif expires_at <= now + timedelta(days=7):
            statuses.append("expires-soon")

    return statuses


def _read_metadata(
    *,
    service: str,
    account: str,
    name: str,
    registry: Optional[Dict[str, EntryMetadata]] = None,
    path: Optional[str] = None,
    backend: str = "secure",
) -> Optional[Dict[str, object]]:
    key = f"{service}::{account}::{name}"
    registry = registry if registry is not None else load_registry()
    registry_meta = registry.get(key)
    if secret_exists(service=service, account=account, name=name, path=path, backend=backend):
        keychain_fields: Dict[str, object] = {}
        try:
            keychain_fields = get_secret_metadata(service=service, account=account, name=name, path=path, backend=backend)
        except BackendError:
            if registry_meta:
                return {
                    "metadata": registry_meta,
                    "metadata_source": "registry-fallback",
                    "keychain_fields": {},
                    "registry_fallback_used": True,
                }
            minimal = EntryMetadata(
                name=name,
                service=service,
                account=account,
                comment="",
                source="keychain-unmanaged",
            )
            return {
                "metadata": minimal,
                "metadata_source": "keychain-minimal",
                "keychain_fields": {},
                "registry_fallback_used": False,
            }
        keychain_meta = EntryMetadata.from_keychain_comment(str(keychain_fields.get("comment", "")))
        if keychain_meta:
            return {
                "metadata": keychain_meta,
                "metadata_source": "keychain",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": False,
            }
        if registry_meta:
            return {
                "metadata": registry_meta,
                "metadata_source": "registry-fallback",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": True,
            }
        minimal = EntryMetadata(
            name=name,
            service=service,
            account=account,
            comment="",
            source="keychain-unmanaged",
        )
        return {
            "metadata": minimal,
            "metadata_source": "keychain-minimal",
            "keychain_fields": keychain_fields,
            "registry_fallback_used": False,
        }
    if registry_meta and path is None and is_secure_backend(backend):
        return {
            "metadata": registry_meta,
            "metadata_source": "registry-only",
            "keychain_fields": {},
            "registry_fallback_used": True,
        }
    return None


def _merge_candidates(*, groups: Iterable[List[ImportCandidate]]) -> Dict[str, ImportCandidate]:
    merged: Dict[str, ImportCandidate] = {}
    for group in groups:
        for candidate in group:
            merged[candidate.metadata.key()] = candidate
    return merged


def _apply_candidates(
    *,
    candidates: Dict[str, ImportCandidate],
    allow_overwrite: bool,
    dry_run: bool,
    allow_empty: bool,
    path: Optional[str] = None,
    backend: str = "secure",
) -> Dict[str, int]:
    registry = load_registry()
    stats = {"created": 0, "updated": 0, "skipped": 0, "unchanged": 0}
    for key in sorted(candidates):
        candidate = candidates[key]
        resolved = _read_metadata(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            registry=registry,
            path=path,
            backend=backend,
        )
        exists = resolved is not None and secret_exists(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            path=path,
            backend=backend,
        )
        if exists and not allow_overwrite:
            stats["skipped"] += 1
            continue
        if not allow_empty and not candidate.value:
            stats["skipped"] += 1
            continue
        if resolved:
            existing_meta = resolved["metadata"]
            if isinstance(existing_meta, EntryMetadata):
                candidate.metadata = _merge_import_metadata(existing=existing_meta, incoming=candidate.metadata)
                candidate.metadata.created_at = existing_meta.created_at
            if exists and not dry_run:
                current_value = get_secret(
                    service=candidate.metadata.service,
                    account=candidate.metadata.account,
                    name=candidate.metadata.name,
                    path=path,
                    backend=backend,
                )
                if current_value == candidate.value:
                    stats["unchanged"] += 1
                    continue
        candidate.metadata.updated_at = now_utc_iso()
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue
        set_secret(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            value=candidate.value,
            label=candidate.metadata.name,
            comment=candidate.metadata.to_keychain_comment(),
            path=path,
            backend=backend,
        )
        upsert_metadata(metadata=candidate.metadata)
        stats["updated" if exists else "created"] += 1
    return stats


def _merge_import_metadata(*, existing: EntryMetadata, incoming: EntryMetadata) -> EntryMetadata:
    merged = EntryMetadata.from_dict(existing.to_dict())
    merged.source = incoming.source
    merged.updated_at = now_utc_iso()
    # Keep existing classification/tags/comment unless the destination did not have them.
    if not merged.entry_type:
        merged.entry_type = incoming.entry_type
    if merged.entry_kind == "generic" and incoming.entry_kind != "generic":
        merged.entry_kind = incoming.entry_kind
    if not merged.tags and incoming.tags:
        merged.tags = incoming.tags
    if not merged.comment and incoming.comment:
        merged.comment = incoming.comment
    return merged


def cmd_set(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value = _read_value(value=args.value, use_stdin=args.stdin, allow_empty=args.allow_empty)
        meta = _build_metadata(args=args, name=name, source="manual")
        set_secret(
            service=args.service,
            account=args.account,
            name=name,
            value=value,
            label=name,
            comment=meta.to_keychain_comment(),
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        upsert_metadata(metadata=meta)
        print(f"stored: name={name} type={meta.entry_type} kind={meta.entry_kind} service={args.service} account={args.account}")
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc))


def cmd_get(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value = get_secret(service=args.service, account=args.account, name=name, path=_keychain_arg(args), backend=_backend_arg(args))
        resolved = _read_metadata(service=args.service, account=args.account, name=name, path=_keychain_arg(args), backend=_backend_arg(args))
        metadata = resolved["metadata"] if resolved else None
        kind = metadata.entry_kind if isinstance(metadata, EntryMetadata) else "unknown"
        entry_type = metadata.entry_type if isinstance(metadata, EntryMetadata) else "unknown"
        if args.raw:
            print(value)
        else:
            print(f"name={name} type={entry_type} kind={kind} service={args.service} account={args.account} value=<redacted>")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_list(*, args: argparse.Namespace) -> int:
    try:
        entries = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)

    rows = []
    cutoff = None
    if args.stale is not None:
        cutoff = datetime.now(timezone.utc).timestamp() - (args.stale * 86400)
    rows = []
    for indexed in entries.values():
        if args.service and indexed.service != args.service:
            continue
        if args.account and indexed.account != args.account:
            continue
        if args.type and indexed.entry_type != args.type:
            continue
        if args.kind and indexed.entry_kind != args.kind:
            continue
        if args.tag and args.tag not in indexed.tags:
            continue
        resolved = _read_metadata(
            service=indexed.service,
            account=indexed.account,
            name=indexed.name,
            registry=entries,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if not resolved:
            continue
        meta = resolved["metadata"]
        if not isinstance(meta, EntryMetadata):
            continue
        if cutoff is not None:
            updated = _parse_timestamp(meta.updated_at)
            if not updated:
                continue
            if updated.timestamp() > cutoff:
                continue
        rows.append((meta, resolved))

    rows.sort(key=lambda item: (item[0].service, item[0].account, item[0].name))

    if args.format == "json":
        output = []
        for item, resolved in rows:
            payload = item.to_dict()
            payload["status"] = _resolve_status(metadata=item)
            payload["metadata_source"] = resolved["metadata_source"]
            payload["registry_fallback_used"] = resolved["registry_fallback_used"]
            output.append(payload)
        print(json.dumps(output, indent=2))
        return 0

    if not rows:
        print("no entries")
        return 0

    headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "STATUS", "UPDATED_AT"]
    table_rows: List[List[str]] = []
    for item, resolved in rows:
        table_rows.append(
            [
                item.name,
                item.entry_type,
                item.entry_kind,
                item.service,
                item.account,
                _format_tags(tags=item.tags),
                ",".join(_resolve_status(metadata=item) or ["ok"]),
                item.updated_at,
            ]
        )
    _print_table(headers=headers, rows=table_rows)
    return 0


def cmd_delete(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        if not args.yes and not _confirm(prompt=f"Delete {name} from service={args.service} account={args.account}?"):
            print("aborted")
            return 1
        delete_secret(service=args.service, account=args.account, name=name, path=_keychain_arg(args), backend=_backend_arg(args))
        delete_metadata(service=args.service, account=args.account, name=name)
        print(f"deleted: name={name} service={args.service} account={args.account}")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_explain(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        resolved = _read_metadata(service=args.service, account=args.account, name=name, path=_keychain_arg(args), backend=_backend_arg(args))
        if not resolved:
            return _fatal(message=f"entry not found: {args.service}::{args.account}::{name}", code=1)
        entry = resolved["metadata"]
        if not isinstance(entry, EntryMetadata):
            return _fatal(message="metadata decode failed", code=1)
        payload = entry.to_dict()
        payload["status"] = _resolve_status(metadata=entry)
        payload["metadata_source"] = resolved["metadata_source"]
        payload["registry_fallback_used"] = resolved["registry_fallback_used"]
        payload["keychain_fields"] = resolved["keychain_fields"]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def _preview_candidates(*, merged: Dict[str, ImportCandidate]) -> None:
    print("plan:")
    print("NAME\tTYPE\tKIND\tSERVICE\tACCOUNT\tTAGS\tSOURCE\tVALUE")
    for key in sorted(merged):
        candidate = merged[key]
        meta = candidate.metadata
        print(
            f"{meta.name}\t{meta.entry_type}\t{meta.entry_kind}\t{meta.service}\t{meta.account}\t{_format_tags(tags=meta.tags)}\t{meta.source}\t<redacted>"
        )


def cmd_import_env(*, args: argparse.Namespace) -> int:
    if not args.dotenv and not args.from_env:
        return _fatal(message="import env requires --dotenv and/or --from-env")
    try:
        groups: List[List[ImportCandidate]] = []
        if args.dotenv:
            groups.append(
                candidates_from_dotenv(
                    dotenv_path=Path(args.dotenv),
                    account=args.account,
                    service=args.service,
                    entry_type=args.type,
                    entry_kind=args.kind,
                    tags_csv=args.tags,
                )
            )
        if args.from_env:
            groups.append(
                candidates_from_env(
                    prefix=args.from_env,
                    account=args.account,
                    service=args.service,
                    entry_type=args.type,
                    entry_kind=args.kind,
                    tags_csv=args.tags,
                )
            )
        merged = _merge_candidates(groups=groups)
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite or getattr(args, "upsert", False),
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_import_file(*, args: argparse.Namespace) -> int:
    try:
        rows = candidates_from_file(
            file_path=Path(args.file),
            fmt=args.format,
            default_type=args.type,
            default_kind=args.kind,
        )
        merged = {row.metadata.key(): row for row in rows}
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_import_encrypted(*, args: argparse.Namespace) -> int:
    try:
        ensure_crypto_available()
        password = _read_password(
            value=args.password,
            use_stdin=args.password_stdin,
            prompt="backup file password for encrypted import: ",
        )
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        decrypted = decrypt_payload(payload=payload, password=password)
        if decrypted.get("format") != "seckit.export":
            return _fatal(message="unsupported decrypted payload format", code=1)
        entries = decrypted.get("entries", [])
        rows: List[ImportCandidate] = []
        for row in entries:
            if not isinstance(row, dict):
                continue
            meta = EntryMetadata.from_dict(row.get("metadata", {}))
            rows.append(ImportCandidate(metadata=meta, value=str(row.get("value", "")).strip()))
        merged = {row.metadata.key(): row for row in rows}
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError, CryptoUnavailable) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_export(*, args: argparse.Namespace) -> int:
    try:
        selected = _select_entries(args=args, require_explicit_selection=True)
        if not selected:
            return _fatal(message="no matching entries selected for export", code=1)

        if args.format == "shell":
            print(export_shell_lines(env_map=_build_env_map(entries=selected, args=args)))
            return 0

        if args.format == "dotenv":
            keys = [meta.name for meta in selected]
            print(export_dotenv_placeholders(keys=keys))
            return 0

        if args.format == "encrypted-json":
            ensure_crypto_available()
            password = _read_password(
                value=args.password,
                use_stdin=args.password_stdin,
                prompt="new password to encrypt the backup file: ",
            )
            items: List[Dict[str, str]] = []
            for meta in sorted(selected, key=lambda item: item.name):
                items.append(
                    {
                        "metadata": meta.to_dict(),
                        "value": get_secret(
                            service=meta.service,
                            account=meta.account,
                            name=meta.name,
                            path=_keychain_arg(args),
                            backend=_backend_arg(args),
                        ),
                    }
                )
            plain = build_plain_export(entries=items)
            encrypted = encrypt_payload(payload=plain, password=password)
            output = json.dumps(encrypted.__dict__, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return 0

        return _fatal(message=f"unsupported format: {args.format}", code=1)
    except (ValidationError, RegistryError, BackendError, CryptoUnavailable) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_run(*, args: argparse.Namespace) -> int:
    command = _child_command_args(args.child_command)
    try:
        if not command:
            return _fatal(message="run requires a target command after --", code=2)

        selected = _select_entries(args=args, require_explicit_selection=False)
        if not selected:
            return _fatal(message="no matching entries selected for run", code=1)

        env = os.environ.copy()
        env.update(_build_env_map(entries=selected, args=args))
        return _exec_child(argv=command, env=env)
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)
    except FileNotFoundError:
        return _fatal(message=f"command not found: {command[0]}", code=127)
    except OSError as exc:
        return _fatal(message=f"failed to launch {command[0]}: {exc}", code=126)


def cmd_service_copy(*, args: argparse.Namespace) -> int:
    try:
        from_account = args.from_account or _current_os_account()
        to_account = args.to_account or from_account
        selector_args = argparse.Namespace(
            service=args.from_service,
            account=from_account,
            names=args.names,
            tag=args.tag,
            type=args.type,
            kind=args.kind,
            all=True,
            keychain=args.keychain,
            backend=_backend_arg(args),
        )
        selected = _select_entries(args=selector_args, require_explicit_selection=False)
        if not selected:
            return _fatal(
                message=f"no matching entries selected for service copy: {args.from_service}/{from_account}",
                code=1,
            )

        stats = {"created": 0, "updated": 0, "skipped": 0}
        for source_meta in selected:
            dest_exists = secret_exists(
                service=args.to_service,
                account=to_account,
                name=source_meta.name,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
            if dest_exists and not args.overwrite:
                stats["skipped"] += 1
                continue

            value = get_secret(
                service=source_meta.service,
                account=source_meta.account,
                name=source_meta.name,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
            dest_meta = EntryMetadata.from_dict(source_meta.to_dict())
            dest_meta.service = args.to_service
            dest_meta.account = to_account
            dest_meta.source = f"copy:{source_meta.service}/{source_meta.account}"
            dest_meta.updated_at = now_utc_iso()
            if not dest_exists:
                dest_meta.created_at = now_utc_iso()
            else:
                existing = _read_metadata(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    path=_keychain_arg(args),
                    backend=_backend_arg(args),
                )
                if existing and isinstance(existing.get("metadata"), EntryMetadata):
                    dest_meta.created_at = existing["metadata"].created_at

            if not args.dry_run:
                set_secret(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    value=value,
                    label=source_meta.name,
                    comment=dest_meta.to_keychain_comment(),
                    path=_keychain_arg(args),
                    backend=_backend_arg(args),
                )
                upsert_metadata(metadata=dest_meta)
            stats["updated" if dest_exists else "created"] += 1

        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_doctor(*, args: argparse.Namespace) -> int:
    status = {
        "security_cli": False,
        "registry": False,
        "defaults": False,
        "keychain_roundtrip": False,
        "registry_path": None,
        "defaults_path": None,
        "metadata_keychain_drift": [],
        "entries_using_registry_fallback": [],
        "rotation_warnings": [],
    }
    if check_security_cli():
        status["security_cli"] = True
    else:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message="security CLI not found", code=1)

    try:
        path = ensure_registry_storage()
        status["registry"] = True
        status["registry_path"] = str(path)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        dpath = ensure_defaults_storage()
        status["defaults"] = True
        status["defaults_path"] = str(dpath)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        doctor_roundtrip(path=_keychain_arg(args), backend=_backend_arg(args))
        status["keychain_roundtrip"] = True
    except BackendError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        entries = load_registry()
        drift = []
        fallback = []
        warnings = []
        for meta in sorted(entries.values(), key=lambda item: (item.service, item.account, item.name)):
            if not secret_exists(service=meta.service, account=meta.account, name=meta.name, path=_keychain_arg(args), backend=_backend_arg(args)):
                if _keychain_arg(args) is not None:
                    continue
                drift.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
                continue
            resolved = _read_metadata(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                registry=entries,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
            if resolved and resolved["metadata_source"] == "registry-fallback":
                fallback.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
            if resolved and isinstance(resolved["metadata"], EntryMetadata):
                entry_status = _resolve_status(metadata=resolved["metadata"])
                if entry_status:
                    warnings.append(
                        {
                            "name": meta.name,
                            "service": meta.service,
                            "account": meta.account,
                            "status": entry_status,
                        }
                    )
        status["metadata_keychain_drift"] = drift
        status["entries_using_registry_fallback"] = fallback
        status["rotation_warnings"] = warnings
    except (RegistryError, BackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"] or status["entries_using_registry_fallback"]:
        return _fatal(message="metadata/keychain drift detected", code=1)
    return 0


def cmd_unlock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)
    command = f"security unlock-keychain {target}"
    harden_command = f"security set-keychain-settings -l -u -t {args.timeout} {target}"
    policy = None
    try:
        policy = keychain_policy(path=target)
    except BackendError:
        policy = None

    print("")
    print("********************************************************************************")
    print("")
    print("About to run:")
    print("")
    print(f"  {command}")
    print("")
    print("This will prompt macOS for the keychain password if needed.")
    print("Secrets-Kit does not read, capture, or store that password.")
    if policy and policy.get("no_timeout"):
        print("")
        print("WARNING: relaxed keychain policy detected: no timeout is configured.")
        print("Suggested hardening command:")
        print("")
        print(f"  {harden_command}")
        print("")
        print("Recommended policy: lock on sleep and lock after timeout.")
    print("********************************************************************************")
    print("")

    if args.dry_run:
        return 0

    if keychain_accessible(path=target):
        print(f"keychain already accessible: {target}")
        return 0

    if not args.yes and not _confirm(prompt=f"Proceed with unlocking {target}?"):
        print("aborted")
        return 1

    try:
        unlock_keychain(path=target)
        print(f"unlocked: {target}")
        if args.harden:
            print("")
            print("********************************************************************************")
            print("")
            print("About to run:")
            print("")
            print(f"  {harden_command}")
            print("")
            print("This will enable lock-on-sleep and lock-after-timeout for the keychain.")
            print("********************************************************************************")
            print("")
            harden_keychain(path=target, timeout_seconds=args.timeout)
            print(f"hardened: {target} timeout={args.timeout}s")
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_lock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)

    if args.dry_run:
        print(f"security lock-keychain {target}")
        return 0

    try:
        print(f"locking keychain: {target}")
        lock_keychain(path=target)
        print(f"locked: {target}")
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_keychain_status(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)
    try:
        policy = keychain_policy(path=target)
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)

    output = {
        "path": target,
        "accessible": keychain_accessible(path=target),
        "no_timeout": policy["no_timeout"],
        "lock_on_sleep": policy["lock_on_sleep"],
        "timeout_seconds": policy["timeout_seconds"],
        "raw": policy["raw"],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if output["no_timeout"]:
        print(
            f"WARNING: relaxed keychain policy detected. Suggested command:\n"
            f"  security set-keychain-settings -l -u -t 3600 {target}",
            file=sys.stderr,
        )
    return 0


def cmd_version(*, args: argparse.Namespace) -> int:
    del args
    print(_cli_version())
    return 0


def cmd_helper_status(*, args: argparse.Namespace) -> int:
    del args
    print(json.dumps(helper_status(), indent=2, sort_keys=True))
    return 0


def cmd_migrate_dotenv(*, args: argparse.Namespace) -> int:
    dotenv = Path(args.dotenv)
    if not dotenv.exists():
        return _fatal(message=f"dotenv file not found: {dotenv}", code=1)

    if args.archive:
        archive_path = Path(args.archive)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dotenv, archive_path)
        print(f"archived: {archive_path}")

    tmp = argparse.Namespace(
        dotenv=str(dotenv),
        from_env=None,
        account=args.account,
        service=args.service,
        keychain=args.keychain,
        backend=args.backend,
        type=args.type,
        kind=args.kind,
        tags=args.tags,
        dry_run=args.dry_run,
        allow_overwrite=args.allow_overwrite,
        upsert=False,
        allow_empty=args.allow_empty,
        yes=args.yes,
    )
    code = cmd_import_env(args=tmp)
    if code != 0 or args.dry_run or not args.replace_with_placeholders:
        return code

    parsed = read_dotenv(dotenv_path=dotenv)
    original = dotenv.read_text(encoding="utf-8").splitlines()
    rewritten: List[str] = []
    for line in original:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            rewritten.append(line)
            continue
        left = stripped.split("=", 1)[0].strip()
        if left.startswith("export "):
            left = left[len("export ") :].strip()
        if left in parsed:
            prefix = "export " if stripped.startswith("export ") else ""
            rewritten.append(f"{prefix}{left}=${{{left}}}")
        else:
            rewritten.append(line)

    dotenv.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(f"rewrote placeholders in {dotenv}")
    return 0


def cmd_migrate_metadata(*, args: argparse.Namespace) -> int:
    try:
        registry = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)

    selected: List[EntryMetadata] = []
    for meta in registry.values():
        if args.service and meta.service != args.service:
            continue
        if args.account and meta.account != args.account:
            continue
        selected.append(meta)

    stats = {"migrated": 0, "skipped": 0, "missing_keychain": 0}
    for meta in sorted(selected, key=lambda item: (item.service, item.account, item.name)):
        if not secret_exists(service=meta.service, account=meta.account, name=meta.name, path=_keychain_arg(args), backend=_backend_arg(args)):
            stats["missing_keychain"] += 1
            continue
        resolved = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if resolved and resolved["metadata_source"] == "keychain" and not args.force:
            stats["skipped"] += 1
            continue
        if args.dry_run:
            stats["migrated"] += 1
            continue
        value = get_secret(service=meta.service, account=meta.account, name=meta.name, path=_keychain_arg(args), backend=_backend_arg(args))
        meta.updated_at = now_utc_iso()
        set_secret(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            value=value,
            label=meta.name,
            comment=meta.to_keychain_comment(),
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        verify = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if not verify or verify["metadata_source"] != "keychain":
            return _fatal(message=f"failed to verify migrated metadata for {meta.key()}", code=1)
        upsert_metadata(metadata=meta)
        stats["migrated"] += 1

    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI parser."""
    parser = argparse.ArgumentParser(prog="seckit", description="Secure secrets and PII CLI for local ops")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {_cli_version()}")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
        description="Available commands",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account")
    common.add_argument("--service")
    common.add_argument("--backend", choices=list(BACKEND_CHOICES))
    common.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")

    p_set = sub.add_parser("set", parents=[common], help="Store or update one secret value")
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--value")
    p_set.add_argument("--stdin", action="store_true")
    p_set.add_argument("--type", choices=["secret", "pii"])
    p_set.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_set.add_argument("--tags")
    p_set.add_argument("--comment")
    p_set.add_argument("--source-url")
    p_set.add_argument("--source-label")
    p_set.add_argument("--rotation-days", type=int)
    p_set.add_argument("--rotation-warn-days", type=int)
    p_set.add_argument("--expires-at")
    p_set.add_argument("--domain", action="append")
    p_set.add_argument("--domains")
    p_set.add_argument("--meta", action="append")
    p_set.add_argument("--allow-empty", action="store_true")
    p_set.set_defaults(func=cmd_set)

    p_get = sub.add_parser("get", parents=[common], help="Read one stored secret value")
    p_get.add_argument("--name", required=True)
    p_get.add_argument("--raw", action="store_true")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List stored metadata entries, redacted by default")
    p_list.add_argument("--account")
    p_list.add_argument("--service")
    p_list.add_argument("--type", choices=["secret", "pii"])
    p_list.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_list.add_argument("--tag")
    p_list.add_argument("--stale", type=int, help="Filter entries older than N days")
    p_list.add_argument("--format", choices=["table", "json"], default="table")
    p_list.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_list.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_list.set_defaults(func=cmd_list)

    p_explain = sub.add_parser("explain", parents=[common], help="Show resolved metadata for a stored entry")
    p_explain.add_argument("--name", required=True)
    p_explain.set_defaults(func=cmd_explain)

    cfg_keys = sorted(_CONFIG_STORABLE_KEYS)
    p_config = sub.add_parser("config", help="View or edit ~/.config/seckit/defaults.json")
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_config_show = config_sub.add_parser(
        "show",
        help="Print defaults from defaults.json; add --effective for merged file + legacy config + env",
    )
    p_config_show.add_argument(
        "--effective",
        action="store_true",
        help="Merge defaults.json, legacy ~/.config/seckit/config.json, and SECKIT_* env overrides",
    )
    p_config_show.set_defaults(func=cmd_config_show)
    p_config_set = config_sub.add_parser("set", help="Set one key in defaults.json")
    p_config_set.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_set.add_argument("value", help="Value (use quotes if it contains spaces)")
    p_config_set.set_defaults(func=cmd_config_set)
    p_config_unset = config_sub.add_parser("unset", help="Remove one key from defaults.json")
    p_config_unset.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_unset.set_defaults(func=cmd_config_unset)
    p_config_path = config_sub.add_parser("path", help="Print path to defaults.json")
    p_config_path.set_defaults(func=cmd_config_path)

    p_delete = sub.add_parser("delete", parents=[common], help="Delete one stored secret and its metadata")
    p_delete.add_argument("--name", required=True)
    p_delete.add_argument("--yes", action="store_true")
    p_delete.set_defaults(func=cmd_delete)

    p_import = sub.add_parser("import", help="Import secrets from env or file sources")
    import_sub = p_import.add_subparsers(dest="import_command", required=True)

    p_import_env = import_sub.add_parser("env", parents=[common], help="Import secrets from dotenv and/or live environment")
    p_import_env.add_argument("--dotenv")
    p_import_env.add_argument("--from-env")
    p_import_env.add_argument("--type", choices=["secret", "pii"])
    p_import_env.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_env.add_argument("--tags")
    p_import_env.add_argument("--dry-run", action="store_true")
    p_import_env.add_argument("--allow-overwrite", action="store_true")
    p_import_env.add_argument("--upsert", action="store_true", help="Create new names and update existing values")
    p_import_env.add_argument("--allow-empty", action="store_true")
    p_import_env.add_argument("--yes", action="store_true")
    p_import_env.set_defaults(func=cmd_import_env)

    p_import_file = import_sub.add_parser("file", help="Import secrets from JSON or YAML files")
    p_import_file.add_argument("--file", required=True)
    p_import_file.add_argument("--format", choices=["json", "yaml", "yml"])
    p_import_file.add_argument("--type", choices=["secret", "pii"])
    p_import_file.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_file.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_import_file.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_import_file.add_argument("--dry-run", action="store_true")
    p_import_file.add_argument("--allow-overwrite", action="store_true")
    p_import_file.add_argument("--allow-empty", action="store_true")
    p_import_file.add_argument("--yes", action="store_true")
    p_import_file.set_defaults(func=cmd_import_file)

    p_import_encrypted = import_sub.add_parser("encrypted-json", help="Import secrets from encrypted JSON export")
    p_import_encrypted.add_argument("--file", required=True)
    p_import_encrypted.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_import_encrypted.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_import_encrypted.add_argument("--password")
    p_import_encrypted.add_argument("--password-stdin", action="store_true")
    p_import_encrypted.add_argument("--dry-run", action="store_true")
    p_import_encrypted.add_argument("--allow-overwrite", action="store_true")
    p_import_encrypted.add_argument("--allow-empty", action="store_true")
    p_import_encrypted.add_argument("--yes", action="store_true")
    p_import_encrypted.set_defaults(func=cmd_import_encrypted)

    p_export = sub.add_parser("export", parents=[common], help="Export selected secrets for runtime use")
    p_export.add_argument("--format", default="shell", choices=["shell", "dotenv", "encrypted-json"])
    p_export.add_argument("--out")
    p_export.add_argument("--password")
    p_export.add_argument("--password-stdin", action="store_true")
    p_export.add_argument("--names")
    p_export.add_argument("--tag")
    p_export.add_argument("--type", choices=["secret", "pii"])
    p_export.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_export.add_argument("--all", action="store_true")
    p_export.set_defaults(func=cmd_export)

    p_run = sub.add_parser("run", parents=[common], help="Resolve secrets in the parent process and exec a child command")
    p_run.add_argument("--names")
    p_run.add_argument("--tag")
    p_run.add_argument("--type", choices=["secret", "pii"])
    p_run.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_run.add_argument("--all", action="store_true")
    p_run.add_argument("child_command", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cmd_run)

    p_service = sub.add_parser("service", help="Manage service-scoped secret groups")
    service_sub = p_service.add_subparsers(dest="service_command", required=True)
    p_service_copy = service_sub.add_parser("copy", help="Copy secrets from one service scope to another")
    p_service_copy.add_argument("--from-service", required=True)
    p_service_copy.add_argument("--to-service", required=True)
    p_service_copy.add_argument("--from-account")
    p_service_copy.add_argument("--to-account")
    p_service_copy.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_service_copy.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_service_copy.add_argument("--names")
    p_service_copy.add_argument("--tag")
    p_service_copy.add_argument("--type", choices=["secret", "pii"])
    p_service_copy.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_service_copy.add_argument("--overwrite", action="store_true")
    p_service_copy.add_argument("--dry-run", action="store_true")
    p_service_copy.set_defaults(func=cmd_service_copy)

    p_doctor = sub.add_parser("doctor", help="Run backend, defaults, and metadata drift diagnostics")
    p_doctor.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_doctor.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_doctor.set_defaults(func=cmd_doctor)

    p_unlock = sub.add_parser("unlock", help="Unlock the configured macOS keychain backend")
    p_unlock.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_unlock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_unlock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_unlock.add_argument("--harden", action="store_true", help="Also apply a safer keychain timeout policy after unlock")
    p_unlock.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds used with --harden (default: 3600)")
    p_unlock.set_defaults(func=cmd_unlock)

    p_lock = sub.add_parser("lock", help="Lock the configured macOS keychain backend")
    p_lock.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_lock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_lock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_lock.set_defaults(func=cmd_lock)

    p_keychain = sub.add_parser("keychain-status", help="Report macOS keychain accessibility and lock policy")
    p_keychain.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_keychain.set_defaults(func=cmd_keychain_status)

    p_version = sub.add_parser("version", help="Print the installed seckit version")
    p_version.set_defaults(func=cmd_version)

    p_helper = sub.add_parser("helper", help="Inspect the native Keychain helper shipped with the package")
    helper_sub = p_helper.add_subparsers(dest="helper_command", required=True)
    p_helper_status = helper_sub.add_parser(
        "status",
        help="Show resolved helper path, bundled binary, and backend availability",
    )
    p_helper_status.set_defaults(func=cmd_helper_status)

    p_migrate = sub.add_parser("migrate", help="Migrate existing secret files into seckit")
    migrate_sub = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_migrate_dotenv = migrate_sub.add_parser("dotenv", parents=[common], help="Import a dotenv file and optionally rewrite it to placeholders")
    p_migrate_dotenv.add_argument("--dotenv", required=True)
    p_migrate_dotenv.add_argument("--archive")
    p_migrate_dotenv.add_argument("--type", choices=["secret", "pii"])
    p_migrate_dotenv.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_migrate_dotenv.add_argument("--tags")
    p_migrate_dotenv.add_argument("--dry-run", action="store_true")
    p_migrate_dotenv.add_argument("--allow-overwrite", action="store_true")
    p_migrate_dotenv.add_argument("--allow-empty", action="store_true")
    p_migrate_dotenv.add_argument("--yes", action="store_true")
    p_migrate_dotenv.add_argument("--replace-with-placeholders", dest="replace_with_placeholders", action="store_true", default=True)
    p_migrate_dotenv.add_argument("--no-replace-with-placeholders", dest="replace_with_placeholders", action="store_false")
    p_migrate_dotenv.set_defaults(func=cmd_migrate_dotenv)

    p_migrate_metadata = migrate_sub.add_parser("metadata", parents=[common], help="Write registry metadata into keychain comment JSON")
    p_migrate_metadata.add_argument("--dry-run", action="store_true")
    p_migrate_metadata.add_argument("--force", action="store_true")
    p_migrate_metadata.set_defaults(func=cmd_migrate_metadata)

    return parser


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "command", None) != "config":
            _apply_defaults(args=args)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    return args.func(args=args)


if __name__ == "__main__":
    raise SystemExit(main())
