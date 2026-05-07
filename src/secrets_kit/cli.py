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
from typing import Any, Dict, Iterable, List, Optional

from secrets_kit.native_helper import helper_status
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
    is_sqlite_backend,
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
from secrets_kit.recover_sources import iter_recover_candidates
from secrets_kit.sqlite_backend import default_sqlite_db_path
from secrets_kit.models import (
    ENTRY_KIND_VALUES,
    METADATA_SCHEMA_VERSION,
    EntryMetadata,
    ValidationError,
    infer_entry_kind_from_name,
    make_registry_key,
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
        "sqlite_db",
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
    migrate_legacy_operator_backend_in_file,
    registry_dir,
    save_defaults,
    upsert_metadata,
)
from secrets_kit.identity import (
    IdentityError,
    export_public_identity,
    identity_dir,
    identity_secret_path,
    init_identity,
    load_identity,
)
from secrets_kit.peers import add_peer_from_file, get_peer, list_peers, remove_peer
from secrets_kit.sync_bundle import (
    SyncBundleError,
    build_bundle,
    decrypt_bundle_for_recipient,
    inspect_bundle,
    parse_bundle_file,
    verify_bundle_structure,
)
from secrets_kit.sync_merge import apply_peer_sync_import, effective_origin_host
from secrets_kit.cli_parser import build_parser


def _fatal(*, message: str, code: int = 2) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return code


def _peer_sync_cli_error(exc: BaseException) -> str:
    """User-facing hints for peer sync / bundle workflows (no secret values)."""
    if isinstance(exc, IdentityError):
        return "Peer sync: no host identity. Run: seckit identity init"
    if isinstance(exc, RegistryError):
        text = str(exc)
        if "unknown peer" in text.lower():
            return f"Peer sync: {text}. Run: seckit peer add <alias> <export.json>"
        return f"Peer sync: {text}"
    if isinstance(exc, SyncBundleError):
        msg = str(exc)
        if "missing wrapped_cek slot" in msg:
            return (
                "Peer sync: this bundle was not encrypted for this host (no wrapped CEK for your signing fingerprint). "
                "Ask the sender to run `seckit sync export` with `--peer` listing your machine's peer alias. "
                f"Detail: {msg}"
            )
        if "does not match trusted peer" in msg:
            return (
                "Peer sync: bundle signing key does not match `seckit peer show` for `--signer`. "
                "Fix the alias or re-add the sender from a fresh `seckit identity export`. "
                f"Detail: {msg}"
            )
        if msg == "invalid signature":
            return (
                "Peer sync: bundle signature invalid (tampered file, truncated transfer, or wrong document). "
                f"Detail: {msg}"
            )
        if (
            "not valid JSON" in msg
            or "top-level must be an object" in msg
            or "unsupported bundle format" in msg
            or "unsupported bundle version" in msg
            or "missing bundle field" in msg
        ):
            return f"Peer sync: file is not a valid peer bundle. Detail: {msg}"
        return f"Peer sync: bundle error. Detail: {msg}"
    if isinstance(exc, BackendError):
        return (
            f"Peer sync: secret backend error — {exc} "
            "(for SQLite: check --backend sqlite, --db, SECKIT_SQLITE_PASSPHRASE, SECKIT_SQLITE_UNLOCK)."
        )
    return str(exc)


def _cli_version() -> str:
    try:
        return package_version("seckit")
    except PackageNotFoundError:
        return "0.1.0"


def _version_info_dict() -> Dict[str, object]:
    """Build a JSON-safe dict for `seckit version --json` / `--info` (no secret values)."""
    status = helper_status()
    info: Dict[str, object] = {
        "version": _cli_version(),
        "platform": sys.platform,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "backend_availability": status["backend_availability"],
        "helper": status["helper"],
    }
    try:
        ensure_defaults_storage()
        dpath = defaults_path()
        info["defaults_path"] = str(dpath)
        merged = _load_defaults()
        safe = {k: merged[k] for k in _CONFIG_STORABLE_KEYS if k in merged}
        info["defaults"] = {str(k): safe[k] for k in sorted(safe.keys(), key=str)}
    except (RegistryError, OSError, TypeError, ValueError):
        info["defaults_path"] = None
        info["defaults"] = {}
    return info


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
    legacy_path = registry_dir() / "config.json"
    if legacy_path.exists():
        try:
            payload = json.loads(legacy_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"invalid config json: {legacy_path} ({exc})") from exc
        if not isinstance(payload, dict):
            raise ValidationError(f"invalid config json: {legacy_path} (top-level must be object)")
        payload = migrate_legacy_operator_backend_in_file(path=legacy_path, payload=payload)
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


def _store_path(args: argparse.Namespace) -> Optional[str]:
    """Backend store path: keychain file (secure) or SQLite database path (sqlite)."""
    backend = _backend_arg(args)
    if is_sqlite_backend(backend):
        db = getattr(args, "db", None)
        if db:
            return os.path.expanduser(str(db))
        env_db = os.environ.get("SECKIT_SQLITE_DB", "").strip()
        if env_db:
            return os.path.expanduser(env_db)
        return default_sqlite_db_path()
    return _keychain_arg(args)


def _kek_keychain_arg(args: argparse.Namespace) -> Optional[str]:
    """When ``backend`` is sqlite, optional keychain file holding the SQLite KEK (not the DB path)."""
    if not is_sqlite_backend(_backend_arg(args)):
        return None
    k = _keychain_arg(args)
    return os.path.expanduser(str(k)) if k else None


def _backend_access_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "path": _store_path(args),
        "backend": _backend_arg(args),
        "kek_keychain_path": _kek_keychain_arg(args),
    }


def _doctor_skip_missing_secret_scan(args: argparse.Namespace) -> bool:
    """Match doctor drift rules: skip when custom keychain or explicit --db is set."""
    backend = _backend_arg(args)
    if is_secure_backend(backend) and _keychain_arg(args) is not None:
        return True
    if is_sqlite_backend(backend) and getattr(args, "db", None):
        return True
    return False


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


def _entries_match_domain_filter(*, entries: List[EntryMetadata], domains: List[str]) -> List[EntryMetadata]:
    """Keep entries whose ``domains`` overlap the filter (any exact match)."""
    if not domains:
        return entries
    dset = set(normalize_domains(domains))
    out: List[EntryMetadata] = []
    for meta in entries:
        if dset & set(normalize_domains(meta.domains)):
            out.append(meta)
    return out


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
                path=_store_path(args),
                backend=_backend_arg(args),
                kek_keychain_path=_kek_keychain_arg(args),
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
        if require_explicit_selection and not explicit_filter:
            continue
        resolved = _read_metadata(
            service=indexed.service,
            account=indexed.account,
            name=indexed.name,
            registry=entries,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        if not resolved:
            continue
        meta = resolved["metadata"]
        if not isinstance(meta, EntryMetadata):
            continue
        if getattr(args, "type", None) and meta.entry_type != args.type:
            continue
        if getattr(args, "kind", None) and meta.entry_kind != args.kind:
            continue
        if getattr(args, "tag", None) and args.tag not in meta.tags:
            continue
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
                **_backend_access_kwargs(args),
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
        path=_store_path(args),
        backend=_backend_arg(args),
        kek_keychain_path=_kek_keychain_arg(args),
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
    kek_keychain_path: Optional[str] = None,
) -> Optional[Dict[str, object]]:
    key = f"{service}::{account}::{name}"
    registry = registry if registry is not None else load_registry()
    registry_meta = registry.get(key)
    if secret_exists(
        service=service,
        account=account,
        name=name,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    ):
        res_store = None
        try:
            from secrets_kit.backend_store import resolve_backend_store

            store = resolve_backend_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
            resolved = store.resolve_by_locator(service=service, account=account, name=name)
            if resolved is not None:
                res_store = resolved
        except (BackendError, OSError, ValueError, TypeError):
            res_store = None
        if res_store is not None:
            keychain_fields: Dict[str, object] = {}
            try:
                keychain_fields = get_secret_metadata(
                    service=service,
                    account=account,
                    name=name,
                    path=path,
                    backend=backend,
                    kek_keychain_path=kek_keychain_path,
                )
            except BackendError:
                pass
            return {
                "metadata": res_store.metadata,
                "metadata_source": "sqlite" if is_sqlite_backend(backend) else "keychain",
                "keychain_fields": keychain_fields,
                "registry_fallback_used": False,
            }
        keychain_fields = {}
        try:
            keychain_fields = get_secret_metadata(
                service=service,
                account=account,
                name=name,
                path=path,
                backend=backend,
                kek_keychain_path=kek_keychain_path,
            )
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
                "metadata_source": "sqlite-minimal" if is_sqlite_backend(backend) else "keychain-minimal",
                "keychain_fields": {},
                "registry_fallback_used": False,
            }
        keychain_meta = EntryMetadata.from_keychain_comment(str(keychain_fields.get("comment", "")))
        if keychain_meta:
            return {
                "metadata": keychain_meta,
                "metadata_source": "sqlite" if is_sqlite_backend(backend) else "keychain",
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
            "metadata_source": "sqlite-minimal" if is_sqlite_backend(backend) else "keychain-minimal",
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
    if registry_meta and is_sqlite_backend(backend):
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
    kek_keychain_path: Optional[str] = None,
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
            kek_keychain_path=kek_keychain_path,
        )
        exists = resolved is not None and secret_exists(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
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
                    kek_keychain_path=kek_keychain_path,
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
            kek_keychain_path=kek_keychain_path,
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
            **_backend_access_kwargs(args),
        )
        upsert_metadata(metadata=meta)
        print(f"stored: name={name} type={meta.entry_type} kind={meta.entry_kind} service={args.service} account={args.account}")
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc))


def cmd_get(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value = get_secret(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
        resolved = _read_metadata(
            service=args.service,
            account=args.account,
            name=name,
            **_backend_access_kwargs(args),
        )
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
    for indexed in entries.values():
        if args.service and indexed.service != args.service:
            continue
        if args.account and indexed.account != args.account:
            continue
        resolved = _read_metadata(
            service=indexed.service,
            account=indexed.account,
            name=indexed.name,
            registry=entries,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        if not resolved:
            continue
        meta = resolved["metadata"]
        if not isinstance(meta, EntryMetadata):
            continue
        if args.type and meta.entry_type != args.type:
            continue
        if args.kind and meta.entry_kind != args.kind:
            continue
        if args.tag and args.tag not in meta.tags:
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
        delete_secret(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
        delete_metadata(service=args.service, account=args.account, name=name)
        print(f"deleted: name={name} service={args.service} account={args.account}")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_explain(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        resolved = _read_metadata(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
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
    headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "SOURCE", "VALUE"]
    table_rows: List[List[str]] = []
    for key in sorted(merged):
        candidate = merged[key]
        meta = candidate.metadata
        table_rows.append(
            [
                meta.name,
                meta.entry_type,
                meta.entry_kind,
                meta.service,
                meta.account,
                _format_tags(tags=meta.tags),
                meta.source,
                "<redacted>",
            ]
        )
    _print_table(headers=headers, rows=table_rows)


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
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
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
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
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
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
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
                            **_backend_access_kwargs(args),
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


def cmd_identity_init(*, args: argparse.Namespace) -> int:
    try:
        ident = init_identity(force=args.force)
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {"host_id": ident.host_id, "secret_path": str(identity_secret_path())},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print("Host identity initialized.")
            print(f"host_id: {ident.host_id}")
            print(f"secret: {identity_secret_path()}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_identity_show(*, args: argparse.Namespace) -> int:
    try:
        ident = load_identity()
        payload = {
            "box_public_hex": bytes(ident.box_public).hex(),
            "host_id": ident.host_id,
            "identity_dir": str(identity_dir()),
            "signing_fingerprint": ident.signing_fingerprint_hex(),
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"host_id: {payload['host_id']}")
            print(f"signing_fingerprint: {payload['signing_fingerprint']}")
            print(f"box_public_hex: {payload['box_public_hex']}")
            print(f"identity_dir: {payload['identity_dir']}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_identity_export(*, args: argparse.Namespace) -> int:
    try:
        out = Path(args.out).expanduser() if getattr(args, "out", None) else None
        pub = export_public_identity(out=out)
        if getattr(args, "json", False) or out is None:
            print(json.dumps(pub, indent=2, sort_keys=True))
        else:
            print(f"wrote {out}")
        return 0
    except IdentityError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_peer_add(*, args: argparse.Namespace) -> int:
    try:
        rec = add_peer_from_file(alias=args.alias, path=Path(args.export_path).expanduser())
        payload = {
            "alias": rec.alias,
            "fingerprint": rec.fingerprint,
            "host_id": rec.host_id,
            "trusted_at": rec.trusted_at,
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"added peer {rec.alias} host_id={rec.host_id} fingerprint={rec.fingerprint[:16]}…")
        return 0
    except IdentityError as exc:
        return _fatal(message=f"Peer registry: invalid peer identity export file — {exc}", code=1)
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_peer_remove(*, args: argparse.Namespace) -> int:
    try:
        ok = remove_peer(alias=args.alias)
        if not ok:
            return _fatal(message=f"no peer named {args.alias!r}", code=1)
        if getattr(args, "json", False):
            print(json.dumps({"removed": args.alias}, indent=2, sort_keys=True))
        else:
            print(f"removed peer {args.alias}")
        return 0
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_peer_list(*, args: argparse.Namespace) -> int:
    try:
        rows = list_peers()
        if getattr(args, "json", False):
            payload = [
                {
                    "alias": p.alias,
                    "fingerprint": p.fingerprint,
                    "host_id": p.host_id,
                    "trusted_at": p.trusted_at,
                }
                for p in rows
            ]
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if not rows:
            print("no peers")
            return 0
        _print_table(
            headers=["alias", "fingerprint", "host_id", "trusted_at"],
            rows=[
                [p.alias, p.fingerprint[:16] + "…", p.host_id, p.trusted_at]
                for p in rows
            ],
        )
        return 0
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_peer_show(*, args: argparse.Namespace) -> int:
    try:
        p = get_peer(alias=args.alias)
        payload = {
            "alias": p.alias,
            "box_public": p.box_public_b64,
            "fingerprint": p.fingerprint,
            "host_id": p.host_id,
            "signing_public": p.signing_public_b64,
            "trusted_at": p.trusted_at,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_export(*, args: argparse.Namespace) -> int:
    try:
        ident = load_identity()
        selected = _select_entries(args=args, require_explicit_selection=True)
        dfilter = _resolve_domains(domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None))
        selected = _entries_match_domain_filter(entries=selected, domains=dfilter)
        if not selected:
            return _fatal(message="no matching entries selected for sync export", code=1)
        recipients = [(get_peer(alias=a).fingerprint, get_peer(alias=a).box_public()) for a in args.peer]
        entries: List[Dict[str, object]] = []
        for meta in sorted(selected, key=lambda item: item.name):
            value = get_secret(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                **_backend_access_kwargs(args),
            )
            oh = effective_origin_host(meta=meta, default_host_id=ident.host_id)
            entries.append({"metadata": meta.to_dict(), "origin_host": oh, "value": value})
        bundle = build_bundle(
            identity=ident,
            recipient_records=recipients,
            entries=entries,
            domain_filter=dfilter or None,
        )
        out_path = Path(args.out).expanduser()
        out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary = {
            "domain_filter": dfilter,
            "entry_count": len(entries),
            "out": str(out_path),
            "peers": list(args.peer),
            "signer_fingerprint": ident.signing_fingerprint_hex(),
        }
        if getattr(args, "json", False):
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    except (BackendError, IdentityError, RegistryError, SyncBundleError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_import(*, args: argparse.Namespace) -> int:
    try:
        ident = load_identity()
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        signer = get_peer(alias=args.signer)
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=ident,
            trusted_signer=signer.verify_key(),
        )
        raw_entries = inner.get("entries", [])
        if not isinstance(raw_entries, list):
            return _fatal(message="bundle inner entries must be an array", code=1)
        dfilter = _resolve_domains(domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None))
        conv_entries = [e for e in raw_entries if isinstance(e, dict)]
        if len(conv_entries) != len(raw_entries):
            return _fatal(message="bundle inner entries must be objects", code=1)
        if not args.dry_run and not args.yes and not _confirm(
            prompt=f"Import {len(conv_entries)} entries from peer bundle (merge rules apply)?",
        ):
            print("aborted")
            return 1
        stats = apply_peer_sync_import(
            inner_entries=conv_entries,
            local_host_id=ident.host_id,
            dry_run=args.dry_run,
            **_backend_access_kwargs(args),
            domain_filter=dfilter or None,
        )
        out = dict(stats)
        out["bundle_export_id"] = inner.get("export_id", "")
        out["bundle_origin_host"] = inner.get("origin_host", "")
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    except (BackendError, IdentityError, RegistryError, SyncBundleError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_verify(*, args: argparse.Namespace) -> int:
    try:
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        vr = verify_bundle_structure(payload=payload)
        result: Dict[str, object] = {
            "entry_count": vr.entry_count,
            "message": vr.message,
            "ok": vr.ok,
            "signer_fingerprint": vr.signer_fingerprint,
            "signer_host_id": vr.signer_host_id,
        }
        if getattr(args, "try_decrypt", False):
            ident = load_identity()
            signer_peer = get_peer(alias=args.signer) if getattr(args, "signer", None) else None
            if signer_peer is None:
                result["decrypt_error"] = "sync verify --try-decrypt requires --signer"
            else:
                try:
                    inner = decrypt_bundle_for_recipient(
                        payload=payload,
                        identity=ident,
                        trusted_signer=signer_peer.verify_key(),
                    )
                    entries = inner.get("entries", [])
                    result["decrypt_ok"] = True
                    result["inner_entry_count"] = len(entries) if isinstance(entries, list) else 0
                except SyncBundleError as exc:
                    result["decrypt_ok"] = False
                    result["decrypt_error"] = _peer_sync_cli_error(exc)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if vr.ok else 1
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except (SyncBundleError, IdentityError, RegistryError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_inspect(*, args: argparse.Namespace) -> int:
    try:
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        info = inspect_bundle(payload=payload)
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except SyncBundleError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


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
            db=getattr(args, "db", None),
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
                **_backend_access_kwargs(args),
            )
            if dest_exists and not args.overwrite:
                stats["skipped"] += 1
                continue

            value = get_secret(
                service=source_meta.service,
                account=source_meta.account,
                name=source_meta.name,
                **_backend_access_kwargs(args),
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
                    path=_store_path(args),
                    backend=_backend_arg(args),
                    kek_keychain_path=_kek_keychain_arg(args),
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
                    **_backend_access_kwargs(args),
                )
                upsert_metadata(metadata=dest_meta)
            stats["updated" if dest_exists else "created"] += 1

        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_doctor(*, args: argparse.Namespace) -> int:
    backend = _backend_arg(args)
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
    if is_secure_backend(backend):
        if check_security_cli():
            status["security_cli"] = True
        else:
            print(json.dumps(status, indent=2, sort_keys=True))
            return _fatal(message="security CLI not found", code=1)
    else:
        status["security_cli"] = check_security_cli()

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
        doctor_roundtrip(**_backend_access_kwargs(args))
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
            if not secret_exists(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args)):
                if _doctor_skip_missing_secret_scan(args):
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
                **_backend_access_kwargs(args),
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
        if is_sqlite_backend(backend):
            from secrets_kit.sqlite_backend import SqliteSecretStore

            spath = _store_path(args)
            if spath:
                st = SqliteSecretStore(db_path=spath, kek_keychain_path=_kek_keychain_arg(args))
                status["backend_security_posture"] = asdict(st.security_posture())
                status["backend_capabilities"] = {**asdict(st.capabilities())}
        elif is_secure_backend(backend):
            from secrets_kit.keychain_backend_store import KeychainBackendStore

            st = KeychainBackendStore(path=_keychain_arg(args))
            status["backend_security_posture"] = asdict(st.security_posture())
            status["backend_capabilities"] = {**asdict(st.capabilities())}
    except (RegistryError, BackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"] or status["entries_using_registry_fallback"]:
        return _fatal(message="metadata/keychain drift detected", code=1)
    return 0


def cmd_backend_index(*, args: argparse.Namespace) -> int:
    """Emit decrypt-free :class:`~secrets_kit.backend_store.IndexRow` records, JSON lines."""
    try:
        from secrets_kit.backend_store import resolve_backend_store

        store = resolve_backend_store(
            backend=_backend_arg(args),
            path=_store_path(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        for row in store.iter_index():
            print(json.dumps(row.to_safe_dict(), sort_keys=True))
        return 0
    except (BackendError, ValidationError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_rebuild_index(*, args: argparse.Namespace) -> int:
    """Rebuild decrypt-free index fields from authority (SQLite); Keychain no-op."""
    try:
        from secrets_kit.backend_store import resolve_backend_store

        store = resolve_backend_store(
            backend=_backend_arg(args),
            path=_store_path(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        store.rebuild_index()
        print(json.dumps({"rebuilt": True, "backend": _backend_arg(args)}, indent=2, sort_keys=True))
        return 0
    except (BackendError, ValidationError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_journal_append(*, args: argparse.Namespace) -> int:
    """Append one JSON object to ``registry_events.jsonl``."""
    try:
        from secrets_kit.registry_journal import append_journal_event

        raw = getattr(args, "event_json", "") or ""
        evt = json.loads(raw)
        if not isinstance(evt, dict):
            return _fatal(message="journal event must be a JSON object", code=1)
        path = append_journal_event(home=None, event=evt)
        print(json.dumps({"written": True, "path": str(path)}, sort_keys=True))
        return 0
    except json.JSONDecodeError as exc:
        return _fatal(message=str(exc), code=1)
    except (RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


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
    if getattr(args, "version_json", False):
        print(json.dumps(_version_info_dict(), indent=2, sort_keys=True))
        return 0
    if getattr(args, "version_info", False):
        data = _version_info_dict()
        lines = [
            f"version: {data['version']}",
            f"platform: {data['platform']}",
            f"python: {data['python']}",
        ]
        dp = data.get("defaults_path")
        lines.append(f"defaults_path: {dp if dp else '(unknown)'}")
        defaults = data.get("defaults") or {}
        if defaults:
            lines.append("defaults:")
            for k in sorted(defaults.keys(), key=str):
                lines.append(f"  {k}: {defaults[k]!r}")
        else:
            lines.append("defaults: (none)")
        ba = data.get("backend_availability") or {}
        lines.append(
            "backend_availability: "
            + ", ".join(f"{k}={ba[k]}" for k in sorted(ba.keys(), key=str))
        )
        hb = data.get("helper") or {}
        lines.append(f"helper.installed: {hb.get('installed')}")
        lines.append(f"helper.path: {hb.get('path') or '(none)'}")
        lines.append(f"helper.bundled_path: {hb.get('bundled_path') or '(none)'}")
        print("\n".join(lines))
        return 0
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
        if not secret_exists(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args)):
            stats["missing_keychain"] += 1
            continue
        resolved = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            **_backend_access_kwargs(args),
        )
        if resolved and resolved["metadata_source"] in {"keychain", "sqlite"} and not args.force:
            stats["skipped"] += 1
            continue
        if args.dry_run:
            stats["migrated"] += 1
            continue
        value = get_secret(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args))
        meta.updated_at = now_utc_iso()
        set_secret(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            value=value,
            label=meta.name,
            comment=meta.to_keychain_comment(),
            **_backend_access_kwargs(args),
        )
        verify = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            **_backend_access_kwargs(args),
        )
        if not verify or verify["metadata_source"] not in {"keychain", "sqlite"}:
            return _fatal(message=f"failed to verify migrated metadata for {meta.key()}", code=1)
        upsert_metadata(metadata=meta)
        stats["migrated"] += 1

    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


def cmd_recover_registry(*, args: argparse.Namespace) -> int:
    """Rebuild ``registry.json`` from Keychain dump or SQLite plaintext index."""
    backend = _backend_arg(args)
    if is_secure_backend(backend):
        if not check_security_cli():
            return _fatal(message="security CLI not found", code=1)
    elif not is_sqlite_backend(backend):
        return _fatal(message="recover requires --backend secure or sqlite", code=1)

    filt = getattr(args, "service", None)
    filt = filt.strip() if filt else None
    service_filter = filt or None

    sqlite_db: Optional[str] = None
    if is_sqlite_backend(backend):
        sqlite_db = _store_path(args)
        if not sqlite_db:
            return _fatal(message="SQLite recover requires --db or SECKIT_SQLITE_DB / defaults", code=1)

    try:
        candidate_iter = iter_recover_candidates(
            backend=backend,
            service_filter=service_filter,
            keychain_file=_keychain_arg(args),
            sqlite_db=sqlite_db,
        )
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)

    stats: Dict[str, Any] = {
        "candidates": 0,
        "recovered": 0,
        "skipped_bad_name": 0,
        "skipped_bad_names": [],
        "skipped_duplicate": 0,
        "skipped_duplicate_keys": [],
        "skipped_no_secret": 0,
        "skipped_no_secret_keys": [],
    }
    seen: set[str] = set()
    dry = bool(getattr(args, "dry_run", False))
    json_only = bool(getattr(args, "json", False))
    recovered_metas: List[EntryMetadata] = []
    recovered_rows: List[List[str]] = []

    for cand in candidate_iter:
        stats["candidates"] += 1
        try:
            validate_key_name(name=cand.name)
        except ValidationError as exc:
            stats["skipped_bad_name"] += 1
            stats["skipped_bad_names"].append(
                {
                    "service": cand.service,
                    "account": cand.account,
                    "name": cand.name,
                    "reason": str(exc),
                }
            )
            continue
        rkey = make_registry_key(service=cand.service, account=cand.account, name=cand.name)
        if rkey in seen:
            stats["skipped_duplicate"] += 1
            stats["skipped_duplicate_keys"].append(rkey)
            continue
        if not secret_exists(
            service=cand.service,
            account=cand.account,
            name=cand.name,
            **_backend_access_kwargs(args),
        ):
            stats["skipped_no_secret"] += 1
            stats["skipped_no_secret_keys"].append(rkey)
            continue

        parsed = EntryMetadata.from_keychain_comment(cand.comment)
        if parsed is not None and (
            parsed.name != cand.name
            or parsed.service != cand.service
            or parsed.account != cand.account
        ):
            parsed = None

        if parsed is not None:
            meta = parsed
            meta.updated_at = now_utc_iso()
        else:
            ts = now_utc_iso()
            meta = EntryMetadata(
                name=cand.name,
                service=cand.service,
                account=cand.account,
                entry_kind=infer_entry_kind_from_name(name=cand.name),
                source="recovered-keychain" if is_secure_backend(backend) else "recovered-sqlite",
                created_at=ts,
                updated_at=ts,
            )

        seen.add(rkey)
        recovered_metas.append(meta)
        recovered_rows.append(
            [
                meta.name,
                meta.entry_type,
                meta.entry_kind,
                meta.service,
                meta.account,
                _format_tags(tags=meta.tags),
                "dry-run" if dry else "written",
                meta.updated_at,
            ]
        )
        if dry:
            stats["recovered"] += 1
            continue
        upsert_metadata(metadata=meta)
        stats["recovered"] += 1

    report: Dict[str, Any] = {**stats, "recovered_entries": [m.to_dict() for m in recovered_metas]}
    if json_only:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    if dry and recovered_rows:
        headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "STATUS", "UPDATED_AT"]
        _print_table(headers=headers, rows=recovered_rows)
        print()

    print(json.dumps({k: v for k, v in report.items() if k != "recovered_entries"}, indent=2, sort_keys=True))
    return 0


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "command", None) not in ("config", "defaults"):
            _apply_defaults(args=args)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    return args.func(args=args)


if __name__ == "__main__":
    raise SystemExit(main())
