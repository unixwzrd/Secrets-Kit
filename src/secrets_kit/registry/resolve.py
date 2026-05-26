"""
secrets_kit.registry.resolve

Cross-backend metadata resolution (Keychain comment, SQLite, registry projection).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from secrets_kit.backends.common import BackendError, is_keychain_backend
from secrets_kit.backends.keychain import get_secret_metadata, secret_exists
from secrets_kit.backends.keychain.comment_codec import parse_keychain_comment
from secrets_kit.backends.sqlite import get_sqlite_metadata, is_sqlite_backend, sqlite_secret_exists
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.registry.storage import load_registry


def resolve_status(*, metadata: EntryMetadata) -> List[str]:
    """Return lifecycle status tags for one metadata record."""
    now = datetime.now(timezone.utc)
    statuses: List[str] = []

    rotation_days = metadata.rotation_days
    if rotation_days:
        rotated_at = parse_timestamp(
            metadata.last_rotated_at or metadata.updated_at or metadata.created_at
        )
        if rotated_at:
            due_at = rotated_at + timedelta(days=rotation_days)
            warn_days = metadata.rotation_warn_days or 7
            if due_at <= now:
                statuses.append("rotation-overdue")
            elif due_at <= now + timedelta(days=warn_days):
                statuses.append("rotation-soon")

    expires_at = parse_timestamp(metadata.expires_at)
    if expires_at:
        if expires_at <= now:
            statuses.append("expired")
        elif expires_at <= now + timedelta(days=7):
            statuses.append("expires-soon")

    return statuses


def read_metadata(
    *,
    service: str,
    account: str,
    name: str,
    registry: Optional[Dict[str, EntryMetadata]] = None,
    path: Optional[str] = None,
    backend: str = "keychain",
    sqlite_dev_mode: bool = False,
) -> Optional[Dict[str, object]]:
    """Resolve metadata from backend and local registry projection."""
    key = f"{service}::{account}::{name}"
    registry = registry if registry is not None else load_registry()
    registry_meta = registry.get(key)
    if is_sqlite_backend(backend=backend):
        if not sqlite_secret_exists(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        ):
            return None
        sqlite_meta = get_sqlite_metadata(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return {
            "metadata": sqlite_meta,
            "metadata_source": "sqlite",
            "keychain_fields": {},
            "registry_fallback_used": False,
        }
    if secret_exists(service=service, account=account, name=name, path=path, backend=backend):
        keychain_fields: Dict[str, object] = {}
        try:
            keychain_fields = get_secret_metadata(
                service=service, account=account, name=name, path=path, backend=backend
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
                "metadata_source": "keychain-minimal",
                "keychain_fields": {},
                "registry_fallback_used": False,
            }
        keychain_meta = parse_keychain_comment(comment=str(keychain_fields.get("comment", "")))
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
    if registry_meta and path is None and is_keychain_backend(backend):
        return {
            "metadata": registry_meta,
            "metadata_source": "registry-only",
            "keychain_fields": {},
            "registry_fallback_used": True,
        }
    return None


def merge_import_metadata(
    *,
    existing: EntryMetadata,
    incoming: EntryMetadata,
    operator_defaults: Optional[Dict[str, object]] = None,
    backend: str = "keychain",
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> EntryMetadata:
    """Merge import candidate metadata into an existing record using schema registry rules."""
    from secrets_kit.cli.defaults import _load_defaults
    from secrets_kit.metadata.merge import merge_entry_metadata
    from secrets_kit.schemas.registry_store import load_schema_registry
    from secrets_kit.schemas.resolve import resolve_descriptor
    from secrets_kit.schemas.validate import ensure_schema_allowed

    defaults = operator_defaults if operator_defaults is not None else _load_defaults()
    schema_registry = load_schema_registry(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    descriptor = resolve_descriptor(
        registry=schema_registry,
        schema_id=incoming.schema_id or existing.schema_id or None,
        entry_type=incoming.entry_type or existing.entry_type,
        entry_kind=incoming.entry_kind or existing.entry_kind,
    )
    ensure_schema_allowed(registry=schema_registry, schema_id=descriptor.schema_id)
    merged = merge_entry_metadata(
        operator_defaults=defaults,
        descriptor=descriptor,
        base=existing,
        overlay=incoming,
    )
    merged.source = incoming.source
    merged.updated_at = now_utc_iso()
    if existing.created_at:
        merged.created_at = existing.created_at
    return merged


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


__all__ = ["merge_import_metadata", "parse_timestamp", "read_metadata", "resolve_status"]
