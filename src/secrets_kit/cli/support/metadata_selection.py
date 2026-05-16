"""
secrets_kit.cli.support.metadata_selection

Metadata parsing, domain filters, and entry selection for CLI commands.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from secrets_kit.cli.support.args import _backend_arg, _kek_keychain_arg, _store_path
from secrets_kit.cli.support.interaction import _parse_timestamp
from secrets_kit.models.core import (
    METADATA_SCHEMA_VERSION,
    EntryMetadata,
    ValidationError,
    normalize_custom,
    normalize_domains,
    normalize_tags,
    now_utc_iso,
    validate_entry_kind,
    validate_entry_type,
    validate_key_name,
)
from secrets_kit.registry.core import load_registry
from secrets_kit.registry.resolve import _read_metadata


def _parse_meta_pairs(items: Optional[List[str]]) -> Dict[str, str]:
    """Parse ``--meta key=value`` strings into a flat dictionary.

    Raises ``ValidationError`` on malformed input (missing ``=`` or empty key).
    """
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
    """Merge explicit ``--domain`` flags and ``--domains`` CSV into a normalised list."""
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
    """Load and filter registry entries according to CLI arguments.

    When ``--names`` is given, only those names are resolved. Otherwise
    entries are filtered by ``--service``, ``--account``, ``--tag``,
    ``--type``, ``--kind``, and ``--all``. If ``require_explicit_selection``
    is ``True`` and no filter flags are present, the result is empty.

    Returns a sorted list of ``EntryMetadata`` objects.
    """
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


def _build_metadata(*, args: argparse.Namespace, name: str, source: str) -> EntryMetadata:
    """Construct an ``EntryMetadata`` from CLI arguments, preserving existing timestamps.

    When the entry already exists in the registry, ``created_at`` and
    ``last_rotated_at`` are carried forward. Otherwise fresh timestamps
    are generated. All fields are normalised and validated.
    """
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
    """Evaluate operational status flags for a single entry.

    Checks rotation deadlines (``rotation-overdue``, ``rotation-soon``)
    and expiration (``expired``, ``expires-soon``). Returns an empty list
    when the entry is healthy.
    """
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
