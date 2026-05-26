"""
secrets_kit.cli.metadata_build

Argparse-driven metadata construction for CLI commands.
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from secrets_kit.backends.common import BACKEND_KEYCHAIN
from secrets_kit.cli.defaults import _load_defaults
from secrets_kit.cli.selection import _keychain_arg
from secrets_kit.cli.taxonomy_prompt import resolve_name_for_cli
from secrets_kit.metadata.merge import merge_entry_metadata
from secrets_kit.models import (
    EntryMetadata,
    ValidationError,
    normalize_custom,
    normalize_domains,
    normalize_tags,
    now_utc_iso,
)
from secrets_kit.registry.resolve import read_metadata
from secrets_kit.registry.storage import load_registry
from secrets_kit.schemas.registry_store import load_schema_registry
from secrets_kit.schemas.resolve import resolve_descriptor
from secrets_kit.schemas.validate import ensure_schema_allowed
from secrets_kit.taxonomy.register import sync_vocabulary_on_write


def parse_meta_pairs(items: Optional[List[str]]) -> Dict[str, str]:
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


def resolve_domains_from_args(
    *, domain: Optional[List[str]], domains_csv: Optional[str]
) -> List[str]:
    items: List[str] = []
    if domains_csv:
        items.extend(domains_csv.split(","))
    if domain:
        items.extend(domain)
    return normalize_domains(items)


def build_metadata(*, args: argparse.Namespace, name: str, source: str) -> EntryMetadata:
    """Build EntryMetadata from CLI args, defaults, schema registry, and existing entry."""
    registry = load_registry()
    backend = getattr(args, "backend", None) or str(
        _load_defaults().get("backend", BACKEND_KEYCHAIN)
    )
    if sys.platform != "darwin" and backend == BACKEND_KEYCHAIN:
        backend = "sqlite"

    existing = read_metadata(
        service=args.service,
        account=args.account,
        name=name,
        registry=registry,
        path=getattr(args, "keychain", None),
        backend=backend,
        sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
    )
    base = existing["metadata"] if existing else None

    raw_type = str(getattr(args, "type", None) or _load_defaults().get("type", "secret"))
    raw_kind = str(getattr(args, "kind", None) or _load_defaults().get("kind", "generic"))
    sqlite_dev = bool(getattr(args, "sqlite_dev_mode", False))
    entry_type = resolve_name_for_cli(
        label="entry_type", raw=raw_type, args=args, sqlite_dev_mode=sqlite_dev
    )
    entry_kind = resolve_name_for_cli(
        label="entry_kind", raw=raw_kind, args=args, sqlite_dev_mode=sqlite_dev
    )
    schema_id = getattr(args, "schema_id", None) or (base.schema_id if base else "")

    keychain_path = _keychain_arg(args)
    schema_registry = load_schema_registry(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
    )
    descriptor = resolve_descriptor(
        registry=schema_registry,
        schema_id=schema_id or None,
        entry_type=entry_type,
        entry_kind=entry_kind,
    )
    ensure_schema_allowed(registry=schema_registry, schema_id=descriptor.schema_id)

    raw_tags = normalize_tags(tags_csv=getattr(args, "tags", None))
    resolved_tags: list[str] = []
    for tag in raw_tags:
        resolved_tags.append(
            resolve_name_for_cli(label="tag", raw=tag, args=args, sqlite_dev_mode=sqlite_dev)
        )
    vocab = sync_vocabulary_on_write(
        entry_type=entry_type,
        entry_kind=entry_kind,
        tags=resolved_tags,
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev,
    )

    overlay = EntryMetadata(
        name=name,
        entry_type=vocab.entry_type,  # type: ignore[arg-type]
        entry_kind=vocab.entry_kind,  # type: ignore[arg-type]
        tags=vocab.tags,
        comment=getattr(args, "comment", "") or "",
        service=args.service,
        account=args.account,
        source=source,
        schema_id=descriptor.schema_id,
        schema_version=descriptor.schema_version,
        source_url=getattr(args, "source_url", "") or "",
        source_label=getattr(args, "source_label", "") or "",
        rotation_days=getattr(args, "rotation_days", None),
        rotation_warn_days=getattr(args, "rotation_warn_days", None),
        expires_at=getattr(args, "expires_at", "") or "",
        domains=resolve_domains_from_args(
            domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None)
        ),
        custom=normalize_custom(parse_meta_pairs(getattr(args, "meta", None))),
        updated_at=now_utc_iso(),
    )

    merged = merge_entry_metadata(
        operator_defaults=_load_defaults(),
        descriptor=descriptor,
        base=base,
        overlay=overlay,
    )
    if base is not None and base.created_at:
        merged.created_at = base.created_at
    return merged


__all__ = ["build_metadata", "parse_meta_pairs", "resolve_domains_from_args"]
