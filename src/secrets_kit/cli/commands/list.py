"""
secrets_kit.cli.commands.list

List command implementation.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import List

from secrets_kit.backends.sqlite import (
    SQLiteBackendError,
    is_sqlite_backend,
    list_active_sqlite_metadata,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.cli.tables import _format_tags, _print_table
from secrets_kit.models import EntryMetadata
from secrets_kit.registry import RegistryError, load_registry
from secrets_kit.registry.resolve import parse_timestamp, read_metadata, resolve_status


def cmd_list(*, args: argparse.Namespace) -> int:
    cutoff = None
    if args.stale is not None:
        cutoff = datetime.now(timezone.utc).timestamp() - (args.stale * 86400)
    if is_sqlite_backend(backend=_backend_arg(args)):
        try:
            sqlite_entries = list_active_sqlite_metadata(
                service=args.service,
                account=args.account,
                sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
            )
        except SQLiteBackendError as exc:
            return _fatal(message=str(exc), code=1)
        rows = []
        for meta in sqlite_entries:
            if args.type and meta.entry_type != args.type:
                continue
            if args.kind and meta.entry_kind != args.kind:
                continue
            if args.tag and args.tag not in meta.tags:
                continue
            if cutoff is not None:
                updated = parse_timestamp(meta.updated_at)
                if not updated:
                    continue
                if updated.timestamp() > cutoff:
                    continue
            rows.append((meta, {"metadata_source": "sqlite", "registry_fallback_used": False}))
        return _print_list_rows(rows=rows, output_format=args.format)

    try:
        entries = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)

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
        resolved = read_metadata(
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
            updated = parse_timestamp(meta.updated_at)
            if not updated:
                continue
            if updated.timestamp() > cutoff:
                continue
        rows.append((meta, resolved))

    rows.sort(key=lambda item: (item[0].service, item[0].account, item[0].name))

    return _print_list_rows(rows=rows, output_format=args.format)


def _print_list_rows(
    *, rows: list[tuple[EntryMetadata, dict[str, object]]], output_format: str
) -> int:
    if output_format == "json":
        output = []
        for item, resolved in rows:
            payload = item.to_dict()
            payload["status"] = resolve_status(metadata=item)
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
    for item, _resolved in rows:
        table_rows.append(
            [
                item.name,
                item.entry_type,
                item.entry_kind,
                item.service,
                item.account,
                _format_tags(tags=item.tags),
                ",".join(resolve_status(metadata=item) or ["ok"]),
                item.updated_at,
            ]
        )
    _print_table(headers=headers, rows=table_rows)
    return 0


__all__ = ["cmd_list"]
