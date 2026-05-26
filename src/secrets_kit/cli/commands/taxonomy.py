"""
secrets_kit.cli.commands.taxonomy

Taxonomy registry CLI commands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secrets_kit.backends.common import BACKEND_KEYCHAIN, normalize_backend
from secrets_kit.cli.defaults import _load_defaults
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.tables import _print_table
from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.export import export_taxonomy_registry_text
from secrets_kit.taxonomy.registry_doc import TaxonomyEntry, TaxonomyRegistryDocument
from secrets_kit.taxonomy.registry_store import (
    load_taxonomy_registry,
    merge_seed_files_into_taxonomy_store,
)


def _backend(args: argparse.Namespace) -> str:
    raw = getattr(args, "backend", None)
    if raw:
        return normalize_backend(raw)
    return normalize_backend(str(_load_defaults().get("backend", BACKEND_KEYCHAIN)))


def _registry_store_kwargs(args: argparse.Namespace) -> dict:
    return {
        "backend": _backend(args),
        "keychain_path": getattr(args, "keychain", None),
        "sqlite_dev_mode": getattr(args, "sqlite_dev_mode", False),
    }


def _list_sections_from_args(*, args: argparse.Namespace) -> tuple[bool, bool, bool]:
    """Return which vocabulary lists to include (default: all when no filter flags)."""
    types = bool(getattr(args, "types", False))
    kinds = bool(getattr(args, "kinds", False))
    tags = bool(getattr(args, "tags", False))
    if not types and not kinds and not tags:
        return True, True, True
    return types, kinds, tags


def taxonomy_list_rows(
    *,
    registry: TaxonomyRegistryDocument,
    include_types: bool = True,
    include_kinds: bool = True,
    include_tags: bool = True,
) -> list[dict[str, object]]:
    """Build sorted list rows for display or JSON export."""
    rows: list[dict[str, object]] = []

    def _append(*, list_name: str, entries: list[TaxonomyEntry]) -> None:
        for entry in entries:
            rows.append(
                {
                    "list": list_name,
                    "name": entry.name,
                    "id": entry.id,
                    "builtin": entry.builtin,
                    "operator_comment": entry.operator_comment,
                }
            )

    if include_types:
        _append(list_name="entry_type", entries=list(registry.entry_types))
    if include_kinds:
        _append(list_name="entry_kind", entries=list(registry.entry_kinds))
    if include_tags:
        _append(list_name="tag", entries=list(registry.tags))
    return sorted(rows, key=lambda item: (str(item["list"]), str(item["name"])))


def cmd_taxonomy_list(*, args: argparse.Namespace) -> int:
    try:
        registry = load_taxonomy_registry(**_registry_store_kwargs(args))
        include_types, include_kinds, include_tags = _list_sections_from_args(args=args)
        rows = taxonomy_list_rows(
            registry=registry,
            include_types=include_types,
            include_kinds=include_kinds,
            include_tags=include_tags,
        )
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
            return 0
        if not rows:
            print("no vocabulary entries match the selected filters")
            return 0
        table_rows = [
            [
                str(row["list"]),
                str(row["name"]),
                "yes" if row["builtin"] else "no",
                str(row["operator_comment"] or "-"),
            ]
            for row in rows
        ]
        _print_table(
            headers=["list", "name", "builtin", "comment"],
            rows=table_rows,
        )
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_taxonomy_show(*, args: argparse.Namespace) -> int:
    try:
        registry = load_taxonomy_registry(**_registry_store_kwargs(args))
        if args.list_name == "entry_type":
            entries = registry.entry_types
        elif args.list_name == "entry_kind":
            entries = registry.entry_kinds
        elif args.list_name == "tag":
            entries = registry.tags
        else:
            return _fatal(message=f"unknown list: {args.list_name}", code=1)
        match = next((item for item in entries if item.name == args.name), None)
        if match is None:
            return _fatal(message=f"not found: {args.list_name} {args.name!r}", code=1)
        text = json.dumps(match.to_dict(), indent=2, sort_keys=True)
        print(text)
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_taxonomy_export(*, args: argparse.Namespace) -> int:
    try:
        registry = load_taxonomy_registry(**_registry_store_kwargs(args))
        content = export_taxonomy_registry_text(document=registry.to_dict())
        if args.output:
            Path(args.output).write_text(content + "\n", encoding="utf-8")
        else:
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_taxonomy_install(*, args: argparse.Namespace) -> int:
    try:
        store = _registry_store_kwargs(args)
        merge_seed_files_into_taxonomy_store(
            backend=store["backend"],
            paths=[Path(item) for item in args.paths],
            keychain_path=store["keychain_path"],
            sqlite_dev_mode=store["sqlite_dev_mode"],
        )
        print(f"taxonomy registry updated from {len(args.paths)} file(s)")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


__all__ = [
    "cmd_taxonomy_export",
    "cmd_taxonomy_install",
    "cmd_taxonomy_list",
    "cmd_taxonomy_show",
    "taxonomy_list_rows",
]
