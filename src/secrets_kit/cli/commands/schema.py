"""
secrets_kit.cli.commands.schema

Schema registry CLI commands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secrets_kit.backends.common import BACKEND_KEYCHAIN, normalize_backend
from secrets_kit.backends.dispatch import read_secret_entry, write_secret
from secrets_kit.cli.defaults import _load_defaults
from secrets_kit.cli.io import _confirm, _fatal
from secrets_kit.models import ValidationError, now_utc_iso
from secrets_kit.schemas.constants import SECKIT_UNDEFINED
from secrets_kit.schemas.export import export_descriptor_bytes, export_registry_text
from secrets_kit.schemas.merge import remove_field_from_descriptor
from secrets_kit.schemas.references import (
    find_field_references,
    find_schema_id_references,
    format_field_reference_error,
)
from secrets_kit.schemas.registry_doc import DeprecatedEntry
from secrets_kit.schemas.registry_store import (
    load_schema_registry,
    merge_seed_files_into_store,
    save_schema_registry,
)
from secrets_kit.schemas.validate import ensure_schema_allowed


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


def cmd_schema_list(*, args: argparse.Namespace) -> int:
    try:
        registry = load_schema_registry(**_registry_store_kwargs(args))
        rows = []
        for schema_id in sorted(registry.schemas.keys()):
            if not args.all and registry.is_deprecated(schema_id):
                continue
            desc = registry.schemas[schema_id]
            rows.append(
                {
                    "schema_id": schema_id,
                    "schema_version": desc.schema_version,
                    "entry_type": desc.entry_type,
                    "entry_kind": desc.entry_kind,
                    "deprecated": registry.is_deprecated(schema_id),
                }
            )
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
            return 0
        for row in rows:
            dep = " (deprecated)" if row["deprecated"] else ""
            print(
                f"{row['schema_id']}\t{row['entry_type']}/{row['entry_kind']}\tv{row['schema_version']}{dep}"
            )
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_show(*, args: argparse.Namespace) -> int:
    try:
        registry = load_schema_registry(**_registry_store_kwargs(args))
        descriptor = registry.get_descriptor(args.schema_id)
        if descriptor is None:
            return _fatal(message=f"unknown schema_id: {args.schema_id}", code=1)
        text = export_descriptor_bytes(descriptor=descriptor.to_dict()).decode("utf-8")
        if args.json:
            print(text)
        else:
            print(text)
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_export(*, args: argparse.Namespace) -> int:
    try:
        registry = load_schema_registry(**_registry_store_kwargs(args))
        if args.schema_id:
            descriptor = registry.get_descriptor(args.schema_id)
            if descriptor is None:
                return _fatal(message=f"unknown schema_id: {args.schema_id}", code=1)
            content = export_descriptor_bytes(descriptor=descriptor.to_dict())
        else:
            content = export_registry_text(document=registry.to_dict()).encode("utf-8")
        if args.output:
            Path(args.output).write_bytes(content)
        else:
            sys.stdout.write(content.decode("utf-8"))
            if not content.endswith(b"\n"):
                sys.stdout.write("\n")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_install(*, args: argparse.Namespace) -> int:
    try:
        backend = _backend(args)
        if args.replace and not args.yes:
            if not _confirm(prompt="Overwrite colliding field definitions in the schema registry?"):
                print("aborted")
                return 1
        store = _registry_store_kwargs(args)
        merge_seed_files_into_store(
            backend=store["backend"],
            paths=[Path(item) for item in args.paths],
            allow_replace=args.replace,
            keychain_path=store["keychain_path"],
            sqlite_dev_mode=store["sqlite_dev_mode"],
        )
        print(f"schema registry updated ({backend})")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_field_remove(*, args: argparse.Namespace) -> int:
    try:
        store = _registry_store_kwargs(args)
        backend = store["backend"]
        registry = load_schema_registry(**store)
        ensure_schema_allowed(registry=registry, schema_id=args.schema_id)
        references = find_field_references(
            schema_id=args.schema_id,
            field_name=args.field_name,
            backend=backend,
            keychain_path=store["keychain_path"],
            sqlite_dev_mode=store["sqlite_dev_mode"],
        )
        if references and not args.force:
            return _fatal(
                message=format_field_reference_error(
                    schema_id=args.schema_id,
                    field_name=args.field_name,
                    references=references,
                ),
                code=1,
            )
        if references and args.force and not args.yes:
            if not _confirm(
                prompt=(
                    f"Set {len(references)} secret(s) custom[{args.field_name!r}] to {SECKIT_UNDEFINED!r} "
                    f"and remove field from schema?"
                )
            ):
                print("aborted")
                return 1
            for ref in references:
                _value, meta = read_secret_entry(
                    service=ref.service,
                    account=ref.account,
                    name=ref.name,
                    backend=backend,
                    keychain_path=store["keychain_path"],
                    sqlite_dev_mode=store["sqlite_dev_mode"],
                )
                meta.custom[args.field_name] = SECKIT_UNDEFINED
                meta.updated_at = now_utc_iso()
                write_secret(
                    service=ref.service,
                    account=ref.account,
                    name=ref.name,
                    value=_value,
                    metadata=meta,
                    backend=backend,
                    keychain_path=store["keychain_path"],
                    sqlite_dev_mode=store["sqlite_dev_mode"],
                )
        registry = remove_field_from_descriptor(
            registry=registry,
            schema_id=args.schema_id,
            field_name=args.field_name,
        )
        save_schema_registry(registry=registry, **store)
        print(f"removed field {args.field_name!r} from {args.schema_id}")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_deprecate(*, args: argparse.Namespace) -> int:
    try:
        store = _registry_store_kwargs(args)
        registry = load_schema_registry(**store)
        if args.schema_id not in registry.schemas:
            return _fatal(message=f"unknown schema_id: {args.schema_id}", code=1)
        registry.deprecated[args.schema_id] = DeprecatedEntry(
            deprecated_at=now_utc_iso(),
            reason=args.reason,
            replacement_schema_id=args.replacement or "",
        )
        registry.bump_descriptor(args.schema_id)
        save_schema_registry(registry=registry, **store)
        print(f"deprecated schema {args.schema_id}")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_schema_remove(*, args: argparse.Namespace) -> int:
    try:
        store = _registry_store_kwargs(args)
        backend = store["backend"]
        registry = load_schema_registry(**store)
        users = find_schema_id_references(
            schema_id=args.schema_id,
            backend=backend,
            keychain_path=store["keychain_path"],
            sqlite_dev_mode=store["sqlite_dev_mode"],
        )
        if users and not args.force:
            lines = [
                f"ERROR: cannot remove schema {args.schema_id!r}: {len(users)} secret(s) still use it",
                "",
            ]
            for meta in users:
                lines.append(f"  {meta.service}::{meta.account}::{meta.name}")
            return _fatal(message="\n".join(lines), code=1)
        if users and args.force and not args.yes:
            if not _confirm(
                prompt=f"Remove schema {args.schema_id} while {len(users)} secret(s) still reference it?"
            ):
                print("aborted")
                return 1
        registry.schemas.pop(args.schema_id, None)
        registry.deprecated.pop(args.schema_id, None)
        save_schema_registry(registry=registry, **store)
        print(f"removed schema {args.schema_id}")
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)


__all__ = [
    "cmd_schema_deprecate",
    "cmd_schema_export",
    "cmd_schema_field_remove",
    "cmd_schema_install",
    "cmd_schema_list",
    "cmd_schema_remove",
    "cmd_schema_show",
]
