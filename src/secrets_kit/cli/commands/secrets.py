"""Core secret CRUD, list, explain, and run."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import List

from secrets_kit.backends.security import BackendError, delete_secret, get_secret, set_secret
from secrets_kit.models.core import EntryMetadata, ValidationError, validate_key_name
from secrets_kit.registry.core import RegistryError, delete_metadata, load_registry, upsert_metadata
from secrets_kit.registry.resolve import _read_metadata

from secrets_kit.cli.support.args import _backend_access_kwargs, _backend_arg, _kek_keychain_arg, _store_path
from secrets_kit.cli.support.env_exec import _build_env_map, _child_command_args, _exec_child
from secrets_kit.cli.support.interaction import _confirm, _fatal, _format_tags, _parse_timestamp, _print_table, _read_value
from secrets_kit.cli.support.metadata_selection import _build_metadata, _resolve_status, _select_entries


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
