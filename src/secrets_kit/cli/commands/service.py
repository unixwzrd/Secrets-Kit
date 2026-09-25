"""
secrets_kit.cli.commands.service

Service command implementations.
"""

from __future__ import annotations

import argparse
import json

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import (
    read_metadata_for_backend,
    read_secret_value,
    secret_exists_for_backend,
    write_secret,
)
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.cli.defaults import _current_os_account
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg, _select_entries
from secrets_kit.models import EntryMetadata, ValidationError, new_entry_id, now_utc_iso


def cmd_service_copy(*, args: argparse.Namespace) -> int:
    try:
        backend = _backend_arg(args)
        keychain_path = _keychain_arg(args)
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
            backend=backend,
        )
        selected = _select_entries(args=selector_args, require_explicit_selection=False)
        if not selected:
            return _fatal(
                message=f"no matching entries selected for service copy: {args.from_service}/{from_account}",
                code=1,
            )

        stats = {"created": 0, "updated": 0, "skipped": 0}
        for source_meta in selected:
            dest_exists = secret_exists_for_backend(
                service=args.to_service,
                account=to_account,
                name=source_meta.name,
                keychain_path=keychain_path,
                backend=backend,
            )
            if dest_exists and not args.overwrite:
                stats["skipped"] += 1
                continue

            value = read_secret_value(
                service=source_meta.service,
                account=source_meta.account,
                name=source_meta.name,
                keychain_path=keychain_path,
                backend=backend,
            )
            dest_meta = EntryMetadata.from_dict(source_meta.to_dict())
            dest_meta.service = args.to_service
            dest_meta.account = to_account
            dest_meta.source = f"copy:{source_meta.service}/{source_meta.account}"
            dest_meta.updated_at = now_utc_iso()
            if not dest_exists:
                dest_meta.created_at = now_utc_iso()
                dest_meta.entry_id = new_entry_id()
            else:
                existing = read_metadata_for_backend(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    backend=backend,
                    keychain_path=keychain_path,
                )
                if existing is not None:
                    dest_meta.created_at = existing.created_at
                    dest_meta.entry_id = existing.entry_id

            if not args.dry_run:
                write_secret(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    value=value,
                    metadata=dest_meta,
                    label=source_meta.name,
                    keychain_path=keychain_path,
                    backend=backend,
                )
            stats["updated" if dest_exists else "created"] += 1

        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, BackendError, SQLiteBackendError) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_service_copy"]
