"""
secrets_kit.cli.commands.get

Get command implementation.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import read_secret_entry
from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _fatal, _write_raw_secret
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.models import EntryMetadata, ValidationError, validate_key_name
from secrets_kit.registry import RegistryError


def cmd_get(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value, metadata = read_secret_entry(
            service=args.service,
            account=args.account,
            name=name,
            backend=_backend_arg(args),
            keychain_path=_keychain_arg(args),
            sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
        )
        if args.raw:
            _write_raw_secret(value)
        else:
            kind = metadata.entry_kind if isinstance(metadata, EntryMetadata) else "unknown"
            entry_type = metadata.entry_type if isinstance(metadata, EntryMetadata) else "unknown"
            print(
                f"name={name} type={entry_type} kind={kind} "
                f"service={args.service} account={args.account} value=<redacted>"
            )
        return 0
    except (ValidationError, BackendError, RegistryError, SQLiteBackendError) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_get"]
