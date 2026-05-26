"""
secrets_kit.cli.commands.set

Set command implementation.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import write_secret
from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _fatal, _read_value
from secrets_kit.cli.metadata_build import build_metadata
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.models import ValidationError, validate_key_name
from secrets_kit.registry import RegistryError, upsert_metadata


def cmd_set(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value = _read_value(value=args.value, use_stdin=args.stdin, allow_empty=args.allow_empty)
        meta = build_metadata(args=args, name=name, source="manual")
        write_secret(
            service=args.service,
            account=args.account,
            name=name,
            value=value,
            metadata=meta,
            backend=_backend_arg(args),
            keychain_path=_keychain_arg(args),
            sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
            label=name,
        )
        upsert_metadata(metadata=meta)
        print(
            f"stored: name={name} type={meta.entry_type} kind={meta.entry_kind} service={args.service} account={args.account}"
        )
        return 0
    except (ValidationError, RegistryError, BackendError, SQLiteBackendError) as exc:
        return _fatal(message=str(exc))


__all__ = ["cmd_set"]
