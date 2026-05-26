"""
secrets_kit.cli.commands.delete

Delete command implementation.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import delete_secret_entry
from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _confirm, _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.locale import msg
from secrets_kit.models import EntryMetadata, ValidationError, validate_key_name
from secrets_kit.registry import RegistryError, delete_metadata


def cmd_delete(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        if not args.yes and not _confirm(
            prompt=msg(
                "prompts.delete_secret", name=name, service=args.service, account=args.account
            )
        ):
            print(msg("cli.common.aborted"))
            return 1
        meta = EntryMetadata(name=name, service=args.service, account=args.account, source="delete")
        delete_secret_entry(
            service=args.service,
            account=args.account,
            name=name,
            metadata=meta,
            backend=_backend_arg(args),
            keychain_path=_keychain_arg(args),
            sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
        )
        delete_metadata(service=args.service, account=args.account, name=name)
        print(f"deleted: name={name} service={args.service} account={args.account}")
        return 0
    except (ValidationError, BackendError, RegistryError, SQLiteBackendError) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_delete"]
