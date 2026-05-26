"""
secrets_kit.cli.commands.explain

Explain command implementation.
"""

from __future__ import annotations

import argparse
import json

from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.locale import msg
from secrets_kit.models import EntryMetadata, ValidationError, validate_key_name
from secrets_kit.registry import RegistryError
from secrets_kit.registry.resolve import read_metadata, resolve_status


def cmd_explain(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        resolved = read_metadata(
            service=args.service,
            account=args.account,
            name=name,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
            sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
        )
        if not resolved:
            return _fatal(
                message=msg(
                    "errors.entry_not_found", service=args.service, account=args.account, name=name
                ),
                code=1,
            )
        entry = resolved["metadata"]
        if not isinstance(entry, EntryMetadata):
            return _fatal(message=msg("errors.metadata_decode_failed"), code=1)
        payload = entry.to_dict()
        payload["status"] = resolve_status(metadata=entry)
        payload["metadata_source"] = resolved["metadata_source"]
        payload["registry_fallback_used"] = resolved["registry_fallback_used"]
        payload["keychain_fields"] = resolved["keychain_fields"]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError, SQLiteBackendError) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_explain"]
