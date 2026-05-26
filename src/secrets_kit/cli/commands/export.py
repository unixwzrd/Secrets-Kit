"""
secrets_kit.cli.commands.export

Export command implementation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import read_secret_value
from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _fatal, _read_password
from secrets_kit.cli.selection import _backend_arg, _build_env_map, _keychain_arg, _select_entries
from secrets_kit.crypto.cli import (
    build_plain_export,
    encrypt_payload,
    ensure_crypto_available,
)
from secrets_kit.crypto.errors import CryptoUnavailable
from secrets_kit.exporters import export_dotenv_placeholders, export_shell_lines
from secrets_kit.locale import msg
from secrets_kit.models import ValidationError
from secrets_kit.registry import RegistryError


def cmd_export(*, args: argparse.Namespace) -> int:
    try:
        selected = _select_entries(args=args, require_explicit_selection=True)
        if not selected:
            return _fatal(message=msg("errors.no_matching_entries.export"), code=1)

        if args.format == "shell":
            print(export_shell_lines(env_map=_build_env_map(entries=selected, args=args)))
            return 0

        if args.format == "dotenv":
            keys = [meta.name for meta in selected]
            print(export_dotenv_placeholders(keys=keys))
            return 0

        if args.format == "encrypted-json":
            ensure_crypto_available()
            password = _read_password(
                value=args.password,
                use_stdin=args.password_stdin,
                prompt="new password to encrypt the backup file: ",
            )
            items: List[Dict[str, str]] = []
            backend = _backend_arg(args)
            for meta in sorted(selected, key=lambda item: item.name):
                value = read_secret_value(
                    service=meta.service,
                    account=meta.account,
                    name=meta.name,
                    backend=backend,
                    keychain_path=_keychain_arg(args),
                    sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
                )
                items.append(
                    {
                        "metadata": meta.to_dict(),
                        "value": value,
                    }
                )
            plain = build_plain_export(entries=items)
            encrypted = encrypt_payload(payload=plain, password=password)
            output = json.dumps(encrypted.__dict__, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return 0

        return _fatal(message=msg("errors.unsupported_format", format=args.format), code=1)
    except (
        ValidationError,
        RegistryError,
        BackendError,
        SQLiteBackendError,
        CryptoUnavailable,
    ) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_export"]
