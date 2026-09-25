"""
secrets_kit.cli.commands.export

Export command implementation.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
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
from secrets_kit.exporters import (
    export_dotenv_placeholders,
    export_shell_lines,
    write_protected_export,
)
from secrets_kit.locale import msg
from secrets_kit.models import ValidationError
from secrets_kit.registry import RegistryError


def cmd_export(*, args: argparse.Namespace) -> int:
    try:
        selected = _select_entries(args=args, require_explicit_selection=True)
        if not selected:
            return _fatal(message=msg("errors.no_matching_entries.export"), code=1)

        if args.format in {"shell", "age"}:
            if args.format == "age":
                executable = shutil.which("age")
                recipient = getattr(args, "recipient", None)
                if not executable or not recipient or not args.out:
                    return _fatal(message=msg("errors.export.age_requirements"), code=1)
            output = export_shell_lines(env_map=_build_env_map(entries=selected, args=args)) + "\n"
            payload = output.encode("utf-8")
            if args.format == "age":
                result = subprocess.run(
                    [executable, "--encrypt", "--recipient", recipient],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
                if result.returncode != 0 or not result.stdout:
                    return _fatal(message=msg("errors.export.age_failed"), code=1)
                payload = result.stdout
            if args.out:
                if args.format == "shell":
                    print(msg("cli.export.plaintext_warning"), file=sys.stderr)
                write_protected_export(destination=Path(args.out), payload=payload)
            else:
                print(output, end="")
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
                prompt=msg("cli.export.password_prompt"),
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
                write_protected_export(
                    destination=Path(args.out), payload=(output + "\n").encode("utf-8")
                )
            else:
                print(output)
            return 0

        return _fatal(message=msg("errors.unsupported_format", format=args.format), code=1)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return _fatal(message=msg("errors.export.write_failed"), code=1)
    except (
        ValidationError,
        RegistryError,
        BackendError,
        SQLiteBackendError,
        CryptoUnavailable,
    ) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_export"]
