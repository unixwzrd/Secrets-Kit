"""
secrets_kit.cli.io

User interaction and terminal output helpers for CLI commands.
"""

from __future__ import annotations

import getpass
import sys
from typing import Optional

from secrets_kit.locale import msg
from secrets_kit.models import ValidationError


def _fatal(*, message: str, code: int = 2) -> int:
    print(msg("errors.error_prefix", message=message), file=sys.stderr)
    return code


def _write_raw_secret(value: str) -> None:
    """Write an explicitly requested secret value to stdout, not diagnostic logs."""
    # Intentional materialization for `seckit get --raw`; normal `get` output stays redacted.
    # codeql[py/clear-text-logging-sensitive-data]
    sys.stdout.write(value)
    sys.stdout.write("\n")


def _confirm(*, prompt: str) -> bool:
    try:
        answer = input(f"{prompt} {msg('prompts.confirm_suffix')}: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _read_value(*, value: Optional[str], use_stdin: bool, allow_empty: bool) -> str:
    if use_stdin:
        data = sys.stdin.read()
    else:
        data = value or ""
    if not allow_empty and not data.strip():
        raise ValidationError("value cannot be empty unless --allow-empty is set")
    return data.strip()


def _read_password(*, value: Optional[str], use_stdin: bool, prompt: str = "password: ") -> str:
    if use_stdin:
        data = sys.stdin.read()
        return data.strip()
    if value:
        return value
    return getpass.getpass(prompt)
