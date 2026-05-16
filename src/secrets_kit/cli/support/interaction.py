"""
secrets_kit.cli.support.interaction

CLI user interaction and tabular output helpers.
"""

from __future__ import annotations

import getpass
import sys
from datetime import datetime

from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.strings import exit_message
from secrets_kit.models.core import ValidationError


def _fatal(
    *,
    message: str = "",
    code: int | None = None,
    code_name: str = "",
) -> int:
    """Print an error to stderr and return an exit code.

    Parameters:
        message: Override message (defaults to the localized message for ``code_name``).
        code: Override numeric exit code (defaults to ``EXIT_CODES[code_name]``).
        code_name: Exit code name from ``EXIT_CODES`` / ``EXIT_MESSAGES``.

    When ``code_name`` is provided, both the numeric code and the human-readable
    message are resolved automatically from the locale tables. Explicit ``message``
    or ``code`` values override the auto-resolved defaults.
    """
    if code_name:
        numeric = EXIT_CODES.get(code_name, EXIT_CODES["EINVAL"])
        text = message or exit_message(code_name=code_name)
    else:
        numeric = code if code is not None else EXIT_CODES["EINVAL"]
        text = message or "error"
    print(f"ERROR: {text}", file=sys.stderr)
    return numeric


def _confirm(*, prompt: str) -> bool:
    """Prompt the operator for a yes/no confirmation on stdin.

    Returns ``True`` only when the operator responds with ``y`` or ``yes``.
    EOF (non-interactive / piped input) is treated as a refusal.
    """
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _read_value(*, value: str | None, use_stdin: bool, allow_empty: bool) -> str:
    """Read a secret value from stdin or a CLI flag.

    When ``use_stdin`` is ``True``, the value is read from ``sys.stdin``.
    Otherwise the explicit ``value`` string is used. Raises
    ``ValidationError`` when the result is empty and ``allow_empty`` is
    ``False``.
    """
    if use_stdin:
        data = sys.stdin.read()
    else:
        data = value or ""
    if not allow_empty and not data.strip():
        raise ValidationError("value cannot be empty unless --allow-empty is set")
    return data.strip()


def _read_password(*, value: str | None, use_stdin: bool, prompt: str = "password: ") -> str:
    """Read a password from stdin, an explicit value, or an interactive prompt.

    ``getpass`` suppresses echo when reading interactively. Prefer ``use_stdin``
    for piped secrets to avoid exposing them in shell history.
    """
    if use_stdin:
        data = sys.stdin.read()
        return data.strip()
    if value:
        return value
    return getpass.getpass(prompt)


def _format_tags(*, tags: list[str]) -> str:
    """Return a comma-separated tag string, or ``-`` when empty."""
    return ",".join(tags) if tags else "-"


def _print_table(*, headers: list[str], rows: list[list[str]]) -> None:
    """Print a left-aligned, space-separated table to stdout.

    Computes per-column widths from ``headers`` and ``rows``, then emits
    one line per row. No truncation is performed; long cells will widen
    the column.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    def fmt(values: list[str]) -> str:
        """Format a row using computed column widths."""
        return "  ".join(value.ljust(widths[idx]) for idx, value in enumerate(values))

    print(fmt(headers))
    for row in rows:
        print(fmt(row))


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string, normalising ``Z`` to ``+00:00``.

    Returns ``None`` for empty input or unparseable values.
    """
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None
