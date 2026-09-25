"""
secrets_kit.cli.parsers.status

Parser registration for the operator status command.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.status import cmd_status
from secrets_kit.locale import msg


def register_status_command(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register the status command."""
    parser = subparsers.add_parser("status", help=msg("cli.status.help"))
    parser.add_argument(
        "--json",
        action="store_true",
        dest="status_json",
        help=msg("cli.status.json_help"),
    )
    parser.add_argument(
        "--backend",
        choices=list(BACKEND_CHOICES),
        help=msg("cli.status.backend_compat_help"),
    )
    parser.set_defaults(func=cmd_status, status_json=False)


__all__ = ["register_status_command"]
