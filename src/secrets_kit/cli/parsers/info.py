"""
secrets_kit.cli.parsers.info

Parser registration for the seckit info command.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.info import cmd_info
from secrets_kit.locale import msg


def register_info_command(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register the info command (environment and backend status)."""
    p_info = subparsers.add_parser("info", help=msg("cli.info.help"))
    p_info.add_argument(
        "--json", action="store_true", dest="info_json", help=msg("cli.info.json_help")
    )
    p_info.add_argument(
        "--backend", choices=list(BACKEND_CHOICES), help=msg("cli.info.backend_help")
    )
    p_info.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_info.set_defaults(func=cmd_info, info_json=False)


__all__ = ["register_info_command"]
