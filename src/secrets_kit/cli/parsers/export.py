"""
secrets_kit.cli.parsers.export

Parser registration for export commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.export import cmd_export
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode
from secrets_kit.locale import msg


def register_export_command(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register the export command.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_export = subparsers.add_parser("export", parents=[common], help=msg("cli.export.help"))
    p_export.add_argument(
        "--format", default="shell", choices=["shell", "dotenv", "encrypted-json"]
    )
    p_export.add_argument("--out")
    p_export.add_argument("--password")
    p_export.add_argument("--password-stdin", action="store_true")
    p_export.add_argument("--names")
    p_export.add_argument("--tag")
    p_export.add_argument("--type", choices=["secret", "pii"])
    p_export.add_argument("--kind", help="entry_kind filter (taxonomy registry)")
    p_export.add_argument("--all", action="store_true")
    add_sqlite_dev_mode(parser=p_export)
    p_export.set_defaults(func=cmd_export)


__all__ = ["register_export_command"]
