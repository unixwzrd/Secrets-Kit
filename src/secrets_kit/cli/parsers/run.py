"""
secrets_kit.cli.parsers.run

Parser registration for the run command.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.run import cmd_run
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode
from secrets_kit.locale import msg


def register_run_command(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register the run command.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_run = subparsers.add_parser("run", parents=[common], help=msg("cli.run.help"))
    p_run.add_argument("--names")
    p_run.add_argument("--tag")
    p_run.add_argument("--type", choices=["secret", "pii"])
    p_run.add_argument("--kind", help="entry_kind filter (taxonomy registry)")
    p_run.add_argument("--all", action="store_true")
    add_sqlite_dev_mode(parser=p_run)
    p_run.add_argument("child_command", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cmd_run)


__all__ = ["register_run_command"]
