"""
secrets_kit.cli.parsers.init_cmd

Parser registration for seckit init commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.init_cmd import cmd_init
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode
from secrets_kit.locale import msg


def register_init_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register init operator and init sqlite subcommands."""
    p_init = subparsers.add_parser("init", help=msg("cli.init.help"))
    p_init.add_argument("-y", "--yes", action="store_true", help=msg("cli.common.yes_help"))
    p_init.add_argument("--home", help=msg("cli.init.home_help"))
    p_init.add_argument("--backend", choices=list(BACKEND_CHOICES), help=msg("cli.init.backend_help"))
    p_init.add_argument(
        "--dev",
        dest="sqlite_dev_mode",
        action="store_true",
        help=msg("cli.init.dev_help"),
    )

    init_targets = p_init.add_subparsers(dest="init_target", metavar="TARGET")
    p_init_sqlite = init_targets.add_parser("sqlite", help=msg("cli.init.sqlite.help"))
    p_init_sqlite.add_argument(
        "--dev",
        dest="sqlite_dev_mode",
        action="store_true",
        help=msg("cli.init.dev_help"),
    )
    add_sqlite_dev_mode(parser=p_init_sqlite)
    add_sqlite_dev_mode(parser=p_init)
    p_init.set_defaults(func=cmd_init, init_target=None)


__all__ = ["register_init_commands"]
