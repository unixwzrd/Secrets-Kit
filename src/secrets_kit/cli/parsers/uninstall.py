"""
secrets_kit.cli.parsers.uninstall

Wire the explicitly confirmed, data-preserving client uninstaller.
"""

from __future__ import annotations

import argparse

from secrets_kit.locale import msg
from secrets_kit.uninstall import cmd_uninstall


def register_uninstall_command(*, subparsers: argparse._SubParsersAction) -> None:
    """Register removal flags without starting a daemon or accessing secrets."""
    parser = subparsers.add_parser("uninstall", help=msg("cli.uninstall.help"))
    parser.add_argument("--dry-run", action="store_true", help=msg("cli.common.dry_run_help"))
    parser.add_argument("--yes", action="store_true", help=msg("cli.common.yes_help"))
    parser.add_argument("--archive", metavar="PATH", help=msg("cli.uninstall.archive_help"))
    parser.add_argument("--purge", action="store_true", help=msg("cli.uninstall.purge_help"))
    parser.add_argument("--purge-file", action="append", metavar="PATH", help=msg("cli.uninstall.purge_file_help"))
    parser.add_argument("--purge-keychain", action="append", nargs=4,
                        metavar=("KEYCHAIN", "SERVICE", "ACCOUNT", "NAME"), help=msg("cli.uninstall.purge_keychain_help"))
    parser.set_defaults(func=cmd_uninstall)
