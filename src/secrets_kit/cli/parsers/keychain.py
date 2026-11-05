"""
secrets_kit.cli.parsers.keychain

Parser registration for SQLite doctor.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.locale import msg


def register_keychain_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """
    Register the SQLite doctor command.

    Args:
        subparsers:
            Root command subparser action.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_doctor = subparsers.add_parser("doctor", help=msg("cli.doctor.help"))
    p_doctor.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_doctor.add_argument(
        "--install-check",
        action="store_true",
        help=msg("cli.doctor.install_check_help"),
    )
    p_doctor.set_defaults(func=cmd_doctor)



__all__ = ["register_keychain_commands"]
