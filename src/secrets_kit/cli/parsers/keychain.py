"""
secrets_kit.cli.parsers.keychain

Parser registration for backend and keychain operational commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.commands.lock import cmd_lock
from secrets_kit.cli.commands.unlock import cmd_unlock
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode
from secrets_kit.locale import msg


def register_keychain_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """
    Register doctor, unlock, and lock commands.

    Args:
        subparsers:
            Root command subparser action.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_doctor = subparsers.add_parser("doctor", help=msg("cli.doctor.help"))
    p_doctor.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_doctor.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_doctor.add_argument(
        "--install-check",
        action="store_true",
        help=msg("cli.doctor.install_check_help"),
    )
    p_doctor.add_argument(
        "--acceptance-test",
        action="store_true",
        help=msg("cli.doctor.acceptance_test_help"),
    )
    add_sqlite_dev_mode(parser=p_doctor)
    p_doctor.set_defaults(func=cmd_doctor)

    p_unlock = subparsers.add_parser("unlock", help=msg("cli.unlock.help"))
    p_unlock.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_unlock.add_argument("--dry-run", action="store_true", help=msg("cli.common.dry_run_help"))
    p_unlock.add_argument("--yes", action="store_true", help=msg("cli.common.yes_help"))
    p_unlock.add_argument("--harden", action="store_true", help=msg("cli.unlock.harden_help"))
    p_unlock.add_argument("--timeout", type=int, default=3600, help=msg("cli.unlock.timeout_help"))
    p_unlock.set_defaults(func=cmd_unlock)

    p_lock = subparsers.add_parser("lock", help=msg("cli.lock.help"))
    p_lock.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_lock.add_argument("--dry-run", action="store_true", help=msg("cli.common.dry_run_help"))
    p_lock.add_argument("--yes", action="store_true", help=msg("cli.common.yes_help"))
    p_lock.set_defaults(func=cmd_lock)


__all__ = ["register_keychain_commands"]
