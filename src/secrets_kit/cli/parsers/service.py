"""
secrets_kit.cli.parsers.service

Parser registration for service commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.service import cmd_service_copy
from secrets_kit.locale import msg


def register_service_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """
    Register service subcommands.

    Args:
        subparsers:
            Root command subparser action.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_service = subparsers.add_parser("service", help=msg("cli.service.help"))
    service_sub = p_service.add_subparsers(dest="service_command", required=True)
    p_service_copy = service_sub.add_parser("copy", help=msg("cli.service.copy_help"))
    p_service_copy.add_argument("--from-service", required=True)
    p_service_copy.add_argument("--to-service", required=True)
    p_service_copy.add_argument("--from-account")
    p_service_copy.add_argument("--to-account")
    p_service_copy.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_service_copy.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_service_copy.add_argument("--names")
    p_service_copy.add_argument("--tag")
    p_service_copy.add_argument("--type", choices=["secret", "pii"])
    p_service_copy.add_argument("--kind", help="entry_kind (taxonomy registry)")
    p_service_copy.add_argument("--overwrite", action="store_true")
    p_service_copy.add_argument("--dry-run", action="store_true")
    p_service_copy.set_defaults(func=cmd_service_copy)


__all__ = ["register_service_commands"]
