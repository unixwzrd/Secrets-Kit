"""
secrets_kit.cli.parsers.transaction

Parser registration for transaction inspection commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.transaction import cmd_transaction_list, cmd_transaction_show
from secrets_kit.locale import msg


def register_transaction_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    transaction = subparsers.add_parser("transaction", help=msg("cli.transaction.transaction_help_text"))
    transaction_sub = transaction.add_subparsers(dest="transaction_command", required=True)

    list_parser = transaction_sub.add_parser("list", help=msg("cli.transaction.list_help_text"))
    list_parser.set_defaults(func=cmd_transaction_list)

    show_parser = transaction_sub.add_parser("show", help=msg("cli.transaction.show_help_text"))
    show_parser.add_argument("transaction_id")
    show_parser.set_defaults(func=cmd_transaction_show)


__all__ = ["register_transaction_commands"]
