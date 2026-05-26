"""
secrets_kit.cli.parsers.secrets

Parser registration for core secret commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.delete import cmd_delete
from secrets_kit.cli.commands.explain import cmd_explain
from secrets_kit.cli.commands.get import cmd_get
from secrets_kit.cli.commands.list import cmd_list
from secrets_kit.cli.commands.set import cmd_set
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode, add_taxonomy_normalization_flags
from secrets_kit.locale import msg


def register_secret_commands(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register set/get/list/explain commands.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_set = subparsers.add_parser("set", parents=[common], help=msg("cli.set.help"))
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--value")
    p_set.add_argument("--stdin", action="store_true")
    p_set.add_argument("--type", help="entry_type (validated against schema registry)")
    p_set.add_argument("--kind", help="entry_kind (validated against schema registry)")
    p_set.add_argument("--schema-id", help="schema_id override")
    p_set.add_argument("--tags")
    p_set.add_argument("--comment")
    p_set.add_argument("--source-url")
    p_set.add_argument("--source-label")
    p_set.add_argument("--rotation-days", type=int)
    p_set.add_argument("--rotation-warn-days", type=int)
    p_set.add_argument("--expires-at")
    p_set.add_argument("--domain", action="append")
    p_set.add_argument("--domains")
    p_set.add_argument("--meta", action="append")
    p_set.add_argument("--allow-empty", action="store_true")
    add_taxonomy_normalization_flags(parser=p_set)
    add_sqlite_dev_mode(parser=p_set)
    p_set.set_defaults(func=cmd_set)

    p_get = subparsers.add_parser("get", parents=[common], help=msg("cli.get.help"))
    p_get.add_argument("--name", required=True)
    p_get.add_argument("--raw", action="store_true")
    add_sqlite_dev_mode(parser=p_get)
    p_get.set_defaults(func=cmd_get)

    p_list = subparsers.add_parser("list", help=msg("cli.list.help"))
    p_list.add_argument("--account")
    p_list.add_argument("--service")
    p_list.add_argument("--type")
    p_list.add_argument("--kind")
    p_list.add_argument("--tag")
    p_list.add_argument("--stale", type=int, help=msg("cli.list.stale_help"))
    p_list.add_argument("--format", choices=["table", "json"], default="table")
    p_list.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_list.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    add_sqlite_dev_mode(parser=p_list)
    p_list.set_defaults(func=cmd_list)

    p_explain = subparsers.add_parser("explain", parents=[common], help=msg("cli.explain.help"))
    p_explain.add_argument("--name", required=True)
    add_sqlite_dev_mode(parser=p_explain)
    p_explain.set_defaults(func=cmd_explain)


def register_delete_command(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register the delete command.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_delete = subparsers.add_parser("delete", parents=[common], help=msg("cli.delete.help"))
    p_delete.add_argument("--name", required=True)
    p_delete.add_argument("--yes", action="store_true")
    add_sqlite_dev_mode(parser=p_delete)
    p_delete.set_defaults(func=cmd_delete)


__all__ = ["register_delete_command", "register_secret_commands"]
