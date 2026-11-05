"""
secrets_kit.cli.parsers.migrate

Parser registration for migrate commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.migrate import (
    cmd_migrate_dotenv,
    cmd_migrate_keychain,
    cmd_migrate_metadata,
)
from secrets_kit.locale import msg


def register_migrate_commands(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register migrate subcommands.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_migrate = subparsers.add_parser("migrate", help=msg("cli.migrate.help"))
    migrate_sub = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_migrate_dotenv = migrate_sub.add_parser(
        "dotenv", parents=[common], help=msg("cli.migrate.dotenv_help")
    )
    p_migrate_dotenv.add_argument("--dotenv", required=True)
    p_migrate_dotenv.add_argument("--archive")
    p_migrate_dotenv.add_argument("--type", choices=["secret", "pii"])
    p_migrate_dotenv.add_argument("--kind", help=msg("cli.migrate.kind_help_text"))
    p_migrate_dotenv.add_argument("--tags")
    p_migrate_dotenv.add_argument("--dry-run", action="store_true")
    p_migrate_dotenv.add_argument("--allow-overwrite", action="store_true")
    p_migrate_dotenv.add_argument("--allow-empty", action="store_true")
    p_migrate_dotenv.add_argument("--yes", action="store_true")
    p_migrate_dotenv.add_argument(
        "--replace-with-placeholders",
        dest="replace_with_placeholders",
        action="store_true",
        default=True,
    )
    p_migrate_dotenv.add_argument(
        "--no-replace-with-placeholders", dest="replace_with_placeholders", action="store_false"
    )
    p_migrate_dotenv.set_defaults(func=cmd_migrate_dotenv)

    p_migrate_metadata = migrate_sub.add_parser(
        "metadata", parents=[common], help=msg("cli.migrate.metadata_help")
    )
    p_migrate_metadata.add_argument("--dry-run", action="store_true")
    p_migrate_metadata.add_argument("--force", action="store_true")
    p_migrate_metadata.set_defaults(func=cmd_migrate_metadata)

    p_migrate_keychain = migrate_sub.add_parser(
        "keychain", help="Inventory or explicitly copy legacy Keychain items into SQLite"
    )
    p_migrate_keychain.add_argument(
        "--keychain", help="source Keychain path; defaults to login Keychain"
    )
    p_migrate_keychain.add_argument("--service", required=True)
    p_migrate_keychain.add_argument("--account", required=True)
    p_migrate_keychain.add_argument(
        "--apply", action="store_true", help="copy after dry-run review"
    )
    p_migrate_keychain.add_argument(
        "--authorize-sync",
        action="store_true",
        help="also queue newly copied credentials for already eligible peers",
    )
    p_migrate_keychain.set_defaults(func=cmd_migrate_keychain)


__all__ = ["register_migrate_commands"]
