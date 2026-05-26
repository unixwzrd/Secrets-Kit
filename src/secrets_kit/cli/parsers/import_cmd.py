"""
secrets_kit.cli.parsers.import_cmd

Parser registration for import commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.import_cmd import (
    cmd_import_encrypted,
    cmd_import_env,
    cmd_import_file,
)
from secrets_kit.cli.parsers.common import add_sqlite_dev_mode
from secrets_kit.locale import msg


def register_import_commands(
    *,
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    common: argparse.ArgumentParser,
) -> None:
    """
    Register import command topology.

    Args:
        subparsers:
            Root command subparser action.
        common:
            Shared scope parent parser.

    Side Effects:
        Mutates the root argparse topology.
    """
    p_import = subparsers.add_parser("import", help=msg("cli.import.help"))
    import_sub = p_import.add_subparsers(dest="import_command", required=True)

    p_import_env = import_sub.add_parser("env", parents=[common], help=msg("cli.import.env_help"))
    p_import_env.add_argument("--dotenv")
    p_import_env.add_argument("--from-env")
    p_import_env.add_argument("--type", choices=["secret", "pii"])
    p_import_env.add_argument("--kind", help="entry_kind (taxonomy registry; auto to infer)")
    p_import_env.add_argument("--tags")
    p_import_env.add_argument("--dry-run", action="store_true")
    p_import_env.add_argument("--allow-overwrite", action="store_true")
    p_import_env.add_argument("--upsert", action="store_true", help=msg("cli.import.upsert_help"))
    p_import_env.add_argument("--allow-empty", action="store_true")
    p_import_env.add_argument("--yes", action="store_true")
    add_sqlite_dev_mode(parser=p_import_env)
    p_import_env.set_defaults(func=cmd_import_env)

    p_import_file = import_sub.add_parser("file", help=msg("cli.import.file_help"))
    p_import_file.add_argument("--file", required=True)
    p_import_file.add_argument("--format", choices=["json"])
    p_import_file.add_argument("--type", choices=["secret", "pii"])
    p_import_file.add_argument("--kind", help="entry_kind (taxonomy registry; auto to infer)")
    p_import_file.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_import_file.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_import_file.add_argument("--dry-run", action="store_true")
    p_import_file.add_argument("--allow-overwrite", action="store_true")
    p_import_file.add_argument("--allow-empty", action="store_true")
    p_import_file.add_argument("--yes", action="store_true")
    add_sqlite_dev_mode(parser=p_import_file)
    p_import_file.set_defaults(func=cmd_import_file)

    p_import_encrypted = import_sub.add_parser(
        "encrypted-json", help=msg("cli.import.encrypted_help")
    )
    p_import_encrypted.add_argument("--file", required=True)
    p_import_encrypted.add_argument("--backend", choices=list(BACKEND_CHOICES))
    p_import_encrypted.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    p_import_encrypted.add_argument("--password")
    p_import_encrypted.add_argument("--password-stdin", action="store_true")
    p_import_encrypted.add_argument("--dry-run", action="store_true")
    p_import_encrypted.add_argument("--allow-overwrite", action="store_true")
    p_import_encrypted.add_argument("--allow-empty", action="store_true")
    p_import_encrypted.add_argument("--yes", action="store_true")
    add_sqlite_dev_mode(parser=p_import_encrypted)
    p_import_encrypted.set_defaults(func=cmd_import_encrypted)


__all__ = ["register_import_commands"]
