"""
secrets_kit.cli.parser

Root argparse topology for the seckit CLI.
"""

from __future__ import annotations

import argparse

from secrets_kit import __version__
from secrets_kit.cli.argparse_helpers import SeckitArgumentParser
from secrets_kit.cli.parsers.common import build_common_parser
from secrets_kit.cli.parsers.config import register_config_commands
from secrets_kit.cli.parsers.export import register_export_command
from secrets_kit.cli.parsers.import_cmd import register_import_commands
from secrets_kit.cli.parsers.info import register_info_command
from secrets_kit.cli.parsers.init_cmd import register_init_commands
from secrets_kit.cli.parsers.install import register_install_commands
from secrets_kit.cli.parsers.keychain import register_keychain_commands
from secrets_kit.cli.parsers.migrate import register_migrate_commands
from secrets_kit.cli.parsers.run import register_run_command
from secrets_kit.cli.parsers.schema import register_schema_commands
from secrets_kit.cli.parsers.secrets import register_delete_command, register_secret_commands
from secrets_kit.cli.parsers.service import register_service_commands
from secrets_kit.cli.parsers.taxonomy import register_taxonomy_commands
from secrets_kit.locale import msg


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the seckit CLI parser.

    Returns:
        Configured argparse parser with command handlers bound.

    Side Effects:
        Creates argparse parser/action objects.
    """
    parser = SeckitArgumentParser(prog="seckit", description=msg("cli.parser.description"))
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title=msg("cli.parser.commands_title"),
        metavar=msg("cli.parser.command_metavar"),
        description=msg("cli.parser.commands_description"),
        parser_class=SeckitArgumentParser,
    )
    common = build_common_parser()

    register_secret_commands(subparsers=subparsers, common=common)
    register_config_commands(subparsers=subparsers)
    register_delete_command(subparsers=subparsers, common=common)
    register_import_commands(subparsers=subparsers, common=common)
    register_export_command(subparsers=subparsers, common=common)
    register_run_command(subparsers=subparsers, common=common)
    register_service_commands(subparsers=subparsers)
    register_keychain_commands(subparsers=subparsers)
    register_init_commands(subparsers=subparsers)
    register_install_commands(subparsers=subparsers)
    register_info_command(subparsers=subparsers)
    register_migrate_commands(subparsers=subparsers, common=common)
    register_schema_commands(subparsers=subparsers)
    register_taxonomy_commands(subparsers=subparsers)

    return parser


__all__ = ["build_parser"]
