"""
secrets_kit.cli.parsers.config

Parser registration for config commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.config import (
    cmd_config_path,
    cmd_config_set,
    cmd_config_show,
    cmd_config_unset,
)
from secrets_kit.cli.defaults import _CONFIG_STORABLE_KEYS
from secrets_kit.locale import msg


def register_config_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """
    Register config subcommands.

    Args:
        subparsers:
            Root command subparser action.

    Side Effects:
        Mutates the root argparse topology.
    """
    cfg_keys = sorted(_CONFIG_STORABLE_KEYS)
    p_config = subparsers.add_parser("config", help=msg("cli.config.help"))
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_config_show = config_sub.add_parser(
        "show",
        help=msg("cli.config.show_help"),
    )
    p_config_show.add_argument(
        "--effective",
        action="store_true",
        help=msg("cli.config.effective_help"),
    )
    p_config_show.set_defaults(func=cmd_config_show)
    p_config_set = config_sub.add_parser("set", help=msg("cli.config.set_help"))
    p_config_set.add_argument("key", choices=cfg_keys, metavar=msg("cli.config.key_metavar"))
    p_config_set.add_argument("value", help=msg("cli.config.value_help"))
    p_config_set.set_defaults(func=cmd_config_set)
    p_config_unset = config_sub.add_parser("unset", help=msg("cli.config.unset_help"))
    p_config_unset.add_argument("key", choices=cfg_keys, metavar=msg("cli.config.key_metavar"))
    p_config_unset.set_defaults(func=cmd_config_unset)
    p_config_path = config_sub.add_parser("path", help=msg("cli.config.path_help"))
    p_config_path.set_defaults(func=cmd_config_path)


__all__ = ["register_config_commands"]
