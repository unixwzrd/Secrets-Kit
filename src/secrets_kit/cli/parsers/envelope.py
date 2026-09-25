"""
secrets_kit.cli.parsers.envelope

Parser registration for envelope inspection commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.envelope import cmd_envelope_list, cmd_envelope_show
from secrets_kit.locale import msg


def register_envelope_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    envelope = subparsers.add_parser("envelope", help=msg("cli.envelope.envelope_help_text"))
    envelope_sub = envelope.add_subparsers(dest="envelope_command", required=True)

    list_parser = envelope_sub.add_parser("list", help=msg("cli.envelope.list_help_text"))
    list_parser.set_defaults(func=cmd_envelope_list)

    show_parser = envelope_sub.add_parser("show", help=msg("cli.envelope.show_help_text"))
    show_parser.add_argument("envelope_id")
    show_parser.set_defaults(func=cmd_envelope_show)


__all__ = ["register_envelope_commands"]
