"""
secrets_kit.cli.parsers.taxonomy

Taxonomy registry subcommands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.parsers.common import add_taxonomy_normalization_flags
from secrets_kit.locale import msg


def register_taxonomy_commands(*, subparsers: argparse._SubParsersAction) -> None:
    """Register taxonomy subcommands."""
    taxonomy = subparsers.add_parser(
        "taxonomy",
        help=msg("cli.taxonomy.taxonomy_help_text"),
    )
    taxonomy_sub = taxonomy.add_subparsers(dest="taxonomy_command", required=True)

    list_parser = taxonomy_sub.add_parser(
        "list",
        help=msg("cli.taxonomy.list_help_text"),
        description=(
            "List entry types, entry kinds, and/or tags from the taxonomy registry. "
            "With no filter flags, all three lists are shown. Use --types, --kinds, "
            "and/or --tags to limit output."
        ),
    )
    list_parser.add_argument(
        "--types",
        action="store_true",
        help=msg("cli.taxonomy.types_help_text"),
    )
    list_parser.add_argument(
        "--kinds",
        action="store_true",
        help=msg("cli.taxonomy.kinds_help_text"),
    )
    list_parser.add_argument(
        "--tags",
        action="store_true",
        help=msg("cli.taxonomy.tags_help_text"),
    )
    list_parser.add_argument("--json", action="store_true", help=msg("cli.taxonomy.json_help_text"))
    list_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    list_parser.set_defaults(func=cmd_taxonomy_list)

    show_parser = taxonomy_sub.add_parser(
        "show",
        help=msg("cli.taxonomy.show_help_text"),
    )
    show_parser.add_argument("list_name", choices=["entry_type", "entry_kind", "tag"])
    show_parser.add_argument("name")
    show_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    show_parser.set_defaults(func=cmd_taxonomy_show)

    export_parser = taxonomy_sub.add_parser("export", help=msg("cli.taxonomy.export_help_text"))
    export_parser.add_argument("-o", "--output")
    export_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    export_parser.set_defaults(func=cmd_taxonomy_export)

    install_parser = taxonomy_sub.add_parser("install", help=msg("cli.taxonomy.install_help_text"))
    install_parser.add_argument("paths", nargs="+")
    add_taxonomy_normalization_flags(parser=install_parser)
    install_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    install_parser.set_defaults(func=cmd_taxonomy_install)


def cmd_taxonomy_list(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.taxonomy import cmd_taxonomy_list as handler

    return handler(args=args)


def cmd_taxonomy_show(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.taxonomy import cmd_taxonomy_show as handler

    return handler(args=args)


def cmd_taxonomy_export(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.taxonomy import cmd_taxonomy_export as handler

    return handler(args=args)


def cmd_taxonomy_install(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.taxonomy import cmd_taxonomy_install as handler

    return handler(args=args)


__all__ = ["register_taxonomy_commands"]
