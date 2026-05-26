"""
secrets_kit.cli.parsers.taxonomy

Taxonomy registry subcommands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.parsers.common import add_sqlite_dev_mode, add_taxonomy_normalization_flags


def register_taxonomy_commands(*, subparsers: argparse._SubParsersAction) -> None:
    """Register taxonomy subcommands."""
    taxonomy = subparsers.add_parser(
        "taxonomy",
        help="manage entry type/kind/tag vocabulary registry",
    )
    taxonomy_sub = taxonomy.add_subparsers(dest="taxonomy_command", required=True)

    list_parser = taxonomy_sub.add_parser(
        "list",
        help="list vocabulary entries (types, kinds, tags) with comments",
        description=(
            "List entry types, entry kinds, and/or tags from the taxonomy registry. "
            "With no filter flags, all three lists are shown. Use --types, --kinds, "
            "and/or --tags to limit output."
        ),
    )
    list_parser.add_argument(
        "--types",
        action="store_true",
        help="include entry_type rows only (policy buckets such as secret, pii)",
    )
    list_parser.add_argument(
        "--kinds",
        action="store_true",
        help="include entry_kind rows only (password, api_key, token, …)",
    )
    list_parser.add_argument(
        "--tags",
        action="store_true",
        help="include tag rows only (operator labels)",
    )
    list_parser.add_argument("--json", action="store_true", help="machine-readable JSON array")
    list_parser.add_argument("--backend")
    add_sqlite_dev_mode(parser=list_parser)
    list_parser.set_defaults(func=cmd_taxonomy_list)

    show_parser = taxonomy_sub.add_parser(
        "show",
        help="show one vocabulary entry (JSON, includes id and comment)",
    )
    show_parser.add_argument("list_name", choices=["entry_type", "entry_kind", "tag"])
    show_parser.add_argument("name")
    show_parser.add_argument("--backend")
    add_sqlite_dev_mode(parser=show_parser)
    show_parser.set_defaults(func=cmd_taxonomy_show)

    export_parser = taxonomy_sub.add_parser("export", help="export taxonomy registry JSON")
    export_parser.add_argument("-o", "--output")
    export_parser.add_argument("--backend")
    add_sqlite_dev_mode(parser=export_parser)
    export_parser.set_defaults(func=cmd_taxonomy_export)

    install_parser = taxonomy_sub.add_parser("install", help="merge taxonomy seed JSON files")
    install_parser.add_argument("paths", nargs="+")
    add_taxonomy_normalization_flags(parser=install_parser)
    install_parser.add_argument("--backend")
    add_sqlite_dev_mode(parser=install_parser)
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
