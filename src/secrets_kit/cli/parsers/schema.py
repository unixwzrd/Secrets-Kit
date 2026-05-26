"""
secrets_kit.cli.parsers.schema

Schema registry subcommands.
"""

from __future__ import annotations

import argparse

from secrets_kit.locale import msg


def register_schema_commands(*, subparsers: argparse._SubParsersAction) -> None:
    """Register schema subcommands."""
    schema = subparsers.add_parser("schema", help=msg("cli.schema.help"))
    schema_sub = schema.add_subparsers(dest="schema_command", required=True)

    list_parser = schema_sub.add_parser("list", help=msg("cli.schema.list_help"))
    list_parser.add_argument("--all", action="store_true", help=msg("cli.schema.list_all_help"))
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_schema_list)

    show_parser = schema_sub.add_parser("show", help=msg("cli.schema.show_help"))
    show_parser.add_argument("schema_id")
    show_parser.add_argument("--json", action="store_true")
    show_parser.set_defaults(func=cmd_schema_show)

    export_parser = schema_sub.add_parser("export", help=msg("cli.schema.export_help"))
    export_parser.add_argument("-o", "--output")
    export_parser.add_argument("--schema-id")
    export_parser.set_defaults(func=cmd_schema_export)

    install_parser = schema_sub.add_parser("install", help=msg("cli.schema.install_help"))
    install_parser.add_argument("paths", nargs="+")
    install_parser.add_argument("--replace", action="store_true")
    install_parser.add_argument("-y", "--yes", action="store_true")
    install_parser.add_argument("--backend")
    install_parser.add_argument("--sqlite-dev-mode", action="store_true")
    install_parser.set_defaults(func=cmd_schema_install)

    field_remove = schema_sub.add_parser("field", help=msg("cli.schema.field_help"))
    field_sub = field_remove.add_subparsers(dest="field_command", required=True)
    remove_parser = field_sub.add_parser("remove", help=msg("cli.schema.field_remove_help"))
    remove_parser.add_argument("schema_id")
    remove_parser.add_argument("field_name")
    remove_parser.add_argument("--force", action="store_true")
    remove_parser.add_argument("-y", "--yes", action="store_true")
    remove_parser.add_argument("--backend")
    remove_parser.add_argument("--sqlite-dev-mode", action="store_true")
    remove_parser.set_defaults(func=cmd_schema_field_remove)

    deprecate_parser = schema_sub.add_parser("deprecate", help=msg("cli.schema.deprecate_help"))
    deprecate_parser.add_argument("schema_id")
    deprecate_parser.add_argument("--replacement")
    deprecate_parser.add_argument("--reason", default="")
    deprecate_parser.add_argument("--backend")
    deprecate_parser.add_argument("--sqlite-dev-mode", action="store_true")
    deprecate_parser.set_defaults(func=cmd_schema_deprecate)

    remove_schema = schema_sub.add_parser("remove", help=msg("cli.schema.remove_help"))
    remove_schema.add_argument("schema_id")
    remove_schema.add_argument("--force", action="store_true")
    remove_schema.add_argument("-y", "--yes", action="store_true")
    remove_schema.add_argument("--backend")
    remove_schema.add_argument("--sqlite-dev-mode", action="store_true")
    remove_schema.set_defaults(func=cmd_schema_remove)


def cmd_schema_list(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_list as handler

    return handler(args=args)


def cmd_schema_show(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_show as handler

    return handler(args=args)


def cmd_schema_export(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_export as handler

    return handler(args=args)


def cmd_schema_install(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_install as handler

    return handler(args=args)


def cmd_schema_field_remove(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_field_remove as handler

    return handler(args=args)


def cmd_schema_deprecate(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_deprecate as handler

    return handler(args=args)


def cmd_schema_remove(*, args: argparse.Namespace) -> int:
    from secrets_kit.cli.commands.schema import cmd_schema_remove as handler

    return handler(args=args)


__all__ = ["register_schema_commands"]
