"""
secrets_kit.cli.parser.family_secrets

argparse wiring for core secret operations: set/list/run, config, import/export, service.

Registration order must match historical ``build_parser`` so ``seckit --help`` stays stable.
Human-facing prose is ``STRINGS[...]`` from :mod:`secrets_kit.cli.strings.en`.

"""

from __future__ import annotations

import argparse
from typing import Iterable, Type

from secrets_kit.cli.commands.config import (
    cmd_config_path,
    cmd_config_set,
    cmd_config_show,
    cmd_config_unset,
)
from secrets_kit.cli.commands.import_export import cmd_export, cmd_import_encrypted, cmd_import_env, cmd_import_file
from secrets_kit.cli.commands.secrets import cmd_delete, cmd_explain, cmd_get, cmd_list, cmd_run, cmd_set
from secrets_kit.cli.commands.service_ops import cmd_service_copy
from secrets_kit.cli.parser.formatter import SeckitHelpFormatter
from secrets_kit.cli.strings.en import STRINGS
from secrets_kit.models.core import ENTRY_KIND_VALUES


def add_secrets_family_commands(
    sub: argparse._SubParsersAction,
    *,
    common: argparse.ArgumentParser,
    backend_choices: Iterable[str],
    cfg_keys: list[str],
    formatter_class: Type[argparse.HelpFormatter] = SeckitHelpFormatter,
) -> None:
    """Register core secret commands (``set``, ``get``, ``list``, …, ``service``) on *sub*.

    Args:
        sub: Root subparser action.
        common: Parent parser from :func:`~secrets_kit.cli.parser.groups.make_common_parent`
            (scope/backend flags).
        backend_choices: Iterable copied to list for ``choices=`` where needed.
        cfg_keys: Sorted keys allowed for ``config`` subcommand completion
            (from ``CONFIG_STORABLE_KEYS`` at the call site).
        formatter_class: Argparse help formatter class; default is
            :class:`~secrets_kit.cli.parser.formatter.SeckitHelpFormatter`.

    Returns:
        None. Mutates *sub* in place.

    Note:
        Command registration order is kept stable for ``seckit --help`` output
        and snapshot tests.
    """
    backend_choices = list(backend_choices)

    p_set = sub.add_parser(
        "set",
        parents=[common],
        help=STRINGS["SET_HELP"],
        epilog=STRINGS["SET_EPILOG"],
        formatter_class=formatter_class,
    )
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--value")
    p_set.add_argument("--stdin", action="store_true")
    p_set.add_argument("--type", choices=["secret", "pii"])
    p_set.add_argument("--kind", choices=ENTRY_KIND_VALUES)
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
    p_set.set_defaults(func=cmd_set)

    p_get = sub.add_parser(
        "get",
        parents=[common],
        help=STRINGS["GET_HELP"],
        epilog=STRINGS["GET_EPILOG"],
        formatter_class=formatter_class,
    )
    p_get.add_argument("--name", required=True)
    p_get.add_argument(
        "--raw",
        action="store_true",
        help=STRINGS["GET_RAW_HELP"],
    )
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser(
        "list",
        parents=[common],
        help=STRINGS["LIST_HELP"],
        epilog=STRINGS["LIST_EPILOG"],
        formatter_class=formatter_class,
    )
    p_list.add_argument("--type", choices=["secret", "pii"])
    p_list.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_list.add_argument("--tag")
    p_list.add_argument("--stale", type=int, help=STRINGS["LIST_STALE_HELP"])
    p_list.add_argument("--format", choices=["table", "json"], default="table")
    p_list.set_defaults(func=cmd_list)

    p_explain = sub.add_parser(
        "explain",
        parents=[common],
        help=STRINGS["EXPLAIN_HELP"],
        epilog=STRINGS["EXPLAIN_EPILOG"],
        formatter_class=formatter_class,
    )
    p_explain.add_argument("--name", required=True)
    p_explain.set_defaults(func=cmd_explain)

    p_config = sub.add_parser(
        "config",
        aliases=["defaults"],
        help=STRINGS["CONFIG_HELP"],
        description=STRINGS["CONFIG_COMMAND_DESCRIPTION"],
        epilog=STRINGS["CONFIG_EPILOG"],
        formatter_class=formatter_class,
    )
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_config_show = config_sub.add_parser(
        "show",
        help=STRINGS["CONFIG_SHOW_HELP"],
    )
    p_config_show.add_argument(
        "--effective",
        action="store_true",
        help=STRINGS["CONFIG_EFFECTIVE_HELP"],
    )
    p_config_show.set_defaults(func=cmd_config_show)
    p_config_set = config_sub.add_parser("set", help=STRINGS["CONFIG_SET_HELP"])
    p_config_set.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_set.add_argument("value", help=STRINGS["CONFIG_VALUE_HELP"])
    p_config_set.set_defaults(func=cmd_config_set)
    p_config_unset = config_sub.add_parser("unset", help=STRINGS["CONFIG_UNSET_HELP"])
    p_config_unset.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_unset.set_defaults(func=cmd_config_unset)
    p_config_path = config_sub.add_parser("path", help=STRINGS["CONFIG_PATH_HELP"])
    p_config_path.set_defaults(func=cmd_config_path)

    p_delete = sub.add_parser(
        "delete",
        parents=[common],
        help=STRINGS["DELETE_HELP"],
        epilog=STRINGS["DELETE_EPILOG"],
        formatter_class=formatter_class,
    )
    p_delete.add_argument("--name", required=True)
    p_delete.add_argument("--yes", action="store_true")
    p_delete.set_defaults(func=cmd_delete)

    p_import = sub.add_parser(
        "import",
        help=STRINGS["IMPORT_HELP"],
        description=STRINGS["IMPORT_DESCRIPTION"],
        formatter_class=formatter_class,
    )
    import_sub = p_import.add_subparsers(dest="import_command", required=True)

    p_import_env = import_sub.add_parser(
        "env",
        parents=[common],
        help=STRINGS["IMPORT_ENV_HELP"],
    )
    p_import_env.add_argument("--dotenv")
    p_import_env.add_argument("--from-env")
    p_import_env.add_argument("--type", choices=["secret", "pii"])
    p_import_env.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_env.add_argument("--tags")
    p_import_env.add_argument("--dry-run", action="store_true")
    p_import_env.add_argument("--allow-overwrite", action="store_true")
    p_import_env.add_argument("--upsert", action="store_true", help=STRINGS["IMPORT_UPSERT_HELP"])
    p_import_env.add_argument("--allow-empty", action="store_true")
    p_import_env.add_argument("--yes", action="store_true")
    p_import_env.set_defaults(func=cmd_import_env)

    p_import_file = import_sub.add_parser("file", help=STRINGS["IMPORT_FILE_HELP"])
    p_import_file.add_argument("--file", required=True)
    p_import_file.add_argument("--format", choices=["json", "yaml", "yml"])
    p_import_file.add_argument("--type", choices=["secret", "pii"])
    p_import_file.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_file.add_argument("--backend", choices=backend_choices)
    p_import_file.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_import_file.add_argument("--db", help=STRINGS["HELP_DB"])
    p_import_file.add_argument("--dry-run", action="store_true")
    p_import_file.add_argument("--allow-overwrite", action="store_true")
    p_import_file.add_argument("--allow-empty", action="store_true")
    p_import_file.add_argument("--yes", action="store_true")
    p_import_file.set_defaults(func=cmd_import_file)

    p_import_encrypted = import_sub.add_parser(
        "encrypted-json",
        help=STRINGS["IMPORT_ENCRYPTED_JSON_HELP"],
    )
    p_import_encrypted.add_argument("--file", required=True)
    p_import_encrypted.add_argument("--backend", choices=backend_choices)
    p_import_encrypted.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_import_encrypted.add_argument("--db", help=STRINGS["HELP_DB"])
    p_import_encrypted.add_argument("--password")
    p_import_encrypted.add_argument("--password-stdin", action="store_true")
    p_import_encrypted.add_argument("--dry-run", action="store_true")
    p_import_encrypted.add_argument("--allow-overwrite", action="store_true")
    p_import_encrypted.add_argument("--allow-empty", action="store_true")
    p_import_encrypted.add_argument("--yes", action="store_true")
    p_import_encrypted.set_defaults(func=cmd_import_encrypted)

    p_export = sub.add_parser(
        "export",
        parents=[common],
        help=STRINGS["EXPORT_HELP"],
        epilog=STRINGS["EXPORT_EPILOG"],
        formatter_class=formatter_class,
    )
    p_export.add_argument("--format", default="shell", choices=["shell", "dotenv", "encrypted-json"])
    p_export.add_argument("--out")
    p_export.add_argument("--password")
    p_export.add_argument("--password-stdin", action="store_true")
    p_export.add_argument("--names")
    p_export.add_argument("--tag")
    p_export.add_argument("--type", choices=["secret", "pii"])
    p_export.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_export.add_argument("--all", action="store_true", help=STRINGS["EXPORT_ALL_HELP"])
    p_export.set_defaults(func=cmd_export)

    p_run = sub.add_parser(
        "run",
        parents=[common],
        help=STRINGS["RUN_HELP"],
        epilog=STRINGS["RUN_EPILOG"],
        formatter_class=formatter_class,
    )
    p_run.add_argument("--names")
    p_run.add_argument("--tag")
    p_run.add_argument("--type", choices=["secret", "pii"])
    p_run.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_run.add_argument("--all", action="store_true", help=STRINGS["RUN_ALL_HELP"])
    p_run.add_argument("child_command", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cmd_run)

    p_service = sub.add_parser("service", help=STRINGS["SERVICE_HELP"])
    service_sub = p_service.add_subparsers(dest="service_command", required=True)
    p_service_copy = service_sub.add_parser("copy", help=STRINGS["SERVICE_COPY_HELP"])
    p_service_copy.add_argument("--from-service", required=True)
    p_service_copy.add_argument("--to-service", required=True)
    p_service_copy.add_argument("--from-account")
    p_service_copy.add_argument("--to-account")
    p_service_copy.add_argument("--backend", choices=backend_choices)
    p_service_copy.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_service_copy.add_argument("--db", help=STRINGS["HELP_DB"])
    p_service_copy.add_argument("--names")
    p_service_copy.add_argument("--tag")
    p_service_copy.add_argument("--type", choices=["secret", "pii"])
    p_service_copy.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_service_copy.add_argument("--overwrite", action="store_true")
    p_service_copy.add_argument("--dry-run", action="store_true")
    p_service_copy.set_defaults(func=cmd_service_copy)


__all__ = ["add_secrets_family_commands"]
