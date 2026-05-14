"""argparse wiring for diagnostics and operator tooling (doctor, version, keychain, …).

Registration order is stable for ``seckit --help``. Human-facing prose is ``STRINGS[...]``.
"""

from __future__ import annotations

import argparse
from typing import Iterable, Type

from secrets_kit.cli.commands.diagnostics import (
    cmd_backend_index,
    cmd_doctor,
    cmd_helper_status,
    cmd_journal_append,
    cmd_keychain_status,
    cmd_lock,
    cmd_rebuild_index,
    cmd_sqlite_inspect,
    cmd_unlock,
    cmd_version,
)
from secrets_kit.cli.commands.migrate import cmd_recover_registry
from secrets_kit.cli.parser.formatter import SeckitHelpFormatter
from secrets_kit.cli.strings.en import STRINGS


def add_diagnostics_family_commands(
    sub: argparse._SubParsersAction,
    *,
    common: argparse.ArgumentParser,
    backend_choices: Iterable[str],
    formatter_class: Type[argparse.HelpFormatter] = SeckitHelpFormatter,
) -> None:
    """
    Register diagnostics and operator commands (``doctor``, ``version``, etc.) on *sub*.

    Args:
        sub: Root subparser action.
        common: Shared parent parser for commands that inherit scope/backend flags.
        backend_choices: Backends allowed on commands that take ``--backend``.
        formatter_class: Help formatter; default
            :class:`~secrets_kit.cli.parser.formatter.SeckitHelpFormatter`.

    Returns:
        None. Mutates *sub* in place.

    Note:
        Order of registration matches historical ``seckit --help`` layout.
    """
    backend_choices = list(backend_choices)

    p_doctor = sub.add_parser(
        "doctor",
        help=STRINGS["DOCTOR_HELP"],
        epilog=STRINGS["DOCTOR_EPILOG"],
        formatter_class=formatter_class,
    )
    p_doctor.add_argument("--backend", choices=backend_choices)
    p_doctor.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_doctor.add_argument("--db", help=STRINGS["HELP_DB"])
    p_doctor.add_argument(
        "--fix-defaults",
        action="store_true",
        help=STRINGS["DOCTOR_FIX_DEFAULTS_HELP"],
    )
    p_doctor.set_defaults(func=cmd_doctor)

    p_backend_index = sub.add_parser(
        "backend-index",
        parents=[common],
        help=STRINGS["BACKEND_INDEX_HELP"],
        epilog=STRINGS["BACKEND_INDEX_EPILOG"],
        formatter_class=formatter_class,
    )
    p_backend_index.set_defaults(func=cmd_backend_index)

    p_sqlite_inspect = sub.add_parser(
        "sqlite-inspect",
        parents=[common],
        help=STRINGS["SQLITE_INSPECT_HELP"],
        epilog=STRINGS["SQLITE_INSPECT_EPILOG"],
        formatter_class=formatter_class,
    )
    p_sqlite_inspect.add_argument(
        "--summaries",
        action="store_true",
        help=STRINGS["SQLITE_INSPECT_SUMMARIES_HELP"],
    )
    p_sqlite_inspect.set_defaults(func=cmd_sqlite_inspect)

    p_rebuild_index = sub.add_parser(
        "rebuild-index",
        parents=[common],
        help=STRINGS["REBUILD_INDEX_HELP"],
    )
    p_rebuild_index.set_defaults(func=cmd_rebuild_index)

    p_journal = sub.add_parser(
        "journal",
        help=STRINGS["JOURNAL_HELP"],
    )
    journal_sub = p_journal.add_subparsers(dest="journal_command", required=True)
    p_journal_append = journal_sub.add_parser(
        "append",
        help=STRINGS["JOURNAL_APPEND_HELP"],
    )
    p_journal_append.add_argument(
        "event_json",
        metavar="JSON",
        help=STRINGS["JOURNAL_EVENT_JSON_HELP"],
    )
    p_journal_append.set_defaults(func=cmd_journal_append)

    p_unlock = sub.add_parser(
        "unlock",
        help=STRINGS["UNLOCK_HELP"],
    )
    p_unlock.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_unlock.add_argument("--dry-run", action="store_true", help=STRINGS["KEYCHAIN_CMD_DRY_RUN_HELP"])
    p_unlock.add_argument("--yes", action="store_true", help=STRINGS["KEYCHAIN_CMD_YES_HELP"])
    p_unlock.add_argument("--harden", action="store_true", help=STRINGS["UNLOCK_HARDEN_HELP"])
    p_unlock.add_argument("--timeout", type=int, default=3600, help=STRINGS["UNLOCK_TIMEOUT_HELP"])
    p_unlock.set_defaults(func=cmd_unlock)

    p_lock = sub.add_parser(
        "lock",
        help=STRINGS["LOCK_HELP"],
    )
    p_lock.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_lock.add_argument("--dry-run", action="store_true", help=STRINGS["KEYCHAIN_CMD_DRY_RUN_HELP"])
    p_lock.add_argument("--yes", action="store_true", help=STRINGS["KEYCHAIN_CMD_YES_HELP"])
    p_lock.set_defaults(func=cmd_lock)

    p_keychain = sub.add_parser(
        "keychain-status",
        help=STRINGS["KEYCHAIN_STATUS_HELP"],
    )
    p_keychain.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_OVERRIDE"])
    p_keychain.set_defaults(func=cmd_keychain_status)

    p_recover = sub.add_parser(
        "recover",
        parents=[common],
        help=STRINGS["RECOVER_HELP"],
        description=STRINGS["RECOVER_DESCRIPTION"],
        epilog=STRINGS["RECOVER_EPILOG"],
        formatter_class=formatter_class,
    )
    p_recover.add_argument(
        "--dry-run",
        action="store_true",
        help=STRINGS["RECOVER_DRY_RUN_HELP"],
    )
    p_recover.add_argument(
        "--json",
        action="store_true",
        help=STRINGS["RECOVER_JSON_OUTPUT_HELP"],
    )
    p_recover.set_defaults(func=cmd_recover_registry)

    p_version = sub.add_parser("version", help=STRINGS["VERSION_HELP"])
    vgrp = p_version.add_mutually_exclusive_group()
    vgrp.add_argument(
        "--info",
        action="store_true",
        dest="version_info",
        help=STRINGS["VERSION_INFO_HELP"],
    )
    vgrp.add_argument(
        "--json",
        action="store_true",
        dest="version_json",
        help=STRINGS["VERSION_JSON_HELP"],
    )
    p_version.set_defaults(func=cmd_version, version_info=False, version_json=False)

    p_helper = sub.add_parser(
        "helper",
        help=STRINGS["HELPER_HELP"],
    )
    helper_sub = p_helper.add_subparsers(dest="helper_command", required=True)
    p_helper_status = helper_sub.add_parser(
        "status",
        help=STRINGS["HELPER_STATUS_HELP"],
    )
    p_helper_status.set_defaults(func=cmd_helper_status)


__all__ = ["add_diagnostics_family_commands"]
