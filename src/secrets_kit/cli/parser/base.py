"""
secrets_kit.cli.parser.base

Argparse construction for the ``seckit`` CLI.

``build_parser`` wires the root parser, shared parent flags, and all command
families. Human-facing ``help`` / ``description`` / ``epilog`` text is loaded
from ``STRINGS`` in :mod:`secrets_kit.cli.strings.en`. Help **layout**
(multi-line preservation, default suffixes) uses
:class:`~secrets_kit.cli.parser.formatter.SeckitHelpFormatter`.

"""

from __future__ import annotations

import argparse

from secrets_kit.backends.registry import BACKEND_CHOICES
from secrets_kit.cli.parser.formatter import SeckitHelpFormatter
from secrets_kit.cli.strings.en import STRINGS
from secrets_kit.cli.parser.daemon import add_daemon_commands
from secrets_kit.cli.parser.family_diagnostics import add_diagnostics_family_commands
from secrets_kit.cli.parser.family_secrets import add_secrets_family_commands
from secrets_kit.cli.parser.family_sync_peer import (
    add_identity_peer_reconcile_sync_commands,
    add_migrate_parent_parser,
    add_migrate_subcommands,
)
from secrets_kit.cli.parser.groups import make_common_parent
from secrets_kit.cli.support.defaults import CONFIG_STORABLE_KEYS
from secrets_kit.cli.support.version_info import _cli_version


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the fully configured root CLI parser.

    Returns:
        Root ``seckit`` parser with ``command`` subparsers, all families
        registered, and ``-v`` / ``--version`` defined.

    Note:
        Registration order is intentional so ``seckit --help`` and tests that
        assert help text stay stable.
    """
    parser = argparse.ArgumentParser(
        prog="seckit",
        description=STRINGS["ROOT_DESCRIPTION"],
        epilog=STRINGS["MAIN_HELP_EPILOG"],
        formatter_class=SeckitHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {_cli_version()}")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
        description=STRINGS["SUBPARSERS_DESCRIPTION"],
    )

    backend_choices = list(BACKEND_CHOICES)
    common = make_common_parent(backend_choices)
    cfg_keys = sorted(CONFIG_STORABLE_KEYS)

    add_secrets_family_commands(
        sub,
        common=common,
        backend_choices=backend_choices,
        cfg_keys=cfg_keys,
        formatter_class=SeckitHelpFormatter,
    )
    add_diagnostics_family_commands(
        sub,
        common=common,
        backend_choices=backend_choices,
        formatter_class=SeckitHelpFormatter,
    )
    p_migrate = add_migrate_parent_parser(sub)
    add_identity_peer_reconcile_sync_commands(
        sub,
        common=common,
        backend_choices=backend_choices,
        formatter_class=SeckitHelpFormatter,
    )
    add_migrate_subcommands(
        p_migrate,
        common=common,
        backend_choices=backend_choices,
        formatter_class=SeckitHelpFormatter,
    )
    add_daemon_commands(sub, formatter_class=SeckitHelpFormatter)

    return parser
