"""
secrets_kit.cli.parser.groups

Shared argparse *parent* parser (scope and backend flags).

``make_common_parent`` returns a parser with ``add_help=False`` meant only as
``parents=[common]`` when defining leaf commands. Human-facing ``help=`` for
shared flags comes from :mod:`secrets_kit.cli.strings.en` (``STRINGS``). This
module does not register subcommands or handler ``func`` defaults.

"""

from __future__ import annotations

import argparse
from typing import Sequence

from secrets_kit.cli.strings.en import STRINGS


def make_common_parent(backend_choices: Sequence[str]) -> argparse.ArgumentParser:
    """Build the shared parent parser for account/service/backend/keychain/db flags.

    Args:
        backend_choices: Allowed values for ``--backend``; usually from
            ``BACKEND_CHOICES``.

    Returns:
        An :class:`argparse.ArgumentParser` with ``add_help=False`` and
        arguments: ``--account``, ``--service``, ``--backend``, ``--keychain``,
        ``--db``.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account")
    common.add_argument("--service")
    common.add_argument("--backend", choices=list(backend_choices))
    common.add_argument("--keychain", help=STRINGS["HELP_KEYCHAIN_COMMON"])
    common.add_argument("--db", help=STRINGS["HELP_DB"])
    return common
