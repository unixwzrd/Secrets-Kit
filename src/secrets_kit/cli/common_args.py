"""
secrets_kit.cli.common_args

Shared argument parser helpers for seckit commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.locale import msg


def add_scope_args(*, parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Add common service/account/backend arguments.

    Args:
        parser:
            Parser to mutate.

    Returns:
        The same parser, for call-site chaining.

    Side Effects:
        Adds argparse options.
    """
    parser.add_argument("--account")
    parser.add_argument("--service")
    parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    parser.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    return parser
