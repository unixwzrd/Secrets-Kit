"""
secrets_kit.cli.parsers.common

Shared argparse helpers for parser registration modules.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.locale import msg


def build_common_parser() -> argparse.ArgumentParser:
    """
    Build the shared service/account/backend parent parser.

    Returns:
        Parent parser for commands that accept the common secret scope.

    Side Effects:
        Creates argparse action definitions.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account")
    common.add_argument("--service")
    common.add_argument("--backend", choices=list(BACKEND_CHOICES))
    common.add_argument("--keychain", help=msg("cli.common.keychain_help"))
    return common


def add_taxonomy_normalization_flags(*, parser: argparse.ArgumentParser) -> None:
    """Register taxonomy name normalization flags for vocabulary writes."""
    parser.add_argument(
        "-y",
        "--accept-normalized",
        dest="accept_normalized",
        action="store_true",
        help="accept canonical taxonomy names without prompting",
    )
    parser.add_argument(
        "--force-raw-name",
        dest="force_raw_name",
        action="store_true",
        help="store literal type/kind/tag spelling (developer mode only; forks UUIDs)",
    )


def add_sqlite_dev_mode(*, parser: argparse.ArgumentParser) -> None:
    """Register --sqlite-dev-mode on a command parser."""
    parser.add_argument(
        "--sqlite-dev-mode",
        dest="sqlite_dev_mode",
        action="store_true",
        help=msg("cli.common.sqlite_dev_mode_help"),
    )


__all__ = ["add_sqlite_dev_mode", "add_taxonomy_normalization_flags", "build_common_parser"]
