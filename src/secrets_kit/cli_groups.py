"""Reusable argparse wiring for seckit.

Shared helpers reuse flag definitions and help strings only. Call sites must keep
command-specific semantics explicit—do not assume one helper implies identical
behavior across commands.
"""

from __future__ import annotations

import argparse
from typing import Sequence


HELP_KEYCHAIN_COMMON = (
    "Secure: keychain file for secret items. SQLite+keychain unlock: keychain file holding "
    "the KEK (see SECKIT_SQLITE_UNLOCK). Default: login.keychain-db"
)

HELP_KEYCHAIN_OVERRIDE = "Override keychain path (default: login.keychain-db)"

HELP_DB = (
    "SQLite database path (--backend sqlite only; default ~/.config/seckit/secrets.db or SECKIT_SQLITE_DB)"
)


def make_common_parent(backend_choices: Sequence[str]) -> argparse.ArgumentParser:
    """Parents=[common] bundle for commands that share scope + backend selection."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account")
    common.add_argument("--service")
    common.add_argument("--backend", choices=list(backend_choices))
    common.add_argument("--keychain", help=HELP_KEYCHAIN_COMMON)
    common.add_argument("--db", help=HELP_DB)
    return common
