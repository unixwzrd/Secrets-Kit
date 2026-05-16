"""
secrets_kit.backends.sqlite

Public SQLite backend surface. Implementation modules live alongside this package;
import stable names from here (``SqliteSecretStore``, path helpers, cache clears).
"""

from __future__ import annotations

from secrets_kit.backends.sqlite.store import (
    CRYPTO_VERSION,
    PLAINTEXT_DEBUG_CRYPTO_VERSION,
    SqliteSecretStore,
    clear_sqlite_crypto_cache,
    default_sqlite_db_path,
)
from secrets_kit.backends.sqlite.recovery import SqliteRecoveryCandidate, iter_sqlite_recovery_candidates
from secrets_kit.backends.sqlite.unlock import derive_passphrase_master_key

__all__ = [
    "CRYPTO_VERSION",
    "PLAINTEXT_DEBUG_CRYPTO_VERSION",
    "SqliteSecretStore",
    "clear_sqlite_crypto_cache",
    "default_sqlite_db_path",
    "derive_passphrase_master_key",
    "SqliteRecoveryCandidate",
    "iter_sqlite_recovery_candidates",
]
