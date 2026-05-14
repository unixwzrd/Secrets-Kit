"""
secrets_kit.backends.sqlite

Public SQLite backend surface. Implementation modules live alongside this package;
import stable names from here (``SqliteSecretStore``, path helpers, cache clears).
"""

from __future__ import annotations

from secrets_kit.backends.sqlite.backend import (
    CRYPTO_VERSION,
    PLAINTEXT_DEBUG_CRYPTO_VERSION,
    SqliteSecretStore,
    clear_sqlite_crypto_cache,
    default_sqlite_db_path,
    iter_secrets_plaintext_index,
)

__all__ = [
    "CRYPTO_VERSION",
    "PLAINTEXT_DEBUG_CRYPTO_VERSION",
    "SqliteSecretStore",
    "clear_sqlite_crypto_cache",
    "default_sqlite_db_path",
    "iter_secrets_plaintext_index",
]
