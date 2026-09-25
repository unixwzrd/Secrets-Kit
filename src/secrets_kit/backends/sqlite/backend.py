"""
secrets_kit.backends.sqlite.backend

Re-exports for SQLite gate + secrets API.
"""

from __future__ import annotations

from secrets_kit.backends.sqlite.gate import (
    SQLITE_PATH_ENV,
    is_sqlite_backend,
    open_sqlite_backend,
    sqlite_path,
)
from secrets_kit.backends.sqlite.secrets_api import (
    SqliteSecretStore,
    delete_sqlite_secret,
    get_sqlite_metadata,
    get_sqlite_secret,
    get_sqlite_secret_entry,
    list_active_sqlite_metadata,
    set_sqlite_secret,
    sqlite_secret_exists,
)

__all__ = [
    "SQLITE_PATH_ENV",
    "SqliteSecretStore",
    "delete_sqlite_secret",
    "get_sqlite_metadata",
    "get_sqlite_secret",
    "get_sqlite_secret_entry",
    "is_sqlite_backend",
    "list_active_sqlite_metadata",
    "open_sqlite_backend",
    "set_sqlite_secret",
    "sqlite_path",
    "sqlite_secret_exists",
]
