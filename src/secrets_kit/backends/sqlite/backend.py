"""
secrets_kit.backends.sqlite.backend

Backward-compatible re-exports for SQLite gate + secrets API.
"""

from __future__ import annotations

from secrets_kit.backends.sqlite.gate import (
    SQLITE_DEVELOPER_MODE_ENV,
    SQLITE_DEVELOPER_MODE_WARNING,
    SQLITE_PATH_ENV,
    SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV,
    SQLITE_UNSAFE_WARNING,
    is_sqlite_backend,
    open_sqlite_backend,
    require_sqlite_developer_mode,
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
from secrets_kit.crypto.storage.sqlite import SQLITE_PLAINTEXT_DEBUG_ENV

__all__ = [
    "SQLITE_DEVELOPER_MODE_ENV",
    "SQLITE_DEVELOPER_MODE_WARNING",
    "SQLITE_PATH_ENV",
    "SQLITE_PLAINTEXT_DEBUG_ENV",
    "SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV",
    "SQLITE_UNSAFE_WARNING",
    "SqliteSecretStore",
    "delete_sqlite_secret",
    "get_sqlite_metadata",
    "get_sqlite_secret",
    "get_sqlite_secret_entry",
    "is_sqlite_backend",
    "list_active_sqlite_metadata",
    "open_sqlite_backend",
    "require_sqlite_developer_mode",
    "set_sqlite_secret",
    "sqlite_path",
    "sqlite_secret_exists",
]
