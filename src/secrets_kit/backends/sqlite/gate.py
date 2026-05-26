"""
secrets_kit.backends.sqlite.gate

SQLite developer-mode acknowledgement, paths, and connection bootstrap.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from secrets_kit.backends.common import BACKEND_SQLITE, normalize_backend
from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.crypto.storage.sqlite import SQLITE_PLAINTEXT_DEBUG_ENV

SQLITE_DEVELOPER_MODE_ENV = "SECKIT_SQLITE_DEVELOPER_MODE"
SQLITE_PATH_ENV = "SECKIT_SQLITE_PATH"
SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV = "SECKIT_SQLITE_SUPPRESS_DEV_WARNING"
SQLITE_DEVELOPER_MODE_WARNING = (
    "WARNING: SQLite developer mode is enabled. "
    "The current SQLite codec stores plaintext payload bytes because encryption-at-rest is not implemented yet; "
    "use only for local development/testing."
)
SQLITE_UNSAFE_WARNING = SQLITE_DEVELOPER_MODE_WARNING
_SQLITE_DEVELOPER_MODE_WARNING_EMITTED = False


def is_sqlite_backend(*, backend: str) -> bool:
    """Return whether a backend value selects standalone SQLite."""
    return normalize_backend(backend) == BACKEND_SQLITE


def _emit_sqlite_developer_mode_warning_once() -> None:
    global _SQLITE_DEVELOPER_MODE_WARNING_EMITTED
    if os.getenv(SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV, "").strip() == "1":
        return
    if _SQLITE_DEVELOPER_MODE_WARNING_EMITTED:
        return
    print(SQLITE_DEVELOPER_MODE_WARNING, file=sys.stderr)
    _SQLITE_DEVELOPER_MODE_WARNING_EMITTED = True


def require_sqlite_developer_mode(*, sqlite_dev_mode: bool = False) -> None:
    """Require explicit developer-mode acknowledgement for Phase 5A SQLite storage."""
    env_enabled = os.getenv(SQLITE_DEVELOPER_MODE_ENV, "").strip() == "1"
    plaintext_debug_enabled = os.getenv(SQLITE_PLAINTEXT_DEBUG_ENV, "").strip() == "1"
    if not sqlite_dev_mode and not env_enabled and not plaintext_debug_enabled:
        raise SQLiteBackendError(
            "SQLite backend requires --sqlite-dev-mode or SECKIT_SQLITE_DEVELOPER_MODE=1 "
            "until encryption-at-rest is implemented"
        )
    _emit_sqlite_developer_mode_warning_once()


def sqlite_path() -> Path:
    """Resolve the standalone SQLite database path."""
    configured = os.getenv(SQLITE_PATH_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "seckit" / "seckit.sqlite"


def open_sqlite_backend() -> sqlite3.Connection:
    """Open and bootstrap the standalone SQLite backend."""
    path = sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect_sqlite(path=path)
    bootstrap_schema(conn=conn)
    return conn


__all__ = [
    "SQLITE_DEVELOPER_MODE_ENV",
    "SQLITE_DEVELOPER_MODE_WARNING",
    "SQLITE_PATH_ENV",
    "SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV",
    "SQLITE_UNSAFE_WARNING",
    "is_sqlite_backend",
    "open_sqlite_backend",
    "require_sqlite_developer_mode",
    "sqlite_path",
]
