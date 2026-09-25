"""
secrets_kit.backends.sqlite.gate

SQLite backend paths and connection bootstrap.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from secrets_kit.backends.common import BACKEND_SQLITE, normalize_backend
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.operator_store_security import is_operator_store_path
from secrets_kit.backends.sqlite.validation import validate_sqlite_datastore
from secrets_kit.registry import RegistryError, read_defaults

SQLITE_PATH_ENV = "SECKIT_SQLITE_PATH"


def is_sqlite_backend(*, backend: str) -> bool:
    """Return whether a backend value selects standalone SQLite."""
    return normalize_backend(backend) == BACKEND_SQLITE


def sqlite_path(*, home: Path | None = None) -> Path:
    """Resolve the standalone SQLite database path."""
    configured = os.getenv(SQLITE_PATH_ENV)
    if configured:
        return Path(configured).expanduser()
    operator_home = home or Path.home()
    return operator_home / ".config" / "seckit" / "seckit.sqlite"


def _configured_storage_mode(*, home: Path | None = None) -> object | None:
    try:
        return read_defaults(home=home).get("sqlite_storage_mode")
    except (RegistryError, OSError, TypeError, ValueError):
        return None


def _open_sqlite_connection_only(*, path: Path) -> sqlite3.Connection:
    """Open an existing SQLite datastore without provisioning or repair."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def open_sqlite_backend(
    *,
    home: Path | None = None,
) -> sqlite3.Connection:
    """Open an existing standalone SQLite backend and validate it."""
    path = sqlite_path(home=home)
    is_operator_store = is_operator_store_path(path=path, home=home)
    if path.is_symlink():
        raise SQLiteBackendError(f"SQLite database path must not be a symbolic link: {path}")
    if not path.exists():
        raise SQLiteBackendError(
            f"SQLite database is missing: {path}; run seckit init"
        )
    conn = _open_sqlite_connection_only(path=path)
    try:
        validate_sqlite_datastore(
            conn=conn,
            home=home,
            sqlite_db_path=path,
            configured_storage_mode=_configured_storage_mode(home=home),
            validate_operator_store_paths=is_operator_store,
            validate_identity=True,
        )
    except Exception:
        conn.close()
        raise
    return conn


__all__ = [
    "SQLITE_PATH_ENV",
    "is_sqlite_backend",
    "open_sqlite_backend",
    "sqlite_path",
]
