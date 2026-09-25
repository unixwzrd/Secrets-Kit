"""
secrets_kit.backends.sqlite.provisioning

Explicit provisioning helpers for SQLite datastores.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.storage_mode import initialize_sqlite_storage_mode


def provision_sqlite_datastore(
    *,
    path: Path,
    storage_mode: str,
) -> sqlite3.Connection:
    """
    Create or provision a SQLite datastore schema and immutable metadata.

    This is a provisioning operation. Runtime open paths must not call it for
    existing datastores.
    """
    if path.is_symlink():
        raise SQLiteBackendError(f"SQLite database path must not be a symbolic link: {path}")
    _ensure_parent_directory(path=path)
    existed = path.exists()
    conn = connect_sqlite(path=path)
    try:
        bootstrap_schema(conn=conn)
        initialize_sqlite_storage_mode(conn=conn, mode=storage_mode)
        if not existed:
            path.chmod(0o600)
        return conn
    except Exception:
        conn.close()
        raise


def _ensure_parent_directory(*, path: Path) -> None:
    parent = path.parent
    if parent.exists():
        if parent.is_symlink():
            raise SQLiteBackendError(
                f"SQLite database parent must not be a symbolic link: {parent}"
            )
        if not parent.is_dir():
            raise SQLiteBackendError(f"SQLite database parent is not a directory: {parent}")
        return
    parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(parent, 0o700)


__all__ = ["provision_sqlite_datastore"]
