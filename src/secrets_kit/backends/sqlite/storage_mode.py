"""
secrets_kit.backends.sqlite.storage_mode

Immutable SQLite datastore storage-mode metadata.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.models import now_utc_iso

SQLITE_STORAGE_MODE_ENCRYPTED: Final[str] = "encrypted"
SQLITE_STORAGE_MODE_PLAINTEXT: Final[str] = "plaintext"
SQLITE_STORAGE_MODES: Final[frozenset[str]] = frozenset(
    {SQLITE_STORAGE_MODE_ENCRYPTED, SQLITE_STORAGE_MODE_PLAINTEXT}
)
SQLITE_STORAGE_MODE_KEY: Final[str] = "storage_mode"


def normalize_sqlite_storage_mode(value: object | None) -> str:
    """Normalize a SQLite storage-mode value."""
    if value is None:
        return SQLITE_STORAGE_MODE_ENCRYPTED
    mode = str(value).strip().lower()
    if mode not in SQLITE_STORAGE_MODES:
        raise SQLiteBackendError(
            "unsupported SQLite storage mode: "
            f"{value!r}; expected one of: encrypted, plaintext"
        )
    return mode


def initialize_sqlite_storage_mode(*, conn: sqlite3.Connection, mode: object | None) -> str:
    """
    Persist the immutable SQLite storage mode for a newly provisioned datastore.

    Existing metadata must match the requested mode. This function never
    converts or toggles an initialized datastore.
    """
    resolved = normalize_sqlite_storage_mode(mode)
    existing = read_sqlite_storage_mode(conn=conn, missing_ok=True)
    if existing is not None and existing != resolved:
        raise SQLiteBackendError(
            "SQLite storage mode mismatch: "
            f"database={existing}; requested={resolved}; "
            "storage mode is immutable for the lifetime of the datastore"
        )
    if existing is None:
        conn.execute(
            """
            INSERT INTO datastore_metadata (metadata_key, metadata_value, created_at)
            VALUES (?, ?, ?)
            """,
            (SQLITE_STORAGE_MODE_KEY, resolved, now_utc_iso()),
        )
        conn.commit()
    return resolved


def read_sqlite_storage_mode(
    *, conn: sqlite3.Connection, missing_ok: bool = False
) -> str | None:
    """Read the immutable SQLite storage mode from datastore metadata."""
    try:
        row = conn.execute(
            """
            SELECT metadata_value
            FROM datastore_metadata
            WHERE metadata_key = ?
            """,
            (SQLITE_STORAGE_MODE_KEY,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise SQLiteBackendError("SQLite datastore metadata is unavailable") from exc
    if row is None:
        if missing_ok:
            return None
        raise SQLiteBackendError(
            "SQLite storage mode metadata is missing; "
            "run explicit SQLite initialization before using this datastore"
        )
    return normalize_sqlite_storage_mode(row["metadata_value"] if hasattr(row, "keys") else row[0])


def validate_sqlite_storage_mode(
    *, conn: sqlite3.Connection, configured_mode: object | None = None
) -> str:
    """
    Validate database mode against optional operator/default configuration.

    Defaults may describe intended mode, but the database metadata is
    authoritative for an initialized datastore.
    """
    database_mode = read_sqlite_storage_mode(conn=conn)
    if configured_mode is not None:
        expected = normalize_sqlite_storage_mode(configured_mode)
        if expected != database_mode:
            raise SQLiteBackendError(
                "SQLite storage mode mismatch: "
                f"database={database_mode}; configured={expected}; "
                "storage mode is immutable and must not be changed at runtime"
            )
    return database_mode


__all__ = [
    "SQLITE_STORAGE_MODE_ENCRYPTED",
    "SQLITE_STORAGE_MODE_PLAINTEXT",
    "SQLITE_STORAGE_MODES",
    "initialize_sqlite_storage_mode",
    "normalize_sqlite_storage_mode",
    "read_sqlite_storage_mode",
    "validate_sqlite_storage_mode",
]
