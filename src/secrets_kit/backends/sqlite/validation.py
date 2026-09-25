"""
secrets_kit.backends.sqlite.validation

Read-only validation entry point for existing SQLite datastores.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.node_identity import validate_sqlite_node_identity
from secrets_kit.backends.sqlite.operator_store_security import validate_sqlite_operator_store
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    validate_sqlite_storage_mode,
)

_REQUIRED_TABLES = frozenset(
    {
        "datastore_metadata",
        "business_organizations",
        "business_clients",
        "owners",
        "peer_groups",
        "nodes",
        "peer_endpoints",
        "node_private",
        "service_groups",
        "service_group_nodes",
        "entry_types",
        "entry_kinds",
        "transactions",
        "secrets",
        "secret_tags",
        "secret_tag_assignments",
        "secret_domains",
        "secret_custom_metadata",
        "envelopes",
    }
)


def validate_sqlite_schema(*, conn: sqlite3.Connection) -> None:
    """Validate required SQLite schema metadata without modifying the datastore."""
    row = conn.execute("PRAGMA user_version").fetchone()
    user_version = int(row[0]) if row is not None else 0
    if user_version != SCHEMA_VERSION:
        raise SQLiteBackendError(
            "SQLite schema validation failed: "
            f"expected_user_version={SCHEMA_VERSION}; actual_user_version={user_version}"
        )
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    tables = {str(row["name"]) for row in rows}
    missing = sorted(_REQUIRED_TABLES - tables)
    if missing:
        raise SQLiteBackendError(
            "SQLite schema validation failed: missing required tables: " + ", ".join(missing)
        )


def validate_sqlite_datastore(
    *,
    conn: sqlite3.Connection,
    home: Path | None,
    sqlite_db_path: Path,
    configured_storage_mode: object | None,
    validate_operator_store_paths: bool = True,
    validate_identity: bool = True,
) -> str:
    """
    Validate one existing SQLite datastore.

    Validation is read-only. It must not create schema, metadata, keys,
    identity material, or repair filesystem state.
    """
    if validate_operator_store_paths:
        validate_sqlite_operator_store(
            home=home,
            sqlite_db_path=sqlite_db_path,
            require_storage_key=False,
        )
    validate_sqlite_schema(conn=conn)
    storage_mode = validate_sqlite_storage_mode(
        conn=conn,
        configured_mode=configured_storage_mode,
    )
    if validate_operator_store_paths:
        validate_sqlite_operator_store(
            home=home,
            sqlite_db_path=sqlite_db_path,
            require_storage_key=storage_mode == SQLITE_STORAGE_MODE_ENCRYPTED,
        )
    if validate_identity:
        validate_sqlite_node_identity(conn=conn, home=home)
    return storage_mode


__all__ = ["validate_sqlite_datastore", "validate_sqlite_schema"]
