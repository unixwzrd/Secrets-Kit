"""
secrets_kit.backends.sqlite.connection

SQLite connection management for local transaction persistence.

Connections are intentionally opened without bootstrapping schema objects.
Callers must run ``bootstrap_schema(conn=conn)`` before persistence operations.

Typical initialization:

    conn = connect_sqlite(path=path)
    bootstrap_schema(conn=conn)
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def connect_sqlite(*, path: Path | str) -> sqlite3.Connection:
    """
    Open a configured SQLite connection.

    Args:
        path:
            SQLite database path.

    Returns:
        Configured SQLite connection. The transactions schema is not created
        automatically; callers must explicitly run ``bootstrap_schema``.

    Raises:
        sqlite3.Error:
            SQLite cannot open or configure the database.

    Side Effects:
        Opens a local SQLite database and configures pragmas. Does not create
        tables, triggers, indexes, or migrations.
    """
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    # WAL is enabled for operational concurrency; NORMAL is the Phase 1
    # durability/performance balance and may be revisited in a later phase.
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(*, conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """
    Run statements inside an explicit SQLite transaction boundary.

    Args:
        conn:
            SQLite connection.

    Yields:
        The input connection.

    Raises:
        sqlite3.Error:
            SQLite transaction or statement failure.

    Side Effects:
        Begins, commits, or rolls back a SQLite transaction.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


__all__ = ["connect_sqlite", "transaction"]
