"""
secrets_kit.backends.sqlite.audit

**Operational audit** metadata for the SQLite backend — trigger names, table handle,
and read helpers for the append-only ``secrets_audit`` log.

DDL for ``secrets_audit`` and trigger bodies remains authoritative in
:mod:`secrets_kit.backends.sqlite.schema` (``SECRETS_AUDIT_TABLE_SQL``,
``AUDIT_TRIGGERS_SQL``). This module holds **Python** constants and diagnostics only;
it must not introduce new SQL schema.
"""

from __future__ import annotations

import sqlite3

# Table and triggers installed by :func:`secrets_kit.backends.sqlite.schema.install_audit_schema`.
SECRETS_AUDIT_TABLE: str = "secrets_audit"
SECRETS_AUDIT_TRIGGER_AFTER_INSERT: str = "secrets_audit_ai"
SECRETS_AUDIT_TRIGGER_AFTER_UPDATE: str = "secrets_audit_au"
SECRETS_AUDIT_TRIGGER_AFTER_DELETE: str = "secrets_audit_ad"


def fetch_audit_tail(*, conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    """
    Return the most recent ``secrets_audit`` rows (newest ``audit_id`` first).

    **Diagnostics only** — callers must not treat this as merge authority or as a
    replication log; see ``docs/BACKEND_STORE_CONTRACT.md`` (operational vs lineage).

    Restores the connection's previous ``row_factory`` after the query.
    """
    if limit < 1:
        return []
    prev_factory = conn.row_factory
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            f"SELECT * FROM {SECRETS_AUDIT_TABLE} ORDER BY audit_id DESC LIMIT ?",
            (limit,),
        )
        return list(cur.fetchall())
    finally:
        conn.row_factory = prev_factory


def count_audit_rows(*, conn: sqlite3.Connection) -> int | None:
    """Return row count in ``secrets_audit``, or ``None`` if the table is missing."""
    try:
        row = conn.execute(
            f"SELECT COUNT(1) AS n FROM {SECRETS_AUDIT_TABLE}",
        ).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return int(row["n"])
    return int(row[0])
