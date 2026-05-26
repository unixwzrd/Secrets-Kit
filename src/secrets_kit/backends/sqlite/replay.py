"""
secrets_kit.backends.sqlite.replay

Deterministic local replay for SQLite projection materialization.
"""

from __future__ import annotations

import sqlite3

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.projections import (
    apply_secret_delete_projection,
    apply_secret_set_projection,
)
from secrets_kit.backends.sqlite.transactions import get_transaction
from secrets_kit.backends.sqlite.vocabulary_projections import (
    apply_vocabulary_entry_kind_upsert,
    apply_vocabulary_entry_type_upsert,
    apply_vocabulary_tag_upsert,
)

SUPPORTED_REPLAY_TRANSACTION_TYPES = frozenset(
    {
        "secret.set",
        "secret.delete",
        "vocabulary.entry_type.upsert",
        "vocabulary.entry_kind.upsert",
        "vocabulary.tag.upsert",
    }
)


def apply_transaction(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """
    Apply one supported transaction to derived projections.

    Args:
        conn:
            SQLite connection.
        transaction:
            Canonical transaction.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Transaction type or payload is unsupported.
        sqlite3.Error:
            SQLite write failure.

    Side Effects:
        Writes derived projection rows for supported transaction types.
    """
    if transaction.transaction_type == "vocabulary.entry_type.upsert":
        apply_vocabulary_entry_type_upsert(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "vocabulary.entry_kind.upsert":
        apply_vocabulary_entry_kind_upsert(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "vocabulary.tag.upsert":
        apply_vocabulary_tag_upsert(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "secret.set":
        apply_secret_set_projection(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "secret.delete":
        apply_secret_delete_projection(conn=conn, transaction=transaction)
        return
    raise SQLiteValidationError(
        f"unsupported replay transaction type: {transaction.transaction_type}"
    )


def replay_transactions(*, conn: sqlite3.Connection) -> list[Transaction]:
    """
    Return recorded transactions in deterministic local replay order.

    Replay ordering is deterministic only within one local SQLite database
    instance and rebuild sequence. ``rowid`` is a Phase 4 local replay cursor,
    not a distributed consensus ordering mechanism or cross-node ordering
    guarantee; a future monotonic sequence column may replace it.

    Args:
        conn:
            SQLite connection.

    Returns:
        Recorded transactions ordered by SQLite ``rowid``.

    Raises:
        SQLiteValidationError:
            Stored transaction payload cannot be decoded.
        sqlite3.Error:
            SQLite query failure.

    Side Effects:
        Reads transaction rows.
    """
    rows = conn.execute(
        """
        SELECT transaction_id
        FROM transactions
        WHERE state = 'recorded'
        ORDER BY rowid ASC
        """
    ).fetchall()
    return [get_transaction(conn=conn, transaction_id=row["transaction_id"]) for row in rows]


def rebuild_secret_projections(*, conn: sqlite3.Connection) -> None:
    """
    Rebuild derived secrets projections from canonical transactions.

    Args:
        conn:
            SQLite connection.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            A recorded transaction is unsupported or invalid.
        sqlite3.Error:
            SQLite read/write failure.

    Side Effects:
        Deletes all derived secrets projections and recreates supported rows.
    """
    conn.execute("DELETE FROM secrets")
    for transaction in replay_transactions(conn=conn):
        apply_transaction(conn=conn, transaction=transaction)


__all__ = [
    "SUPPORTED_REPLAY_TRANSACTION_TYPES",
    "apply_transaction",
    "rebuild_secret_projections",
    "replay_transactions",
]
