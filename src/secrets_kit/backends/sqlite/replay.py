"""
secrets_kit.backends.sqlite.replay

Deterministic local replay for SQLite projection materialization.
"""

from __future__ import annotations

import sqlite3

from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.replay_support import bootstrap_replay_support_rows
from secrets_kit.backends.sqlite.transaction_apply import apply_transaction
from secrets_kit.backends.sqlite.transaction_engine import (
    REPLAY_TRANSACTION_POLICY,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transactions import get_transaction

SUPPORTED_REPLAY_TRANSACTION_TYPES = frozenset(
    {
        "secret.set",
        "secret.delete",
        "vocabulary.entry_type.upsert",
        "vocabulary.entry_kind.upsert",
        "vocabulary.tag.upsert",
        "peer.admission.request",
        "peer.admission.accept",
        "peer.admission.reject",
        "peer.endpoint.register",
        "peer.endpoint.update",
        "peer.endpoint.replace",
        "peer.endpoint.expire",
        "peer.endpoint.remove",
    }
)


def replay_transactions(*, conn: sqlite3.Connection) -> list[Transaction]:
    """
    Return replayable transactions in deterministic local replay order.

    Replay ordering is deterministic only within one local SQLite database
    instance and rebuild sequence. ``rowid`` is a local replay cursor, not a
    distributed consensus ordering mechanism or cross-node ordering guarantee.

    Args:
        conn:
            SQLite connection.

    Returns:
        Replayable transactions ordered by SQLite ``rowid``.

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
        WHERE state IN ('pending', 'applied', 'replayed')
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
            A replayable transaction is unsupported or invalid.
        sqlite3.Error:
            SQLite read/write failure.

    Side Effects:
        Deletes all derived secrets projections and recreates supported rows.
    """
    conn.execute("SAVEPOINT rebuild_secret_projections")
    try:
        conn.execute("DELETE FROM secrets")
        conn.execute("DELETE FROM peer_endpoints")
        transactions = replay_transactions(conn=conn)
        bootstrap_replay_support_rows(conn=conn, transactions=transactions)
        for transaction in transactions:
            submit_transaction(
                conn=conn,
                transaction=transaction,
                policy=REPLAY_TRANSACTION_POLICY,
            )
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT rebuild_secret_projections")
        conn.execute("RELEASE SAVEPOINT rebuild_secret_projections")
        raise
    conn.execute("RELEASE SAVEPOINT rebuild_secret_projections")


__all__ = [
    "SUPPORTED_REPLAY_TRANSACTION_TYPES",
    "apply_transaction",
    "bootstrap_replay_support_rows",
    "rebuild_secret_projections",
    "replay_transactions",
]
