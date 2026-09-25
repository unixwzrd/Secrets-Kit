"""
secrets_kit.backends.sqlite.transaction_engine

Canonical SQLite transaction submission pipeline.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum

from secrets_kit.backends.sqlite.envelopes import persist_outbound_envelopes_for_configured_peers
from secrets_kit.backends.sqlite.exceptions import DuplicateTransactionError, SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_admission_auth import verify_peer_admission_transaction
from secrets_kit.backends.sqlite.peer_endpoint_auth import verify_peer_endpoint_transaction
from secrets_kit.backends.sqlite.replay_support import bootstrap_replay_support_rows
from secrets_kit.backends.sqlite.transaction_apply import apply_transaction
from secrets_kit.backends.sqlite.transactions import (
    get_transaction,
    insert_transaction,
    mark_transaction_applied,
    transaction_exists,
    validate_transaction,
)


class TransactionSubmissionMode(str, Enum):
    """Explicit transaction submission policy selector."""

    LOCAL = "local"
    REMOTE = "remote"
    RESTORE = "restore"
    REPLAY = "replay"


@dataclass(frozen=True)
class TransactionSubmissionPolicy:
    """
    Explicit policy for one canonical transaction submission.

    Callers choose policy based on their role. The engine does not infer local,
    remote, replay, restore/import, or outbound behavior from unrelated state.
    """

    mode: TransactionSubmissionMode
    persist_transaction: bool
    apply_projection: bool
    mark_applied: bool
    generate_outbound_envelopes: bool
    bootstrap_support_rows: bool
    ignore_duplicate: bool


@dataclass(frozen=True)
class TransactionSubmissionResult:
    transaction_id: str
    mode: TransactionSubmissionMode
    persisted: bool
    applied: bool
    duplicate: bool
    outbound_envelopes_requested: bool


LOCAL_TRANSACTION_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=True,
    bootstrap_support_rows=False,
    ignore_duplicate=False,
)

REMOTE_TRANSACTION_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.REMOTE,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=True,
    bootstrap_support_rows=True,
    ignore_duplicate=True,
)

REPLAY_TRANSACTION_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.REPLAY,
    persist_transaction=False,
    apply_projection=True,
    mark_applied=False,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=False,
    ignore_duplicate=False,
)

RESTORE_TRANSACTION_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.RESTORE,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)


def submit_transaction(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
    policy: TransactionSubmissionPolicy,
) -> TransactionSubmissionResult:
    """
    Validate, persist, apply, and optionally enqueue outbound envelopes.

    The surrounding caller owns the SQLite transaction boundary. This keeps
    local multi-transaction producer flows, such as vocabulary upserts followed
    by ``secret.set``, atomic without duplicating submission semantics.
    """
    validate_transaction(transaction=transaction)
    _validate_authenticated_transaction(conn=conn, transaction=transaction)
    duplicate = False
    persisted = False
    applied = False
    outbound_envelopes_requested = False

    if policy.bootstrap_support_rows:
        bootstrap_replay_support_rows(conn=conn, transactions=[transaction])

    if policy.persist_transaction:
        if policy.ignore_duplicate and transaction_exists(
            conn=conn, transaction_id=transaction.transaction_id
        ):
            _validate_duplicate_payload_matches(conn=conn, transaction=transaction)
            return TransactionSubmissionResult(
                transaction_id=transaction.transaction_id,
                mode=policy.mode,
                persisted=False,
                applied=False,
                duplicate=True,
                outbound_envelopes_requested=False,
            )
        try:
            insert_transaction(conn=conn, transaction=transaction)
            persisted = True
        except DuplicateTransactionError:
            if not policy.ignore_duplicate:
                raise
            _validate_duplicate_payload_matches(conn=conn, transaction=transaction)
            return TransactionSubmissionResult(
                transaction_id=transaction.transaction_id,
                mode=policy.mode,
                persisted=False,
                applied=False,
                duplicate=True,
                outbound_envelopes_requested=False,
            )

    if policy.apply_projection:
        apply_transaction(conn=conn, transaction=transaction)
        applied = True

    if policy.mark_applied:
        mark_transaction_applied(conn=conn, transaction_id=transaction.transaction_id)

    if policy.generate_outbound_envelopes:
        persist_outbound_envelopes_for_configured_peers(conn=conn, transaction=transaction)
        outbound_envelopes_requested = True

    return TransactionSubmissionResult(
        transaction_id=transaction.transaction_id,
        mode=policy.mode,
        persisted=persisted,
        applied=applied,
        duplicate=duplicate,
        outbound_envelopes_requested=outbound_envelopes_requested,
    )


def _validate_authenticated_transaction(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
) -> None:
    if transaction.transaction_type.startswith("peer.admission."):
        verify_peer_admission_transaction(conn=conn, transaction=transaction)
    elif transaction.transaction_type.startswith("peer.endpoint."):
        verify_peer_endpoint_transaction(conn=conn, transaction=transaction)


def _validate_duplicate_payload_matches(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
) -> None:
    existing = get_transaction(conn=conn, transaction_id=transaction.transaction_id)
    if existing.payload_hash != transaction.payload_hash:
        raise SQLiteValidationError(
            f"duplicate transaction_id has different payload: {transaction.transaction_id}"
        )


__all__ = [
    "LOCAL_TRANSACTION_POLICY",
    "REMOTE_TRANSACTION_POLICY",
    "REPLAY_TRANSACTION_POLICY",
    "RESTORE_TRANSACTION_POLICY",
    "TransactionSubmissionMode",
    "TransactionSubmissionPolicy",
    "TransactionSubmissionResult",
    "submit_transaction",
]
