"""
secrets_kit.backends.sqlite.transaction_apply

Canonical transaction-to-projection application.
"""

from __future__ import annotations

import sqlite3

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_admission_projection import (
    apply_peer_admission_accept,
    apply_peer_admission_reject,
    apply_peer_admission_request,
)
from secrets_kit.backends.sqlite.peer_endpoint_projection import apply_peer_endpoint_transaction
from secrets_kit.backends.sqlite.projections import (
    apply_secret_delete_projection,
    apply_secret_set_projection,
)
from secrets_kit.backends.sqlite.vocabulary_projections import (
    apply_vocabulary_entry_kind_upsert,
    apply_vocabulary_entry_type_upsert,
    apply_vocabulary_tag_upsert,
)


def apply_transaction(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """
    Apply one supported transaction to derived projections.

    This is projection application only. Transaction submission policy
    decisions live in ``transaction_engine``.
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
    if transaction.transaction_type == "peer.admission.request":
        apply_peer_admission_request(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "peer.admission.accept":
        apply_peer_admission_accept(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type == "peer.admission.reject":
        apply_peer_admission_reject(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type.startswith("peer.endpoint."):
        apply_peer_endpoint_transaction(conn=conn, transaction=transaction)
        return
    raise SQLiteValidationError(
        f"unsupported replay transaction type: {transaction.transaction_type}"
    )


__all__ = ["apply_transaction"]
