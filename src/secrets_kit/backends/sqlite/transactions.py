"""
secrets_kit.backends.sqlite.transactions

SQLite transaction persistence helpers.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secrets_kit.backends.sqlite.exceptions import (
    DuplicateTransactionError,
    SQLiteBackendError,
    SQLiteValidationError,
    TransactionNotFoundError,
)
from secrets_kit.backends.sqlite.hashing import (
    payload_hash_bytes_to_hex,
    payload_hash_hex_to_bytes,
    sha256_hex,
)
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.serialization import canonical_json_bytes, load_canonical_json
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier
from secrets_kit.models import now_utc_iso


@dataclass(frozen=True)
class TransactionListInspection:
    transaction_id: str
    transaction_type: str
    state: str
    origin_node_id: str
    created_at: str
    received_at: str
    applied_at: str
    acknowledged_at: str
    cleared_at: str
    payload_hash: str


@dataclass(frozen=True)
class TransactionInspection:
    transaction_id: str
    transaction_version: int
    payload_version: int
    protocol_version: int
    organization_id: str
    client_id: str
    owner_id: str
    origin_node_id: str
    transaction_type: str
    previous_transaction_id: str
    payload: dict[str, Any]
    payload_hash: str
    signature: str
    state: str
    created_at: str
    received_at: str
    applied_at: str
    acknowledged_at: str
    cleared_at: str


def create_transaction(
    *,
    transaction_id: str,
    transaction_type: str,
    origin_node_id: str,
    payload: dict[str, Any],
    created_at: str,
    transaction_version: int = 1,
    payload_version: int = 1,
    protocol_version: int = 1,
    organization_id: str | None = None,
    client_id: str | None = None,
    owner_id: str | None = None,
    previous_transaction_id: str | None = None,
    signature: bytes | None = None,
    state: str = "pending",
    received_at: str | None = None,
    applied_at: str | None = None,
    acknowledged_at: str | None = None,
    cleared_at: str | None = None,
) -> Transaction:
    """
    Create a Transaction with deterministic payload hash.
    """
    payload_bytes = canonical_json_bytes(payload=payload)
    transaction = Transaction(
        transaction_id=transaction_id,
        transaction_type=transaction_type,
        payload=payload,
        payload_hash=sha256_hex(data=payload_bytes),
        transaction_version=transaction_version,
        payload_version=payload_version,
        protocol_version=protocol_version,
        organization_id=organization_id,
        client_id=client_id,
        owner_id=owner_id,
        origin_node_id=origin_node_id,
        previous_transaction_id=previous_transaction_id,
        signature=signature,
        state=state,
        created_at=created_at,
        received_at=received_at,
        applied_at=applied_at,
        acknowledged_at=acknowledged_at,
        cleared_at=cleared_at,
    )
    validate_transaction(transaction=transaction)
    return transaction


def validate_transaction(*, transaction: Transaction) -> None:
    if not transaction.transaction_id:
        raise SQLiteValidationError("transaction_id is required")
    if not transaction.transaction_type:
        raise SQLiteValidationError("transaction_type is required")
    if not transaction.origin_node_id:
        raise SQLiteValidationError("origin_node_id is required")
    if not transaction.created_at:
        raise SQLiteValidationError("created_at is required")
    if not isinstance(transaction.payload, dict):
        raise SQLiteValidationError("payload must be a dict")
    if transaction.state not in {"pending", "applied", "replayed", "failed"}:
        raise SQLiteValidationError("state must be pending, applied, replayed, or failed")
    _validate_identifier(value=transaction.transaction_id, expected_type="transaction", field="transaction_id")
    _validate_identifier(value=transaction.origin_node_id, expected_type="node", field="origin_node_id")
    if transaction.organization_id:
        _validate_identifier(
            value=transaction.organization_id,
            expected_type="organization",
            field="organization_id",
        )
    if transaction.client_id:
        _validate_identifier(value=transaction.client_id, expected_type="client", field="client_id")
    if transaction.owner_id:
        _validate_identifier(value=transaction.owner_id, expected_type="owner", field="owner_id")
    if transaction.previous_transaction_id:
        _validate_identifier(
            value=transaction.previous_transaction_id,
            expected_type="transaction",
            field="previous_transaction_id",
        )

    payload_bytes = canonical_json_bytes(payload=transaction.payload)
    expected_hash = sha256_hex(data=payload_bytes)
    if transaction.payload_hash != expected_hash:
        raise SQLiteValidationError("payload_hash does not match payload")

    _ = payload_hash_hex_to_bytes(hash_hex=transaction.payload_hash)


def _validate_identifier(*, value: str, expected_type: str, field: str) -> None:
    try:
        validate_identifier(
            value=value,
            expected_type=expected_type,  # type: ignore[arg-type]
            field=field,
        )
    except IdentifierValidationError as exc:
        raise SQLiteValidationError(str(exc)) from exc


def insert_transaction(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    validate_transaction(transaction=transaction)
    payload_bytes = canonical_json_bytes(payload=transaction.payload)
    payload_hash = payload_hash_hex_to_bytes(hash_hex=transaction.payload_hash)
    try:
        conn.execute(
            """
            INSERT INTO transactions (
                transaction_id,
                transaction_version,
                payload_version,
                protocol_version,
                organization_id,
                client_id,
                owner_id,
                origin_node_id,
                transaction_type,
                previous_transaction_id,
                payload,
                payload_hash,
                signature,
                state,
                created_at,
                received_at,
                applied_at,
                acknowledged_at,
                cleared_at
            )
            VALUES (
                :transaction_id,
                :transaction_version,
                :payload_version,
                :protocol_version,
                :organization_id,
                :client_id,
                :owner_id,
                :origin_node_id,
                :transaction_type,
                :previous_transaction_id,
                :payload,
                :payload_hash,
                :signature,
                :state,
                :created_at,
                :received_at,
                :applied_at,
                :acknowledged_at,
                :cleared_at
            )
            """,
            {
                "transaction_id": transaction.transaction_id,
                "transaction_version": transaction.transaction_version,
                "payload_version": transaction.payload_version,
                "protocol_version": transaction.protocol_version,
                "organization_id": transaction.organization_id,
                "client_id": transaction.client_id,
                "owner_id": transaction.owner_id,
                "origin_node_id": transaction.origin_node_id,
                "transaction_type": transaction.transaction_type,
                "previous_transaction_id": transaction.previous_transaction_id,
                "payload": payload_bytes,
                "payload_hash": payload_hash,
                "signature": transaction.signature,
                "state": transaction.state,
                "created_at": transaction.created_at,
                "received_at": transaction.received_at,
                "applied_at": transaction.applied_at,
                "acknowledged_at": transaction.acknowledged_at,
                "cleared_at": transaction.cleared_at,
            },
        )
    except sqlite3.IntegrityError as exc:
        message = str(exc).lower()
        if "unique constraint failed: transactions.transaction_id" in message:
            raise DuplicateTransactionError(transaction.transaction_id) from exc
        raise SQLiteBackendError(str(exc)) from exc


def transaction_exists(*, conn: sqlite3.Connection, transaction_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM transactions WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()
    return row is not None


def mark_transaction_applied(*, conn: sqlite3.Connection, transaction_id: str) -> None:
    """
    Transition one pending transaction to applied after projection succeeds.

    Args:
        conn:
            SQLite connection inside the projection transaction boundary.
        transaction_id:
            Canonical transaction identifier.

    Raises:
        SQLiteValidationError:
            No matching pending transaction exists.

    Side Effects:
        Updates the transaction state and application timestamp.
    """
    cursor = conn.execute(
        """
        UPDATE transactions
        SET state = 'applied', applied_at = ?
        WHERE transaction_id = ? AND state = 'pending'
        """,
        (now_utc_iso(), transaction_id),
    )
    if cursor.rowcount != 1:
        raise SQLiteValidationError(
            f"pending transaction not found for applied transition: {transaction_id}"
        )


def get_transaction(*, conn: sqlite3.Connection, transaction_id: str) -> Transaction:
    row = conn.execute(
        """
        SELECT
            transaction_id,
            transaction_version,
            payload_version,
            protocol_version,
            organization_id,
            client_id,
            owner_id,
            origin_node_id,
            transaction_type,
            previous_transaction_id,
            payload,
            payload_hash,
            signature,
            state,
            created_at,
            received_at,
            applied_at,
            acknowledged_at,
            cleared_at
        FROM transactions
        WHERE transaction_id = ?
        """,
        (transaction_id,),
    ).fetchone()
    if row is None:
        raise TransactionNotFoundError(f"transaction not found: {transaction_id}")
    return _transaction_from_row(row=row)


def list_transactions_for_inspection(
    *,
    path: Path,
    limit: int = 50,
    state: str | None = None,
) -> list[TransactionListInspection]:
    query = """
        SELECT
            transaction_id,
            transaction_type,
            state,
            origin_node_id,
            created_at,
            received_at,
            applied_at,
            acknowledged_at,
            cleared_at,
            payload_hash
        FROM transactions
    """
    params: list[Any] = []
    if state is not None:
        query += " WHERE state = ?"
        params.append(state)
    query += " ORDER BY rowid DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    return [_transaction_list_inspection_from_row(row=row) for row in rows]


def inspect_transaction(*, path: Path, transaction_id: str) -> TransactionInspection:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT
                transaction_id,
                transaction_version,
                payload_version,
                protocol_version,
                organization_id,
                client_id,
                owner_id,
                origin_node_id,
                transaction_type,
                previous_transaction_id,
                payload,
                payload_hash,
                signature,
                state,
                created_at,
                received_at,
                applied_at,
                acknowledged_at,
                cleared_at
            FROM transactions
            WHERE transaction_id = ?
            """,
            (transaction_id,),
        ).fetchone()
    if row is None:
        raise TransactionNotFoundError(f"transaction not found: {transaction_id}")
    return _transaction_inspection_from_row(row=row)


def _transaction_from_row(*, row: sqlite3.Row) -> Transaction:
    payload = load_canonical_json(payload_bytes=row["payload"])
    payload_hash = payload_hash_bytes_to_hex(hash_bytes=row["payload_hash"])
    signature = row["signature"]
    return Transaction(
        transaction_id=str(row["transaction_id"]),
        transaction_type=str(row["transaction_type"]),
        payload=payload,
        payload_hash=payload_hash,
        transaction_version=int(row["transaction_version"]),
        payload_version=int(row["payload_version"]),
        protocol_version=int(row["protocol_version"]),
        organization_id=row["organization_id"],
        client_id=row["client_id"],
        owner_id=row["owner_id"],
        origin_node_id=row["origin_node_id"],
        previous_transaction_id=row["previous_transaction_id"],
        signature=bytes(signature) if signature is not None else None,
        state=str(row["state"]),
        created_at=row["created_at"],
        received_at=row["received_at"],
        applied_at=row["applied_at"],
        acknowledged_at=row["acknowledged_at"],
        cleared_at=row["cleared_at"],
    )


def _transaction_list_inspection_from_row(
    *,
    row: sqlite3.Row,
) -> TransactionListInspection:
    return TransactionListInspection(
        transaction_id=str(row["transaction_id"]),
        transaction_type=str(row["transaction_type"]),
        state=str(row["state"]),
        origin_node_id=str(row["origin_node_id"] or ""),
        created_at=str(row["created_at"] or ""),
        received_at=str(row["received_at"] or ""),
        applied_at=str(row["applied_at"] or ""),
        acknowledged_at=str(row["acknowledged_at"] or ""),
        cleared_at=str(row["cleared_at"] or ""),
        payload_hash=payload_hash_bytes_to_hex(hash_bytes=row["payload_hash"]),
    )


def _transaction_inspection_from_row(*, row: sqlite3.Row) -> TransactionInspection:
    signature = row["signature"]
    payload = load_canonical_json(payload_bytes=row["payload"])
    return TransactionInspection(
        transaction_id=str(row["transaction_id"]),
        transaction_version=int(row["transaction_version"]),
        payload_version=int(row["payload_version"]),
        protocol_version=int(row["protocol_version"]),
        organization_id=str(row["organization_id"] or ""),
        client_id=str(row["client_id"] or ""),
        owner_id=str(row["owner_id"] or ""),
        origin_node_id=str(row["origin_node_id"] or ""),
        transaction_type=str(row["transaction_type"]),
        previous_transaction_id=str(row["previous_transaction_id"] or ""),
        payload=payload,
        payload_hash=payload_hash_bytes_to_hex(hash_bytes=row["payload_hash"]),
        signature=bytes(signature).hex() if signature is not None else "",
        state=str(row["state"]),
        created_at=str(row["created_at"] or ""),
        received_at=str(row["received_at"] or ""),
        applied_at=str(row["applied_at"] or ""),
        acknowledged_at=str(row["acknowledged_at"] or ""),
        cleared_at=str(row["cleared_at"] or ""),
    )


def get_persisted_transaction(*, path: Path, transaction_id: str) -> TransactionInspection:
    return inspect_transaction(path=path, transaction_id=transaction_id)


def list_persisted_transactions(
    *, path: Path, limit: int = 50, state: str | None = None
) -> list[TransactionListInspection]:
    return list_transactions_for_inspection(path=path, limit=limit, state=state)


__all__ = [
    "TransactionInspection",
    "TransactionListInspection",
    "create_transaction",
    "get_persisted_transaction",
    "get_transaction",
    "inspect_transaction",
    "insert_transaction",
    "list_persisted_transactions",
    "list_transactions_for_inspection",
    "mark_transaction_applied",
    "transaction_exists",
    "validate_transaction",
]
