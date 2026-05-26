"""
secrets_kit.backends.sqlite.transactions

Append-only transaction persistence helpers.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.exceptions import (
    DuplicateTransactionError,
    SQLiteValidationError,
    TransactionNotFoundError,
)
from secrets_kit.backends.sqlite.hashing import (
    hash_payload,
    payload_hash_bytes_to_hex,
    payload_hash_hex_to_bytes,
)
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.serialization import canonical_json_bytes, load_canonical_json


def create_transaction(
    *,
    transaction_id: str,
    transaction_type: str,
    origin_node_id: str,
    created_at: str,
    payload: Mapping[str, Any],
    transaction_version: int = 1,
    payload_version: int = 1,
    protocol_version: int = 1,
    payload_encoding: str = "json",
    origin_peer_group_id: str | None = None,
    origin_organization_id: str | None = None,
    source_class: str = "local",
    idempotency_key: str | None = None,
    origin_owner_id: str | None = None,
    target_peer_group_id: str | None = None,
    target_service_group_id: str | None = None,
    target_owner_id: str | None = None,
    target_object_id: str | None = None,
    replication_policy: str | None = None,
    previous_transaction_id: str | None = None,
    signature: bytes | None = None,
    state: str = "recorded",
    received_at: str | None = None,
    applied_at: str | None = None,
    acknowledged_at: str | None = None,
    cleared_at: str | None = None,
) -> Transaction:
    """
    Build a transaction with its canonical payload hash.

    Phase 1 stores canonical transaction payloads directly as JSON for
    debugging visibility. Later phases may separate canonical transaction
    metadata, encrypted object payloads, transport envelope payloads, signing
    identity, transport encryption, and store encryption.

    Args:
        transaction_id:
            Stable transaction identifier.
        transaction_type:
            Application transaction type.
        origin_node_id:
            Node that originated the transaction.
        created_at:
            Creation timestamp string.
        payload:
            Canonical JSON payload data.
        transaction_version:
            Transaction schema version.
        payload_version:
            Payload schema version.
        protocol_version:
            Protocol version.
        payload_encoding:
            Payload storage encoding. Phase 1 supports ``json`` only.
        origin_peer_group_id:
            Origin peer group identifier.
        origin_organization_id:
            Origin organization identifier.
        source_class:
            Source classification.
        idempotency_key:
            Idempotency key.
        origin_owner_id:
            Origin owner identifier.
        target_peer_group_id:
            Target peer group identifier.
        target_service_group_id:
            Target service group identifier.
        target_owner_id:
            Target owner identifier.
        target_object_id:
            Target object identifier.
        replication_policy:
            Replication policy marker.
        previous_transaction_id:
            Simplified lineage placeholder. Future phases may split transaction
            ordering lineage from object mutation lineage.
        signature:
            Nullable reserved cryptographic state. Preserved without
            interpretation in Phase 1.
        state:
            Persistence state. ``recorded`` does not imply projection apply.
        received_at:
            Receive timestamp string.
        applied_at:
            Projection apply timestamp string.
        acknowledged_at:
            Acknowledgement timestamp string.
        cleared_at:
            Clear timestamp string.

    Returns:
        Transaction with computed payload hash.

    Raises:
        SQLiteValidationError:
            Payload cannot be serialized deterministically.

    Side Effects:
        None.
    """
    payload_hash = hash_payload(payload=payload)
    return Transaction(
        transaction_id=transaction_id,
        transaction_type=transaction_type,
        origin_node_id=origin_node_id,
        created_at=created_at,
        payload=payload,
        payload_hash=payload_hash,
        transaction_version=transaction_version,
        payload_version=payload_version,
        protocol_version=protocol_version,
        payload_encoding=payload_encoding,
        origin_peer_group_id=origin_peer_group_id,
        origin_organization_id=origin_organization_id,
        source_class=source_class,
        idempotency_key=idempotency_key,
        origin_owner_id=origin_owner_id,
        target_peer_group_id=target_peer_group_id,
        target_service_group_id=target_service_group_id,
        target_owner_id=target_owner_id,
        target_object_id=target_object_id,
        replication_policy=replication_policy,
        previous_transaction_id=previous_transaction_id,
        signature=signature,
        state=state,
        received_at=received_at,
        applied_at=applied_at,
        acknowledged_at=acknowledged_at,
        cleared_at=cleared_at,
    )


def validate_transaction(*, transaction: Transaction) -> None:
    """
    Validate a transaction before persistence.

    Args:
        transaction:
            Transaction to validate.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Transaction has missing fields or an invalid payload hash.

    Side Effects:
        None.
    """
    required_text = {
        "transaction_id": transaction.transaction_id,
        "transaction_type": transaction.transaction_type,
        "origin_node_id": transaction.origin_node_id,
        "created_at": transaction.created_at,
        "source_class": transaction.source_class,
        "payload_hash": transaction.payload_hash,
    }
    for field_name, value in required_text.items():
        if not value:
            raise SQLiteValidationError(f"{field_name} is required")

    for field_name, value in {
        "transaction_version": transaction.transaction_version,
        "payload_version": transaction.payload_version,
        "protocol_version": transaction.protocol_version,
    }.items():
        if not isinstance(value, int) or value < 1:
            raise SQLiteValidationError(f"{field_name} must be a positive integer")

    if not isinstance(transaction.payload, Mapping):
        raise SQLiteValidationError("payload must be a JSON object")

    if transaction.payload_encoding != "json":
        raise SQLiteValidationError("payload_encoding must be json")

    if transaction.state != "recorded":
        raise SQLiteValidationError("state must be recorded")

    expected_hash = hash_payload(payload=transaction.payload)
    if transaction.payload_hash != expected_hash:
        raise SQLiteValidationError("payload_hash does not match canonical payload")

    payload_hash_hex_to_bytes(hash_hex=transaction.payload_hash)


def insert_transaction(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """
    Append a transaction to canonical local history.

    Args:
        conn:
            SQLite connection.
        transaction:
            Transaction to insert.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Transaction validation failure.
        DuplicateTransactionError:
            Transaction identifier already exists.
        sqlite3.Error:
            SQLite insertion failure.

    Side Effects:
        Inserts one transaction row.
    """
    validate_transaction(transaction=transaction)
    payload_bytes = canonical_json_bytes(payload=transaction.payload)
    payload_hash_bytes = payload_hash_hex_to_bytes(hash_hex=transaction.payload_hash)
    try:
        conn.execute(
            """
            INSERT INTO transactions (
                transaction_id,
                transaction_version,
                payload_version,
                protocol_version,
                payload_encoding,
                transaction_type,
                origin_node_id,
                origin_owner_id,
                origin_peer_group_id,
                origin_organization_id,
                target_peer_group_id,
                target_service_group_id,
                target_owner_id,
                target_object_id,
                source_class,
                replication_policy,
                previous_transaction_id,
                payload_json_or_blob,
                payload_hash,
                signature,
                idempotency_key,
                state,
                created_at,
                received_at,
                applied_at,
                acknowledged_at,
                cleared_at
            ) VALUES (
                :transaction_id,
                :transaction_version,
                :payload_version,
                :protocol_version,
                :payload_encoding,
                :transaction_type,
                :origin_node_id,
                :origin_owner_id,
                :origin_peer_group_id,
                :origin_organization_id,
                :target_peer_group_id,
                :target_service_group_id,
                :target_owner_id,
                :target_object_id,
                :source_class,
                :replication_policy,
                :previous_transaction_id,
                :payload_json_or_blob,
                :payload_hash,
                :signature,
                :idempotency_key,
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
                "payload_encoding": transaction.payload_encoding,
                "transaction_type": transaction.transaction_type,
                "origin_node_id": transaction.origin_node_id,
                "origin_owner_id": transaction.origin_owner_id,
                "origin_peer_group_id": transaction.origin_peer_group_id,
                "origin_organization_id": transaction.origin_organization_id,
                "target_peer_group_id": transaction.target_peer_group_id,
                "target_service_group_id": transaction.target_service_group_id,
                "target_owner_id": transaction.target_owner_id,
                "target_object_id": transaction.target_object_id,
                "source_class": transaction.source_class,
                "replication_policy": transaction.replication_policy,
                "previous_transaction_id": transaction.previous_transaction_id,
                "payload_json_or_blob": payload_bytes,
                "payload_hash": payload_hash_bytes,
                "signature": transaction.signature,
                "idempotency_key": transaction.idempotency_key,
                "state": transaction.state,
                "created_at": transaction.created_at,
                "received_at": transaction.received_at,
                "applied_at": transaction.applied_at,
                "acknowledged_at": transaction.acknowledged_at,
                "cleared_at": transaction.cleared_at,
            },
        )
    except sqlite3.IntegrityError as exc:
        if "UNIQUE" in str(exc) or "transactions.transaction_id" in str(exc):
            raise DuplicateTransactionError(
                f"transaction already exists: {transaction.transaction_id}"
            ) from exc
        raise


def get_transaction(*, conn: sqlite3.Connection, transaction_id: str) -> Transaction:
    """
    Retrieve a transaction by identifier.

    Args:
        conn:
            SQLite connection.
        transaction_id:
            Transaction identifier.

    Returns:
        Stored transaction.

    Raises:
        TransactionNotFoundError:
            Transaction identifier does not exist.
        SQLiteValidationError:
            Stored payload cannot be decoded.
        sqlite3.Error:
            SQLite query failure.

    Side Effects:
        Reads one transaction row.
    """
    row = conn.execute(
        "SELECT * FROM transactions WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()
    if row is None:
        raise TransactionNotFoundError(f"transaction not found: {transaction_id}")

    return Transaction(
        transaction_id=row["transaction_id"],
        transaction_version=row["transaction_version"],
        payload_version=row["payload_version"],
        protocol_version=row["protocol_version"],
        payload_encoding=row["payload_encoding"],
        transaction_type=row["transaction_type"],
        origin_node_id=row["origin_node_id"],
        origin_owner_id=row["origin_owner_id"],
        origin_peer_group_id=row["origin_peer_group_id"],
        origin_organization_id=row["origin_organization_id"],
        target_peer_group_id=row["target_peer_group_id"],
        target_service_group_id=row["target_service_group_id"],
        target_owner_id=row["target_owner_id"],
        target_object_id=row["target_object_id"],
        source_class=row["source_class"],
        replication_policy=row["replication_policy"],
        previous_transaction_id=row["previous_transaction_id"],
        payload=load_canonical_json(payload_bytes=row["payload_json_or_blob"]),
        payload_hash=payload_hash_bytes_to_hex(hash_bytes=row["payload_hash"]),
        signature=bytes(row["signature"]) if row["signature"] is not None else None,
        idempotency_key=row["idempotency_key"],
        state=row["state"],
        created_at=row["created_at"],
        received_at=row["received_at"],
        applied_at=row["applied_at"],
        acknowledged_at=row["acknowledged_at"],
        cleared_at=row["cleared_at"],
    )


def transaction_exists(*, conn: sqlite3.Connection, transaction_id: str) -> bool:
    """
    Check whether a transaction identifier exists.

    Args:
        conn:
            SQLite connection.
        transaction_id:
            Transaction identifier.

    Returns:
        True when the transaction exists, otherwise False.

    Raises:
        sqlite3.Error:
            SQLite query failure.

    Side Effects:
        Reads transaction existence only.
    """
    row = conn.execute(
        "SELECT 1 FROM transactions WHERE transaction_id = ? LIMIT 1",
        (transaction_id,),
    ).fetchone()
    return row is not None


__all__ = [
    "create_transaction",
    "get_transaction",
    "insert_transaction",
    "transaction_exists",
    "validate_transaction",
]
