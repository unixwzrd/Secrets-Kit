"""
secrets_kit.backends.sqlite.models

Dataclasses for SQLite-backed canonical transaction records.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Transaction:
    """
    Canonical transaction record for local SQLite persistence.

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
            Canonical JSON payload data for Phase 1 storage. This is the
            canonical transaction payload boundary, not a permanent assertion
            that transaction payloads and secure object payloads are identical.
        payload_hash:
            Lowercase hexadecimal SHA-256 hash of canonical payload bytes.
        payload_encoding:
            Encoding used for payload storage. Phase 1 supports ``json`` only.
        transaction_version:
            Transaction schema version.
        payload_version:
            Payload schema version.
        protocol_version:
            Protocol version for future sync compatibility.
        origin_peer_group_id:
            Origin peer group identifier.
        origin_organization_id:
            Origin organization identifier.
        source_class:
            Source classification.
        idempotency_key:
            Application idempotency key.
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
            Nullable reserved cryptographic state. Phase 1 preserves this value
            without signing, verifying, or interpreting it.
        state:
            Phase 1 persistence state. ``recorded`` means durably recorded,
            not replayed, synchronized, acknowledged, or projection-applied.
        received_at:
            Receive timestamp string.
        applied_at:
            Projection application timestamp string.
        acknowledged_at:
            Acknowledgement timestamp string.
        cleared_at:
            Clear timestamp string.

    Returns:
        Immutable transaction record.

    Side Effects:
        None.
    """

    transaction_id: str
    transaction_type: str
    origin_node_id: str
    created_at: str
    payload: Mapping[str, Any]
    payload_hash: str
    transaction_version: int = 1
    payload_version: int = 1
    protocol_version: int = 1
    payload_encoding: str = "json"
    origin_peer_group_id: str | None = None
    origin_organization_id: str | None = None
    source_class: str = "local"
    idempotency_key: str | None = None
    origin_owner_id: str | None = None
    target_peer_group_id: str | None = None
    target_service_group_id: str | None = None
    target_owner_id: str | None = None
    target_object_id: str | None = None
    replication_policy: str | None = None
    previous_transaction_id: str | None = None
    signature: bytes | None = None
    state: str = "recorded"
    received_at: str | None = None
    applied_at: str | None = None
    acknowledged_at: str | None = None
    cleared_at: str | None = None


__all__ = ["Transaction"]
