"""
secrets_kit.backends.sqlite.models

SQLite backend data models.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Transaction:
    """
    SQLite transaction persistence record.

    Attributes:
        transaction_id:
            Stable transaction identifier.
        transaction_type:
            Transaction type discriminator.
        payload:
            Canonical transaction payload mapping.
        payload_hash:
            Lowercase hexadecimal SHA-256 hash of canonical payload bytes.
        transaction_version:
            Transaction record format version.
        payload_version:
            Payload format version.
        protocol_version:
            Protocol format version.
        organization_id:
            Business organization scope identifier.
        client_id:
            Business client scope identifier.
        owner_id:
            Owner scope identifier.
        origin_node_id:
            Originating node identifier.
        previous_transaction_id:
            Optional predecessor transaction identifier.
        signature:
            Optional transaction signature bytes.
        state:
            Transaction lifecycle state.
        created_at:
            ISO-8601 timestamp for creation.
        received_at:
            ISO-8601 timestamp for receipt, when applicable.
        applied_at:
            ISO-8601 timestamp for projection application, when applicable.
        acknowledged_at:
            ISO-8601 timestamp for acknowledgement, when applicable.
        cleared_at:
            ISO-8601 timestamp for local clearing, when applicable.
    """

    transaction_id: str
    transaction_type: str
    payload: dict[str, Any]
    payload_hash: str
    transaction_version: int = 1
    payload_version: int = 1
    protocol_version: int = 1
    organization_id: str | None = None
    client_id: str | None = None
    owner_id: str | None = None
    origin_node_id: str | None = None
    previous_transaction_id: str | None = None
    signature: bytes | None = None
    state: str = "pending"
    created_at: str | None = None
    received_at: str | None = None
    applied_at: str | None = None
    acknowledged_at: str | None = None
    cleared_at: str | None = None


__all__ = ["Transaction"]
