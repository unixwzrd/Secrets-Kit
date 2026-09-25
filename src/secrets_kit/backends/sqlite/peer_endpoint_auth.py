"""
secrets_kit.backends.sqlite.peer_endpoint_auth

Validation shared by peer-endpoint transaction submission and projection.
"""

from __future__ import annotations

import re
import sqlite3

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_registry import get_peer_registry_entry
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier

PEER_ENDPOINT_REGISTER = "peer.endpoint.register"
PEER_ENDPOINT_UPDATE = "peer.endpoint.update"
PEER_ENDPOINT_REPLACE = "peer.endpoint.replace"
PEER_ENDPOINT_EXPIRE = "peer.endpoint.expire"
PEER_ENDPOINT_REMOVE = "peer.endpoint.remove"
PEER_ENDPOINT_TRANSACTION_TYPES = frozenset(
    {
        PEER_ENDPOINT_REGISTER,
        PEER_ENDPOINT_UPDATE,
        PEER_ENDPOINT_REPLACE,
        PEER_ENDPOINT_EXPIRE,
        PEER_ENDPOINT_REMOVE,
    }
)
PEER_ENDPOINT_STATES = frozenset({"active", "expired", "removed"})
_ENDPOINT_MAX_LENGTH = 2048
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def validate_endpoint(*, value: object, field: str = "endpoint") -> str:
    """Validate one transport-neutral, opaque endpoint descriptor."""
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field} is required")
    if len(value) > _ENDPOINT_MAX_LENGTH:
        raise SQLiteValidationError(f"{field} exceeds {_ENDPOINT_MAX_LENGTH} characters")
    if value != value.strip() or _CONTROL_CHARACTERS.search(value):
        raise SQLiteValidationError(f"{field} contains invalid whitespace or control characters")
    return value


def verify_peer_endpoint_transaction(
    *, conn: sqlite3.Connection, transaction: Transaction
) -> None:
    """Verify endpoint transaction identity, authorization, and payload shape."""
    if transaction.transaction_type not in PEER_ENDPOINT_TRANSACTION_TYPES:
        raise SQLiteValidationError(
            f"unsupported peer endpoint transaction type: {transaction.transaction_type}"
        )
    payload = transaction.payload
    node_id = payload.get("node_id")
    try:
        validate_identifier(value=node_id, expected_type="node", field="node_id")
    except (IdentifierValidationError, TypeError) as exc:
        raise SQLiteValidationError(str(exc)) from exc
    if transaction.origin_node_id != node_id:
        raise SQLiteValidationError(
            "peer endpoint origin_node_id must match payload node_id: "
            f"transaction_id={transaction.transaction_id}"
        )
    validate_endpoint(value=payload.get("endpoint"))
    previous = payload.get("previous_endpoint")
    if transaction.transaction_type in {PEER_ENDPOINT_UPDATE, PEER_ENDPOINT_REPLACE} and previous is None:
        raise SQLiteValidationError(
            f"{transaction.transaction_type} requires previous_endpoint"
        )
    if previous is not None:
        validate_endpoint(value=previous, field="previous_endpoint")
    expires_at = payload.get("expires_at")
    if expires_at is not None and (not isinstance(expires_at, str) or not expires_at):
        raise SQLiteValidationError("expires_at must be a non-empty ISO-8601 string when present")

    local_node = load_local_node_projection(conn=conn)
    if local_node is not None and local_node.node_id == node_id:
        return
    entry = get_peer_registry_entry(conn=conn, node_id=node_id)
    if entry is None or not entry.synchronization_eligible:
        raise SQLiteValidationError(
            "peer endpoint transaction requires an admitted, authorized peer: "
            f"peer_id={node_id}"
        )


__all__ = [
    "PEER_ENDPOINT_EXPIRE",
    "PEER_ENDPOINT_REGISTER",
    "PEER_ENDPOINT_REMOVE",
    "PEER_ENDPOINT_REPLACE",
    "PEER_ENDPOINT_STATES",
    "PEER_ENDPOINT_TRANSACTION_TYPES",
    "PEER_ENDPOINT_UPDATE",
    "validate_endpoint",
    "verify_peer_endpoint_transaction",
]
