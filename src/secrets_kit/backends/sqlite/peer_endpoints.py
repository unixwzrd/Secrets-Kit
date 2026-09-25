"""
secrets_kit.backends.sqlite.peer_endpoints

Runtime-owned peer endpoint lifecycle transaction producers and queries.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_endpoint_auth import (
    PEER_ENDPOINT_EXPIRE,
    PEER_ENDPOINT_REGISTER,
    PEER_ENDPOINT_REMOVE,
    PEER_ENDPOINT_REPLACE,
    PEER_ENDPOINT_UPDATE,
    validate_endpoint,
)
from secrets_kit.backends.sqlite.transaction_engine import (
    TransactionSubmissionMode,
    TransactionSubmissionPolicy,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transactions import create_transaction
from secrets_kit.identifiers import random_identifier, validate_identifier
from secrets_kit.models import now_utc_iso

PEER_ENDPOINT_LOCAL_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)
PEER_ENDPOINT_PROPAGATING_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=True,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)


@dataclass(frozen=True)
class PeerEndpointRecord:
    """Durable endpoint metadata projected for one peer identity."""

    node_id: str
    endpoint: str
    state: str
    created_at: str
    updated_at: str
    expires_at: str
    last_seen_at: str
    operator_comment: str


def create_peer_endpoint_transaction(
    *,
    transaction_type: str,
    node_id: str,
    endpoint: str,
    previous_endpoint: str | None = None,
    expires_at: str | None = None,
    operator_comment: str = "",
) -> Transaction:
    """Create one canonical endpoint lifecycle transaction."""
    if transaction_type not in {
        PEER_ENDPOINT_REGISTER,
        PEER_ENDPOINT_UPDATE,
        PEER_ENDPOINT_REPLACE,
        PEER_ENDPOINT_EXPIRE,
        PEER_ENDPOINT_REMOVE,
    }:
        raise SQLiteValidationError(f"unsupported peer endpoint transaction type: {transaction_type}")
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    endpoint = validate_endpoint(value=endpoint)
    if previous_endpoint is not None:
        previous_endpoint = validate_endpoint(value=previous_endpoint, field="previous_endpoint")
    if transaction_type in {PEER_ENDPOINT_UPDATE, PEER_ENDPOINT_REPLACE} and not previous_endpoint:
        raise SQLiteValidationError(f"{transaction_type} requires previous_endpoint")
    if expires_at is not None and not expires_at:
        raise SQLiteValidationError("expires_at must not be empty")
    payload: dict[str, object] = {
        "node_id": node_id,
        "endpoint": endpoint,
        "observed_at": now_utc_iso(),
    }
    if previous_endpoint is not None:
        payload["previous_endpoint"] = previous_endpoint
    if expires_at is not None:
        payload["expires_at"] = expires_at
    if operator_comment:
        payload["operator_comment"] = operator_comment
    return create_transaction(
        transaction_id=random_identifier(identifier_type="transaction"),
        transaction_type=transaction_type,
        origin_node_id=node_id,
        payload=payload,
        created_at=str(payload["observed_at"]),
    )


def register_local_endpoint(
    *,
    endpoint: str,
    expires_at: str | None = None,
    operator_comment: str = "",
    propagate: bool = False,
) -> Transaction:
    """Register the current local daemon endpoint through the transaction engine."""
    return _submit_local(
        transaction=create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REGISTER,
            node_id=_local_node_id(),
            endpoint=endpoint,
            expires_at=expires_at,
            operator_comment=operator_comment,
        ),
        propagate=propagate,
    )


def reregister_local_endpoint(
    *,
    endpoint: str,
    expires_at: str | None = None,
    operator_comment: str = "",
    propagate: bool = False,
) -> Transaction:
    """Register or canonically replace the local daemon endpoint.

    Daemon restart and rebinding may present a different endpoint while the
    prior endpoint remains active in the durable projection.  Re-registration
    therefore uses the endpoint replacement transaction rather than bypassing
    the lifecycle state machine.
    """
    node_id = _local_node_id()
    conn = open_sqlite_backend()
    try:
        active = list_active_peer_endpoints(conn=conn)
        previous = next((value for peer_id, value in active if peer_id == node_id), None)
    finally:
        conn.close()
    if previous is not None and previous != endpoint:
        return update_local_endpoint(
            endpoint=endpoint,
            previous_endpoint=previous,
            expires_at=expires_at,
            operator_comment=operator_comment,
            propagate=propagate,
        )
    return register_local_endpoint(
        endpoint=endpoint,
        expires_at=expires_at,
        operator_comment=operator_comment,
        propagate=propagate,
    )


def update_local_endpoint(
    *,
    endpoint: str,
    previous_endpoint: str,
    expires_at: str | None = None,
    operator_comment: str = "",
    propagate: bool = False,
) -> Transaction:
    """Replace the local active endpoint through a canonical update transaction."""
    return _submit_local(
        transaction=create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_UPDATE,
            node_id=_local_node_id(),
            endpoint=endpoint,
            previous_endpoint=previous_endpoint,
            expires_at=expires_at,
            operator_comment=operator_comment,
        ),
        propagate=propagate,
    )


def replace_local_endpoint(
    *,
    endpoint: str,
    previous_endpoint: str,
    expires_at: str | None = None,
    operator_comment: str = "",
    propagate: bool = False,
) -> Transaction:
    """Replace the local endpoint with an explicit replacement transaction."""
    return _submit_local(
        transaction=create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REPLACE,
            node_id=_local_node_id(),
            endpoint=endpoint,
            previous_endpoint=previous_endpoint,
            expires_at=expires_at,
            operator_comment=operator_comment,
        ),
        propagate=propagate,
    )


def expire_local_endpoint(
    *, endpoint: str, operator_comment: str = "", propagate: bool = False
) -> Transaction:
    """Mark one local endpoint expired through a canonical transaction."""
    return _submit_local(
        transaction=create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_EXPIRE,
            node_id=_local_node_id(),
            endpoint=endpoint,
            operator_comment=operator_comment,
        ),
        propagate=propagate,
    )


def remove_local_endpoint(
    *, endpoint: str, operator_comment: str = "", propagate: bool = False
) -> Transaction:
    """Remove one local endpoint through a canonical transaction."""
    return _submit_local(
        transaction=create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REMOVE,
            node_id=_local_node_id(),
            endpoint=endpoint,
            operator_comment=operator_comment,
        ),
        propagate=propagate,
    )


def list_peer_endpoint_records(*, conn: sqlite3.Connection, node_id: str | None = None) -> list[PeerEndpointRecord]:
    """List durable endpoint records in deterministic order."""
    query = """
        SELECT node_id, endpoint, state, created_at, updated_at,
               expires_at, last_seen_at, operator_comment
        FROM peer_endpoints
    """
    parameters: tuple[object, ...] = ()
    if node_id is not None:
        validate_identifier(value=node_id, expected_type="node", field="node_id")
        query += " WHERE node_id = ?"
        parameters = (node_id,)
    query += " ORDER BY node_id, updated_at, endpoint"
    return [
        PeerEndpointRecord(
            node_id=str(row["node_id"]),
            endpoint=str(row["endpoint"]),
            state=str(row["state"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            expires_at=str(row["expires_at"] or ""),
            last_seen_at=str(row["last_seen_at"] or ""),
            operator_comment=str(row["operator_comment"] or ""),
        )
        for row in conn.execute(query, parameters).fetchall()
    ]


def list_active_peer_endpoints(*, conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Return active endpoint descriptors keyed by peer identity."""
    rows = conn.execute(
        """
        SELECT node_id, endpoint
        FROM peer_endpoints
        WHERE state = 'active'
        ORDER BY node_id, updated_at DESC, endpoint
        """
    ).fetchall()
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for row in rows:
        node_id = str(row["node_id"])
        if node_id in seen:
            continue
        seen.add(node_id)
        result.append((node_id, str(row["endpoint"])))
    return result


def _submit_local(*, transaction: Transaction, propagate: bool) -> Transaction:
    conn = open_sqlite_backend()
    try:
        with sqlite_transaction(conn=conn):
            submit_transaction(
                conn=conn,
                transaction=transaction,
                policy=PEER_ENDPOINT_PROPAGATING_POLICY if propagate else PEER_ENDPOINT_LOCAL_POLICY,
            )
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()
    return transaction


def _local_node_id() -> str:
    conn = open_sqlite_backend()
    try:
        projection = load_local_node_projection(conn=conn)
        if projection is None:
            raise SQLiteValidationError("local node identity is required before endpoint registration")
        return projection.node_id
    finally:
        conn.close()


__all__ = [
    "PEER_ENDPOINT_EXPIRE",
    "PEER_ENDPOINT_REGISTER",
    "PEER_ENDPOINT_REMOVE",
    "PEER_ENDPOINT_REPLACE",
    "PEER_ENDPOINT_UPDATE",
    "PEER_ENDPOINT_LOCAL_POLICY",
    "PeerEndpointRecord",
    "create_peer_endpoint_transaction",
    "expire_local_endpoint",
    "list_active_peer_endpoints",
    "list_peer_endpoint_records",
    "register_local_endpoint",
    "replace_local_endpoint",
    "reregister_local_endpoint",
    "remove_local_endpoint",
    "update_local_endpoint",
]
