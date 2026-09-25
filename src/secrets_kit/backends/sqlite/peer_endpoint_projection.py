"""
secrets_kit.backends.sqlite.peer_endpoint_projection

Canonical projection for durable peer endpoint lifecycle records.
"""

from __future__ import annotations

import sqlite3

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_endpoint_auth import (
    PEER_ENDPOINT_EXPIRE,
    PEER_ENDPOINT_REGISTER,
    PEER_ENDPOINT_REMOVE,
    PEER_ENDPOINT_REPLACE,
    PEER_ENDPOINT_UPDATE,
    validate_endpoint,
)
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier


def apply_peer_endpoint_transaction(
    *, conn: sqlite3.Connection, transaction: Transaction
) -> None:
    """Materialize one validated endpoint lifecycle transaction."""
    payload = transaction.payload
    node_id = _node_id(payload=payload)
    endpoint = validate_endpoint(value=payload.get("endpoint"))
    now = transaction.created_at
    row = conn.execute(
        "SELECT state, endpoint, created_at FROM peer_endpoints WHERE node_id = ? AND endpoint = ?",
        (node_id, endpoint),
    ).fetchone()
    active = conn.execute(
        "SELECT endpoint FROM peer_endpoints WHERE node_id = ? AND state = 'active' ORDER BY endpoint",
        (node_id,),
    ).fetchall()

    if transaction.transaction_type == PEER_ENDPOINT_REGISTER:
        if active and all(str(item["endpoint"]) != endpoint for item in active):
            raise SQLiteValidationError(
                "peer already has a different active endpoint; use peer.endpoint.replace: "
                f"peer_id={node_id}"
            )
        _upsert_endpoint(
            conn=conn,
            node_id=node_id,
            endpoint=endpoint,
            state="active",
            created_at=str(row["created_at"]) if row is not None else now,
            updated_at=now,
            expires_at=_optional_text(payload=payload, field="expires_at"),
            comment=_optional_text(payload=payload, field="operator_comment"),
        )
    elif transaction.transaction_type in {PEER_ENDPOINT_UPDATE, PEER_ENDPOINT_REPLACE}:
        previous = validate_endpoint(
            value=payload.get("previous_endpoint") or _active_endpoint(active=active),
            field="previous_endpoint",
        )
        if previous == endpoint and transaction.transaction_type == PEER_ENDPOINT_REPLACE:
            raise SQLiteValidationError("peer endpoint replacement must change endpoint")
        _remove_active_endpoint(conn=conn, node_id=node_id, endpoint=previous, now=now)
        _upsert_endpoint(
            conn=conn,
            node_id=node_id,
            endpoint=endpoint,
            state="active",
            created_at=now,
            updated_at=now,
            expires_at=_optional_text(payload=payload, field="expires_at"),
            comment=_optional_text(payload=payload, field="operator_comment"),
        )
    elif transaction.transaction_type == PEER_ENDPOINT_EXPIRE:
        _require_active_endpoint(active=active, endpoint=endpoint, node_id=node_id)
        _set_endpoint_state(conn=conn, node_id=node_id, endpoint=endpoint, state="expired", now=now)
    elif transaction.transaction_type == PEER_ENDPOINT_REMOVE:
        if not row or str(row["state"]) == "removed":
            raise SQLiteValidationError(f"peer endpoint is not removable: peer_id={node_id} endpoint={endpoint}")
        _set_endpoint_state(conn=conn, node_id=node_id, endpoint=endpoint, state="removed", now=now)
    else:  # pragma: no cover - transaction scope prevents this path.
        raise SQLiteValidationError(f"unsupported peer endpoint transaction: {transaction.transaction_type}")

    current = conn.execute(
        "SELECT endpoint FROM peer_endpoints WHERE node_id = ? AND state = 'active' ORDER BY updated_at DESC, endpoint LIMIT 1",
        (node_id,),
    ).fetchone()
    conn.execute(
        "UPDATE nodes SET service_address = ?, last_seen_at = ?, updated_at = ? WHERE node_id = ?",
        (str(current["endpoint"]) if current else None, now, now, node_id),
    )


def _node_id(*, payload: dict[str, object]) -> str:
    value = payload.get("node_id")
    try:
        return validate_identifier(value=value, expected_type="node", field="node_id")
    except (IdentifierValidationError, TypeError) as exc:
        raise SQLiteValidationError(str(exc)) from exc


def _active_endpoint(*, active: list[sqlite3.Row]) -> str:
    if not active:
        raise SQLiteValidationError("peer endpoint update requires an active endpoint")
    return str(active[0]["endpoint"])


def _require_active_endpoint(*, active: list[sqlite3.Row], endpoint: str, node_id: str) -> None:
    if all(str(row["endpoint"]) != endpoint for row in active):
        raise SQLiteValidationError(
            f"peer endpoint is not active: peer_id={node_id} endpoint={endpoint}"
        )


def _upsert_endpoint(
    *,
    conn: sqlite3.Connection,
    node_id: str,
    endpoint: str,
    state: str,
    created_at: str,
    updated_at: str,
    expires_at: str | None,
    comment: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO peer_endpoints (
            node_id, endpoint, state, created_at, updated_at, expires_at,
            last_seen_at, operator_comment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id, endpoint) DO UPDATE SET
            state = excluded.state,
            updated_at = excluded.updated_at,
            expires_at = excluded.expires_at,
            last_seen_at = excluded.last_seen_at,
            operator_comment = COALESCE(excluded.operator_comment, peer_endpoints.operator_comment)
        """,
        (node_id, endpoint, state, created_at, updated_at, expires_at, updated_at, comment),
    )


def _remove_active_endpoint(*, conn: sqlite3.Connection, node_id: str, endpoint: str, now: str) -> None:
    row = conn.execute(
        "SELECT state FROM peer_endpoints WHERE node_id = ? AND endpoint = ?",
        (node_id, endpoint),
    ).fetchone()
    if row is None or str(row["state"]) != "active":
        raise SQLiteValidationError(
            f"peer endpoint replacement source is not active: peer_id={node_id} endpoint={endpoint}"
        )
    _set_endpoint_state(conn=conn, node_id=node_id, endpoint=endpoint, state="removed", now=now)


def _set_endpoint_state(*, conn: sqlite3.Connection, node_id: str, endpoint: str, state: str, now: str) -> None:
    cursor = conn.execute(
        "UPDATE peer_endpoints SET state = ?, updated_at = ?, last_seen_at = ? WHERE node_id = ? AND endpoint = ?",
        (state, now, now, node_id, endpoint),
    )
    if cursor.rowcount != 1:
        raise SQLiteValidationError(f"peer endpoint record not found: peer_id={node_id} endpoint={endpoint}")


def _optional_text(*, payload: dict[str, object], field: str) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field} must be a non-empty string when present")
    return value


__all__ = ["apply_peer_endpoint_transaction"]
