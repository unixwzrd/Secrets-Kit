"""
secrets_kit.backends.sqlite.peer_registry

Canonical SQLite Peer Registry read model.

The registry is a deterministic projection over existing peer lifecycle
tables. It does not own cryptographic identity, transport configuration,
transaction history, or synchronization queues. Registry state changes are
created by canonical transactions and materialized by transaction replay.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.crypto.codecs import encode_b64url
from secrets_kit.identifiers import validate_identifier

ADMISSION_STATE_REQUESTED = "admission_requested"
ADMISSION_STATE_ACTIVE = "active"
ADMISSION_STATE_REJECTED = "rejected"
AUTHORIZATION_STATE_AUTHORIZED = "authorized"
AUTHORIZATION_STATE_UNAUTHORIZED = "unauthorized"
AUTHORIZATION_MODE_NONE = "none"
AUTHORIZATION_MODE_ALLOW_LIST = "allow_list"
AUTHORIZATION_MODE_ALL = "all"
AUTHORIZATION_MODES = frozenset(
    {AUTHORIZATION_MODE_NONE, AUTHORIZATION_MODE_ALLOW_LIST, AUTHORIZATION_MODE_ALL}
)


@dataclass(frozen=True)
class PeerRegistryEntry:
    node_id: str
    admission_state: str
    authorization_state: str
    authorization_mode: str
    synchronization_eligible: bool
    display_name: str
    local_alias: str
    service_address: str
    endpoint: str
    endpoint_state: str
    endpoint_expires_at: str
    signing_algorithm: str
    signing_public_key: str
    signing_fingerprint: str
    encryption_algorithm: str
    encryption_public_key: str
    encryption_fingerprint: str
    service_group_ids: tuple[str, ...]
    created_at: str
    updated_at: str
    operator_metadata: str


def get_peer_registry_entry(
    *, conn: sqlite3.Connection, node_id: str
) -> PeerRegistryEntry | None:
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    row = conn.execute(
        """
        SELECT
            n.node_id,
            n.state,
            n.signing_algorithm,
            n.signing_public_key,
            n.encryption_algorithm,
            n.encryption_public_key,
            n.authorization_mode,
            n.service_address,
            n.operator_description,
            n.created_at,
            n.updated_at,
            n.operator_comment
        FROM nodes n
        LEFT JOIN node_private np ON np.node_id = n.node_id
        WHERE n.node_id = ? AND np.node_id IS NULL
        """,
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return _entry_from_row(conn=conn, row=row)


def list_peer_registry_entries(*, conn: sqlite3.Connection) -> list[PeerRegistryEntry]:
    rows = conn.execute(
        """
        SELECT
            n.node_id,
            n.state,
            n.signing_algorithm,
            n.signing_public_key,
            n.encryption_algorithm,
            n.encryption_public_key,
            n.authorization_mode,
            n.service_address,
            n.operator_description,
            n.created_at,
            n.updated_at,
            n.operator_comment
        FROM nodes n
        LEFT JOIN node_private np ON np.node_id = n.node_id
        WHERE np.node_id IS NULL
        ORDER BY n.node_id
        """
    ).fetchall()
    return [_entry_from_row(conn=conn, row=row) for row in rows]


def is_peer_synchronization_eligible(
    *,
    conn: sqlite3.Connection,
    node_id: str,
    service_group_id: str | None = None,
) -> bool:
    entry = get_peer_registry_entry(conn=conn, node_id=node_id)
    if entry is None:
        return False
    if not entry.synchronization_eligible:
        return False
    if service_group_id is None:
        return True
    validate_identifier(
        value=service_group_id,
        expected_type="service_group",
        field="service_group_id",
    )
    if entry.authorization_mode == AUTHORIZATION_MODE_ALL:
        return True
    if entry.authorization_mode == AUTHORIZATION_MODE_ALLOW_LIST:
        return service_group_id in entry.service_group_ids
    return False


def require_peer_synchronization_eligible(
    *,
    conn: sqlite3.Connection,
    node_id: str,
    service_group_id: str | None = None,
) -> None:
    entry = get_peer_registry_entry(conn=conn, node_id=node_id)
    if entry is None:
        raise SQLiteValidationError(f"unknown peer: peer_id={node_id}")
    if not entry.synchronization_eligible:
        raise SQLiteValidationError(
            "peer synchronization not permitted: "
            f"peer_id={node_id} admission_state={entry.admission_state} "
            f"authorization_state={entry.authorization_state}"
        )
    if service_group_id is None:
        return
    if entry.authorization_mode == AUTHORIZATION_MODE_ALL:
        return
    if entry.authorization_mode == AUTHORIZATION_MODE_ALLOW_LIST and service_group_id in entry.service_group_ids:
        return
    if entry.authorization_mode == AUTHORIZATION_MODE_ALLOW_LIST:
        raise SQLiteValidationError(
            "peer is not authorized for service group: "
            f"peer_id={node_id} service_group_id={service_group_id}"
        )
    raise SQLiteValidationError(
        "peer has no service-group synchronization authorization: "
        f"peer_id={node_id} authorization_mode={entry.authorization_mode} "
        f"service_group_id={service_group_id}"
    )


def _entry_from_row(*, conn: sqlite3.Connection, row: sqlite3.Row) -> PeerRegistryEntry:
    signing_public_key = _bytes_or_empty(row["signing_public_key"])
    encryption_public_key = _bytes_or_empty(row["encryption_public_key"])
    admission_state = str(row["state"] or "")
    authorization_mode = str(row["authorization_mode"] or AUTHORIZATION_MODE_NONE)
    if authorization_mode not in AUTHORIZATION_MODES:
        raise SQLiteValidationError(
            "peer authorization_mode is invalid: "
            f"peer_id={row['node_id']} authorization_mode={authorization_mode}"
        )
    authorization_state = _authorization_state(admission_state=admission_state)
    service_group_ids = _service_group_ids(conn=conn, node_id=str(row["node_id"]))
    endpoint, endpoint_state, endpoint_expires_at = _endpoint_metadata(
        conn=conn,
        node_id=str(row["node_id"]),
        legacy_service_address=str(row["service_address"] or ""),
    )
    return PeerRegistryEntry(
        node_id=str(row["node_id"]),
        admission_state=admission_state,
        authorization_state=authorization_state,
        authorization_mode=authorization_mode,
        synchronization_eligible=(
            admission_state == ADMISSION_STATE_ACTIVE
            and authorization_state == AUTHORIZATION_STATE_AUTHORIZED
        ),
        display_name=str(row["operator_description"] or ""),
        local_alias="",
        service_address=endpoint,
        endpoint=endpoint,
        endpoint_state=endpoint_state,
        endpoint_expires_at=endpoint_expires_at,
        signing_algorithm=str(row["signing_algorithm"] or ""),
        signing_public_key=encode_b64url(signing_public_key) if signing_public_key else "",
        signing_fingerprint=_fingerprint(value=signing_public_key),
        encryption_algorithm=str(row["encryption_algorithm"] or ""),
        encryption_public_key=(
            encode_b64url(encryption_public_key) if encryption_public_key else ""
        ),
        encryption_fingerprint=_fingerprint(value=encryption_public_key),
        service_group_ids=service_group_ids,
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
        operator_metadata=str(row["operator_comment"] or ""),
    )


def _authorization_state(*, admission_state: str) -> str:
    if admission_state == ADMISSION_STATE_ACTIVE:
        return AUTHORIZATION_STATE_AUTHORIZED
    return AUTHORIZATION_STATE_UNAUTHORIZED


def _service_group_ids(*, conn: sqlite3.Connection, node_id: str) -> tuple[str, ...]:
    rows = conn.execute(
        """
        SELECT service_group_id
        FROM service_group_nodes
        WHERE node_id = ? AND COALESCE(state, '') = 'active'
        ORDER BY service_group_id
        """,
        (node_id,),
    ).fetchall()
    return tuple(str(row["service_group_id"]) for row in rows)


def _endpoint_metadata(
    *, conn: sqlite3.Connection, node_id: str, legacy_service_address: str
) -> tuple[str, str, str]:
    """Resolve current durable endpoint metadata for a peer."""
    row = conn.execute(
        """
        SELECT endpoint, state, expires_at
        FROM peer_endpoints
        WHERE node_id = ?
        ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'expired' THEN 1 ELSE 2 END,
                 updated_at DESC, endpoint
        LIMIT 1
        """,
        (node_id,),
    ).fetchone()
    if row is None:
        return legacy_service_address, "unknown", ""
    endpoint = str(row["endpoint"] or "") if str(row["state"]) == "active" else ""
    return endpoint, str(row["state"]), str(row["expires_at"] or "")


def _bytes_or_empty(value: object) -> bytes:
    if value is None:
        return b""
    return bytes(value)


def _fingerprint(*, value: bytes) -> str:
    if not value:
        return ""
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "ADMISSION_STATE_ACTIVE",
    "ADMISSION_STATE_REJECTED",
    "ADMISSION_STATE_REQUESTED",
    "AUTHORIZATION_MODE_ALL",
    "AUTHORIZATION_MODE_ALLOW_LIST",
    "AUTHORIZATION_MODE_NONE",
    "AUTHORIZATION_MODES",
    "AUTHORIZATION_STATE_AUTHORIZED",
    "AUTHORIZATION_STATE_UNAUTHORIZED",
    "PeerRegistryEntry",
    "get_peer_registry_entry",
    "is_peer_synchronization_eligible",
    "list_peer_registry_entries",
    "require_peer_synchronization_eligible",
]
