"""
secrets_kit.backends.sqlite.peer_nodes

SQLite projection helpers for remote peer communication endpoints.

Remote peers are nodes this datastore can communicate with. They are not
managed local resources, key custody records, discovery state, transport
sessions, trust decisions, or relay topology. Peer-group rows support routing;
service-group rows support secret distribution targeting.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from secrets_kit.crypto.peer_models import PeerIdentity
from secrets_kit.models import now_utc_iso


@dataclass(frozen=True)
class PeerNodeProjection:
    """
    Remote peer node endpoint projection.

    The projection stores public communication metadata only. It does not store
    peer private keys, key references, custody state, runtime metadata,
    discovery state, trust state, or key-rotation schedules.
    """

    node_id: str
    service_address: str
    signing_public_key: bytes
    signing_algorithm: str
    encryption_public_key: bytes
    encryption_algorithm: str
    operator_description: str
    last_seen_at: str
    state: str
    created_at: str
    updated_at: str
    peer_group_id: str
    service_group_ids: tuple[str, ...]


def save_peer_node_projection(
    *,
    conn: sqlite3.Connection,
    identity: PeerIdentity,
    peer_group_id: str,
    service_address: str,
    service_group_ids: tuple[str, ...] = (),
    operator_description: str = "",
    last_seen_at: str = "",
) -> None:
    """
    Save one remote peer node endpoint projection.

    Callers pass the existing crypto-layer ``PeerIdentity`` as source material
    for the node id and public keys. SQLite stores the operational endpoint row
    and routing/distribution relationships; it does not decompose or own the
    crypto peer model.
    """
    if not isinstance(identity, PeerIdentity):
        raise TypeError("identity must be a PeerIdentity")
    _validate_required_text(value=peer_group_id, field_name="peer_group_id")
    _validate_required_text(value=service_address, field_name="service_address")
    _validate_optional_text(value=operator_description, field_name="operator_description")
    _validate_optional_text(value=last_seen_at, field_name="last_seen_at")
    for service_group_id in service_group_ids:
        _validate_required_text(value=service_group_id, field_name="service_group_id")

    now = now_utc_iso()
    created_at = _existing_created_at(conn=conn, node_id=identity.node_id) or now
    conn.execute(
        "INSERT OR IGNORE INTO peer_groups (peer_group_id) VALUES (?)",
        (peer_group_id,),
    )
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            service_address,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            operator_description,
            last_seen_at,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            peer_group_id = excluded.peer_group_id,
            service_address = excluded.service_address,
            signing_public_key = excluded.signing_public_key,
            signing_algorithm = excluded.signing_algorithm,
            encryption_public_key = excluded.encryption_public_key,
            encryption_algorithm = excluded.encryption_algorithm,
            operator_description = excluded.operator_description,
            last_seen_at = excluded.last_seen_at,
            state = excluded.state,
            updated_at = excluded.updated_at
        """,
        (
            identity.node_id,
            peer_group_id,
            service_address,
            identity.public_keys.signing_public_key,
            identity.public_keys.signing_algorithm,
            identity.public_keys.encryption_public_key,
            identity.public_keys.encryption_algorithm,
            operator_description,
            last_seen_at,
            "active",
            created_at,
            now,
        ),
    )
    conn.execute(
        "DELETE FROM service_group_nodes WHERE node_id = ?",
        (identity.node_id,),
    )
    for service_group_id in service_group_ids:
        conn.execute(
            """
            INSERT INTO service_group_nodes (
                node_id,
                service_group_id,
                state,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (identity.node_id, service_group_id, "active", now, now),
        )


def load_peer_node_projection(
    *,
    conn: sqlite3.Connection,
    node_id: str,
) -> PeerNodeProjection | None:
    """
    Load one remote peer node endpoint projection.

    Returns ``None`` when no peer node row exists.
    """
    _validate_required_text(value=node_id, field_name="node_id")
    row = conn.execute(
        """
        SELECT
            node_id,
            peer_group_id,
            service_address,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            operator_description,
            last_seen_at,
            state,
            created_at,
            updated_at
        FROM nodes
        WHERE node_id = ?
        """,
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return PeerNodeProjection(
        node_id=str(row["node_id"]),
        peer_group_id=str(row["peer_group_id"]),
        service_address=str(row["service_address"]),
        signing_public_key=bytes(row["signing_public_key"]),
        signing_algorithm=str(row["signing_algorithm"]),
        encryption_public_key=bytes(row["encryption_public_key"]),
        encryption_algorithm=str(row["encryption_algorithm"]),
        operator_description=str(row["operator_description"]),
        last_seen_at=str(row["last_seen_at"]),
        state=str(row["state"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        service_group_ids=_service_group_ids(conn=conn, node_id=node_id),
    )


def _existing_created_at(*, conn: sqlite3.Connection, node_id: str) -> str:
    row = conn.execute(
        "SELECT created_at FROM nodes WHERE node_id = ?",
        (node_id,),
    ).fetchone()
    if row is None:
        return ""
    return str(row["created_at"])


def _service_group_ids(*, conn: sqlite3.Connection, node_id: str) -> tuple[str, ...]:
    rows = conn.execute(
        """
        SELECT service_group_id
        FROM service_group_nodes
        WHERE node_id = ?
        ORDER BY service_group_id
        """,
        (node_id,),
    ).fetchall()
    return tuple(str(row["service_group_id"]) for row in rows)


def _validate_required_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


def _validate_optional_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


__all__ = [
    "PeerNodeProjection",
    "load_peer_node_projection",
    "save_peer_node_projection",
]
