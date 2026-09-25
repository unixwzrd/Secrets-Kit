"""
secrets_kit.backends.sqlite.local_node

SQLite projection helpers for the singleton local node.

Every datastore represents one node. This module stores that node's public data
in ``nodes`` and local-only private-key references in ``node_private``. It
never stores raw private keys and does not wire identity state into CLI,
daemon, transport, synchronization, keychain, or export/import behavior.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from secrets_kit.backends.sqlite.local_hierarchy import (
    local_peer_group_display_name,
    local_peer_group_id_for_node,
)
from secrets_kit.crypto.models import NodeIdentity
from secrets_kit.identifiers import validate_identifier


@dataclass(frozen=True)
class LocalNodeProjection:
    """
    Singleton local node projection loaded from SQLite.

    The projection stores local operational authority state: node id, public
    keys, and private-key references.
    """

    node_id: str
    peer_group_id: str
    signing_public_key: bytes
    signing_private_key_reference: str
    encryption_public_key: bytes
    encryption_private_key_reference: str
    state: str
    created_at: str
    updated_at: str


def save_local_node_projection(
    *,
    conn: sqlite3.Connection,
    identity: NodeIdentity,
    signing_private_key_reference: str,
    encryption_private_key_reference: str,
) -> None:
    """
    Save the singleton local node projection.

    Callers pass the existing crypto-layer ``NodeIdentity`` as source material.
    The SQLite projection is operational node state, not a crypto object
    decomposition. Only public keys and private-key references are persisted.
    """
    if not isinstance(identity, NodeIdentity):
        raise TypeError("identity must be a NodeIdentity")
    validate_identifier(value=identity.node_id, expected_type="node", field="node_id")
    peer_group_id = local_peer_group_id_for_node(node_id=identity.node_id)
    validate_identifier(
        value=peer_group_id,
        expected_type="peer_group",
        field="peer_group_id",
    )
    _validate_reference(
        value=signing_private_key_reference,
        field_name="signing_private_key_reference",
    )
    _validate_reference(
        value=encryption_private_key_reference,
        field_name="encryption_private_key_reference",
    )
    created_at = _existing_node_created_at(conn=conn, node_id=identity.node_id) or min(
        identity.signing.metadata.created_at,
        identity.encryption.metadata.created_at,
    )
    updated_at = max(identity.signing.metadata.created_at, identity.encryption.metadata.created_at)

    conn.execute(
        """
        INSERT OR IGNORE INTO peer_groups (peer_group_id, name, operator_comment)
        VALUES (?, ?, ?)
        """,
        (
            peer_group_id,
            local_peer_group_display_name(peer_group_id=peer_group_id),
            "local SQLite node peer group",
        ),
    )
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            peer_group_id = excluded.peer_group_id,
            signing_public_key = excluded.signing_public_key,
            signing_algorithm = excluded.signing_algorithm,
            encryption_public_key = excluded.encryption_public_key,
            encryption_algorithm = excluded.encryption_algorithm,
            state = excluded.state,
            updated_at = excluded.updated_at
        """,
        (
            identity.node_id,
            peer_group_id,
            identity.signing.public_key,
            identity.signing.metadata.algorithm,
            identity.encryption.public_key,
            identity.encryption.metadata.algorithm,
            "active",
            created_at,
            updated_at,
        ),
    )
    conn.execute("DELETE FROM node_private WHERE node_id != ?", (identity.node_id,))
    conn.execute(
        """
        INSERT INTO node_private (
            node_id,
            signing_private_key_reference,
            encryption_private_key_reference
        ) VALUES (?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            signing_private_key_reference = excluded.signing_private_key_reference,
            encryption_private_key_reference = excluded.encryption_private_key_reference
        """,
        (
            identity.node_id,
            signing_private_key_reference,
            encryption_private_key_reference,
        ),
    )


def load_local_node_projection(*, conn: sqlite3.Connection) -> LocalNodeProjection | None:
    """
    Load the singleton local node projection.

    Returns ``None`` when this datastore has no local node row.
    """
    row = conn.execute(
        """
        SELECT
            nodes.node_id,
            nodes.peer_group_id,
            nodes.signing_public_key,
            node_private.signing_private_key_reference,
            nodes.encryption_public_key,
            node_private.encryption_private_key_reference,
            nodes.state,
            nodes.created_at,
            nodes.updated_at
        FROM node_private
        INNER JOIN nodes ON nodes.node_id = node_private.node_id
        ORDER BY nodes.node_id
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return None
    return LocalNodeProjection(
        node_id=str(row["node_id"]),
        peer_group_id=str(row["peer_group_id"]),
        signing_public_key=bytes(row["signing_public_key"]),
        signing_private_key_reference=str(row["signing_private_key_reference"]),
        encryption_public_key=bytes(row["encryption_public_key"]),
        encryption_private_key_reference=str(row["encryption_private_key_reference"]),
        state=str(row["state"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _existing_node_created_at(*, conn: sqlite3.Connection, node_id: str) -> str:
    row = conn.execute(
        "SELECT created_at FROM nodes WHERE node_id = ?",
        (node_id,),
    ).fetchone()
    if row is None:
        return ""
    return str(row["created_at"])


def _validate_reference(*, value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


__all__ = [
    "LocalNodeProjection",
    "load_local_node_projection",
    "save_local_node_projection",
]
