"""
secrets_kit.backends.sqlite.replay_support

Deterministic local support rows required by replay/imported transaction history.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.local_hierarchy import (
    LOCAL_CLIENT_ID,
    LOCAL_ORGANIZATION_ID,
    local_peer_group_display_name,
    local_peer_group_id_for_node,
)
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier


@dataclass(frozen=True)
class _ReplaySupportRows:
    origin_node_ids: frozenset[str]
    owner_ids: frozenset[str]
    service_groups: Mapping[str, str]


def bootstrap_replay_support_rows(
    *, conn: sqlite3.Connection, transactions: Iterable[Transaction]
) -> None:
    """
    Ensure deterministic local support rows required before local replay.

    Side Effects:
        Inserts minimal local parent rows needed by transaction and secret
        projection foreign keys.
    """
    history = list(transactions)
    support = _replay_support_rows(transactions=history)
    if not support.origin_node_ids and not support.owner_ids and not support.service_groups:
        return

    conn.execute(
        """
        INSERT OR IGNORE INTO business_organizations (organization_id, operator_comment)
        VALUES (?, ?)
        """,
        (LOCAL_ORGANIZATION_ID, "local SQLite replay support"),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO business_clients (client_id, organization_id, operator_comment)
        VALUES (?, ?, ?)
        """,
        (LOCAL_CLIENT_ID, LOCAL_ORGANIZATION_ID, "local SQLite replay support"),
    )
    for owner_id in sorted(support.owner_ids):
        conn.execute(
            """
            INSERT OR IGNORE INTO owners (owner_id, client_id, operator_comment)
            VALUES (?, ?, ?)
            """,
            (owner_id, LOCAL_CLIENT_ID, "local SQLite replay support"),
        )
    for node_id in sorted(support.origin_node_ids):
        peer_group_id = local_peer_group_id_for_node(node_id=node_id)
        conn.execute(
            """
            INSERT OR IGNORE INTO peer_groups (peer_group_id, name, operator_comment)
            VALUES (?, ?, ?)
            """,
            (
                peer_group_id,
                local_peer_group_display_name(peer_group_id=peer_group_id),
                "local SQLite replay support",
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO nodes (
                node_id,
                peer_group_id,
                signing_public_key,
                signing_algorithm,
                encryption_public_key,
                encryption_algorithm,
                state,
                operator_comment
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node_id,
                peer_group_id,
                bytes(32),
                "ed25519",
                bytes(32),
                "x25519",
                "active",
                "local SQLite replay support",
            ),
        )
    for service_group_id, owner_id in sorted(support.service_groups.items()):
        conn.execute(
            """
            INSERT OR IGNORE INTO service_groups (
                service_group_id,
                owner_id,
                operator_comment
            )
            VALUES (?, ?, ?)
            """,
            (service_group_id, owner_id, "local SQLite replay support"),
        )


def _replay_support_rows(*, transactions: Iterable[Transaction]) -> _ReplaySupportRows:
    origin_node_ids: set[str] = set()
    owner_ids: set[str] = set()
    service_groups: dict[str, str] = {}

    for transaction in transactions:
        if transaction.origin_node_id:
            _validate_identifier(
                value=transaction.origin_node_id,
                expected_type="node",
                field_name="origin_node_id",
            )
            origin_node_ids.add(transaction.origin_node_id)
        if transaction.owner_id:
            _validate_identifier(
                value=transaction.owner_id,
                expected_type="owner",
                field_name="owner_id",
            )
            owner_ids.add(transaction.owner_id)
        if transaction.transaction_type not in {"secret.set", "secret.delete"}:
            continue
        owner_id = _payload_text(transaction.payload, "owner_id")
        service_group_id = _payload_text(transaction.payload, "service_group_id")
        if owner_id is None or service_group_id is None:
            continue
        _validate_identifier(value=owner_id, expected_type="owner", field_name="owner_id")
        _validate_identifier(
            value=service_group_id,
            expected_type="service_group",
            field_name="service_group_id",
        )
        owner_ids.add(owner_id)
        existing_owner_id = service_groups.setdefault(service_group_id, owner_id)
        if existing_owner_id != owner_id:
            raise SQLiteValidationError(
                f"service_group_id maps to multiple owners during replay: {service_group_id}"
            )

    return _ReplaySupportRows(
        origin_node_ids=frozenset(origin_node_ids),
        owner_ids=frozenset(owner_ids),
        service_groups=service_groups,
    )


def _payload_text(payload: Mapping[str, Any], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field_name} must be a non-empty string")
    return value


def _validate_identifier(*, value: str, expected_type: str, field_name: str) -> None:
    try:
        validate_identifier(
            value=value,
            expected_type=expected_type,  # type: ignore[arg-type]
            field=field_name,
        )
    except IdentifierValidationError as exc:
        raise SQLiteValidationError(str(exc)) from exc



__all__ = ["bootstrap_replay_support_rows"]
