"""
secrets_kit.backends.sqlite.peer_admission_projection

Projection materialization for peer admission transactions.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_registry import (
    AUTHORIZATION_MODE_ALL,
    AUTHORIZATION_MODE_ALLOW_LIST,
    AUTHORIZATION_MODE_NONE,
    AUTHORIZATION_MODES,
)
from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier

ADMISSION_STATE_REQUESTED = "admission_requested"
ADMISSION_STATE_ACTIVE = "active"
ADMISSION_STATE_REJECTED = "rejected"
PEER_ADMISSION_GROUP_ID = "peer-group:admission"

REQUEST_REQUIRED_FIELDS = frozenset(
    {
        "node_id",
        "signing_public_key",
        "signing_algorithm",
        "encryption_public_key",
        "encryption_algorithm",
    }
)
DECISION_REQUIRED_FIELDS = frozenset({"node_id"})


def apply_peer_admission_request(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    payload = transaction.payload
    _validate_required_fields(payload=payload, required_fields=REQUEST_REQUIRED_FIELDS)
    node_id = _required_text(payload=payload, field_name="node_id")
    signing_algorithm = _required_text(payload=payload, field_name="signing_algorithm")
    encryption_algorithm = _required_text(payload=payload, field_name="encryption_algorithm")
    if signing_algorithm != "ed25519":
        raise SQLiteValidationError("signing_algorithm must be ed25519")
    if encryption_algorithm != "x25519":
        raise SQLiteValidationError("encryption_algorithm must be x25519")
    signing_public_key = _required_public_key(payload=payload, field_name="signing_public_key")
    encryption_public_key = _required_public_key(
        payload=payload, field_name="encryption_public_key"
    )
    _validate_signing_public_key(value=signing_public_key)
    _validate_encryption_public_key(value=encryption_public_key)
    if signing_public_key == encryption_public_key:
        raise SQLiteValidationError("signing_public_key and encryption_public_key must differ")
    requested_at = _optional_text(payload=payload, field_name="requested_at") or _required_text(
        payload=payload,
        field_name="created_at",
    )
    existing = _node_row(conn=conn, node_id=node_id)
    if existing is not None and not _is_replay_support_placeholder(row=existing):
        raise SQLiteValidationError(f"duplicate peer admission request: {node_id}")
    _ensure_peer_admission_group(conn=conn)
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            authorization_mode,
            service_address,
            operator_description,
            state,
            created_at,
            updated_at,
            operator_comment
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            peer_group_id = excluded.peer_group_id,
            signing_public_key = excluded.signing_public_key,
            signing_algorithm = excluded.signing_algorithm,
            encryption_public_key = excluded.encryption_public_key,
            encryption_algorithm = excluded.encryption_algorithm,
            authorization_mode = excluded.authorization_mode,
            service_address = excluded.service_address,
            operator_description = excluded.operator_description,
            state = excluded.state,
            updated_at = excluded.updated_at,
            operator_comment = excluded.operator_comment
        """,
        (
            node_id,
            PEER_ADMISSION_GROUP_ID,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            AUTHORIZATION_MODE_NONE,
            _optional_text(payload=payload, field_name="service_address"),
            _optional_text(payload=payload, field_name="operator_description"),
            ADMISSION_STATE_REQUESTED,
            requested_at,
            requested_at,
            _optional_text(payload=payload, field_name="operator_comment"),
        ),
    )


def apply_peer_admission_accept(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    _apply_peer_admission_decision(
        conn=conn,
        transaction=transaction,
        target_state=ADMISSION_STATE_ACTIVE,
        timestamp_field="accepted_at",
        unknown_message="cannot accept unknown peer admission request",
        already_message="peer admission already accepted",
    )


def apply_peer_admission_reject(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    _apply_peer_admission_decision(
        conn=conn,
        transaction=transaction,
        target_state=ADMISSION_STATE_REJECTED,
        timestamp_field="rejected_at",
        unknown_message="cannot reject unknown peer admission request",
        already_message="peer admission already rejected",
    )


def _apply_peer_admission_decision(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
    target_state: str,
    timestamp_field: str,
    unknown_message: str,
    already_message: str,
) -> None:
    payload = transaction.payload
    _validate_required_fields(payload=payload, required_fields=DECISION_REQUIRED_FIELDS)
    node_id = _required_text(payload=payload, field_name="node_id")
    state = _node_state(conn=conn, node_id=node_id)
    if state is None:
        raise SQLiteValidationError(f"{unknown_message}: {node_id}")
    if state == target_state:
        raise SQLiteValidationError(f"{already_message}: {node_id}")
    if state != ADMISSION_STATE_REQUESTED:
        raise SQLiteValidationError(
            f"peer admission request is not pending: {node_id} state={state}"
        )
    decided_at = _optional_text(payload=payload, field_name=timestamp_field) or transaction.created_at
    conn.execute(
        """
        UPDATE nodes
        SET
            state = ?,
            updated_at = ?,
            operator_description = COALESCE(?, operator_description),
            operator_comment = COALESCE(?, operator_comment),
            authorization_mode = ?
        WHERE node_id = ?
        """,
        (
            target_state,
            decided_at,
            _optional_text(payload=payload, field_name="display_name"),
            _optional_text(payload=payload, field_name="operator_comment"),
            _authorization_mode_for_decision(payload=payload, target_state=target_state),
            node_id,
        ),
    )
    if target_state == ADMISSION_STATE_ACTIVE:
        _apply_service_group_authorization(
            conn=conn,
            node_id=node_id,
            service_group_ids=_optional_text_list(payload=payload, field_name="service_group_ids"),
            timestamp=decided_at,
        )


def _ensure_peer_admission_group(*, conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO peer_groups (peer_group_id, name, state, operator_comment)
        VALUES (?, ?, ?, ?)
        """,
        (
            PEER_ADMISSION_GROUP_ID,
            "Peer admission",
            "active",
            "Canonical peer admission projection",
        ),
    )


def _node_state(*, conn: sqlite3.Connection, node_id: str) -> str | None:
    row = _node_row(conn=conn, node_id=node_id)
    if row is None:
        return None
    return str(row["state"] or "")


def _node_row(*, conn: sqlite3.Connection, node_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT state, signing_public_key, encryption_public_key, operator_comment
        FROM nodes
        WHERE node_id = ?
        """,
        (node_id,),
    ).fetchone()


def _is_replay_support_placeholder(*, row: sqlite3.Row) -> bool:
    signing_public_key = row["signing_public_key"]
    encryption_public_key = row["encryption_public_key"]
    return (
        bytes(signing_public_key or b"") == bytes(32)
        and bytes(encryption_public_key or b"") == bytes(32)
        and str(row["operator_comment"] or "") == "local SQLite replay support"
    )


def _required_public_key(*, payload: Mapping[str, Any], field_name: str) -> bytes:
    encoded = _required_text(payload=payload, field_name=field_name)
    try:
        value = decode_b64url(encoded)
    except ValueError as exc:
        raise SQLiteValidationError(f"{field_name} must be base64url public key bytes") from exc
    if len(value) != 32:
        raise SQLiteValidationError(f"{field_name} must decode to 32 bytes")
    return value


def _validate_signing_public_key(*, value: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(value)
    except ValueError as exc:
        raise SQLiteValidationError("signing_public_key is not a valid Ed25519 public key") from exc


def _validate_encryption_public_key(*, value: bytes) -> None:
    try:
        X25519PublicKey.from_public_bytes(value)
    except ValueError as exc:
        raise SQLiteValidationError("encryption_public_key is not a valid X25519 public key") from exc


def _required_text(*, payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field_name} is required")
    return value


def _optional_text(*, payload: Mapping[str, Any], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SQLiteValidationError(f"{field_name} must be a string")
    return value


def _optional_text_list(*, payload: Mapping[str, Any], field_name: str) -> tuple[str, ...]:
    value = payload.get(field_name)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SQLiteValidationError(f"{field_name} must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise SQLiteValidationError(f"{field_name} entries must be non-empty strings")
        result.append(item)
    return tuple(result)


def _authorization_mode_for_decision(
    *, payload: Mapping[str, Any], target_state: str
) -> str:
    if target_state != ADMISSION_STATE_ACTIVE:
        return AUTHORIZATION_MODE_NONE
    mode = _optional_text(payload=payload, field_name="authorization_mode")
    if mode is None:
        return AUTHORIZATION_MODE_NONE
    if mode not in AUTHORIZATION_MODES:
        raise SQLiteValidationError(f"authorization_mode is unsupported: {mode}")
    service_group_ids = _optional_text_list(payload=payload, field_name="service_group_ids")
    if mode == AUTHORIZATION_MODE_ALL and service_group_ids:
        raise SQLiteValidationError(
            "authorization_mode all cannot include service_group_ids"
        )
    if mode == AUTHORIZATION_MODE_NONE and service_group_ids:
        raise SQLiteValidationError(
            "authorization_mode none cannot include service_group_ids"
        )
    if mode == AUTHORIZATION_MODE_ALLOW_LIST:
        return AUTHORIZATION_MODE_ALLOW_LIST
    return mode


def _apply_service_group_authorization(
    *,
    conn: sqlite3.Connection,
    node_id: str,
    service_group_ids: tuple[str, ...],
    timestamp: str,
) -> None:
    for service_group_id in service_group_ids:
        try:
            validate_identifier(
                value=service_group_id,
                expected_type="service_group",
                field="service_group_id",
            )
        except IdentifierValidationError as exc:
            raise SQLiteValidationError(str(exc)) from exc
        conn.execute(
            """
            INSERT OR IGNORE INTO service_groups (service_group_id, state, operator_comment)
            VALUES (?, ?, ?)
            """,
            (service_group_id, "active", "peer registry authorization"),
        )
        conn.execute(
            """
            INSERT INTO service_group_nodes (
                service_group_id,
                node_id,
                state,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(service_group_id, node_id) DO UPDATE SET
                state = excluded.state,
                updated_at = excluded.updated_at
            """,
            (service_group_id, node_id, "active", timestamp, timestamp),
        )


def _validate_required_fields(
    *, payload: Mapping[str, Any], required_fields: frozenset[str]
) -> None:
    for field_name in sorted(required_fields):
        if field_name not in payload:
            raise SQLiteValidationError(f"{field_name} is required")


__all__ = [
    "ADMISSION_STATE_ACTIVE",
    "ADMISSION_STATE_REJECTED",
    "ADMISSION_STATE_REQUESTED",
    "PEER_ADMISSION_GROUP_ID",
    "apply_peer_admission_accept",
    "apply_peer_admission_reject",
    "apply_peer_admission_request",
]
