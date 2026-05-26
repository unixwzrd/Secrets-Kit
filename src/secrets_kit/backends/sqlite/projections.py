"""
secrets_kit.backends.sqlite.projections

Projection materialization helpers for SQLite replay.
"""

from __future__ import annotations

import base64
import binascii
import sqlite3
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.taxonomy import (
    resolve_entry_type_and_kind_ids,
    sync_secret_tags,
    tags_from_payload,
)

SET_REQUIRED_FIELDS = frozenset(
    {
        "secret_id",
        "owner_id",
        "service_group_id",
        "entry_type",
        "entry_kind",
        "locator_hash_b64",
        "encrypted_name_b64",
        "encrypted_payload_b64",
        "content_hash_b64",
    }
)
DELETE_REQUIRED_FIELDS = frozenset(
    {
        "secret_id",
        "owner_id",
        "service_group_id",
        "entry_type",
        "entry_kind",
        "locator_hash_b64",
        "encrypted_name_b64",
        "content_hash_b64",
    }
)


def _required_text(*, payload: Mapping[str, Any], field_name: str) -> str:
    """
    Return a required payload string field.

    Args:
        payload:
            Transaction payload mapping.
        field_name:
            Field to read.

    Returns:
        Required string field value.

    Raises:
        SQLiteValidationError:
            Field is absent or not a non-empty string.

    Side Effects:
        None.
    """
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field_name} is required")
    return value


def _optional_text(*, payload: Mapping[str, Any], field_name: str) -> str | None:
    """
    Return an optional payload string field.

    Args:
        payload:
            Transaction payload mapping.
        field_name:
            Field to read.

    Returns:
        String value or None.

    Raises:
        SQLiteValidationError:
            Field is present but not a string.

    Side Effects:
        None.
    """
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SQLiteValidationError(f"{field_name} must be a string")
    return value


def _optional_int(*, payload: Mapping[str, Any], field_name: str) -> int | None:
    """
    Return an optional payload integer field.

    Args:
        payload:
            Transaction payload mapping.
        field_name:
            Field to read.

    Returns:
        Integer value or None.

    Raises:
        SQLiteValidationError:
            Field is present but not an integer.

    Side Effects:
        None.
    """
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, int):
        raise SQLiteValidationError(f"{field_name} must be an integer")
    return value


def _required_b64(*, payload: Mapping[str, Any], field_name: str) -> bytes:
    """
    Decode a required base64 payload field.

    Args:
        payload:
            Transaction payload mapping.
        field_name:
            Field to decode.

    Returns:
        Decoded bytes.

    Raises:
        SQLiteValidationError:
            Field is absent, not a string, or invalid base64.

    Side Effects:
        None.
    """
    return _decode_b64(
        value=_required_text(payload=payload, field_name=field_name), field_name=field_name
    )


def _optional_b64(*, payload: Mapping[str, Any], field_name: str) -> bytes | None:
    """
    Decode an optional base64 payload field.

    Args:
        payload:
            Transaction payload mapping.
        field_name:
            Field to decode.

    Returns:
        Decoded bytes or None.

    Raises:
        SQLiteValidationError:
            Field is present but not a valid base64 string.

    Side Effects:
        None.
    """
    value = _optional_text(payload=payload, field_name=field_name)
    if value is None:
        return None
    return _decode_b64(value=value, field_name=field_name)


def _decode_b64(*, value: str, field_name: str) -> bytes:
    """
    Decode a base64 string using strict validation.

    Args:
        value:
            Base64 text.
        field_name:
            Field name for validation errors.

    Returns:
        Decoded bytes.

    Raises:
        SQLiteValidationError:
            Value is invalid base64.

    Side Effects:
        None.
    """
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise SQLiteValidationError(f"{field_name} must be valid base64") from exc


def _validate_required_fields(
    *, payload: Mapping[str, Any], required_fields: frozenset[str]
) -> None:
    """
    Validate that all required payload fields are present.

    Args:
        payload:
            Transaction payload mapping.
        required_fields:
            Required field names.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            A required field is missing.

    Side Effects:
        None.
    """
    for field_name in sorted(required_fields):
        if field_name not in payload:
            raise SQLiteValidationError(f"{field_name} is required")


def apply_secret_set_projection(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """
    Materialize a ``secret.set`` transaction into the secrets projection.

    Args:
        conn:
            SQLite connection.
        transaction:
            Canonical transaction.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Projection payload is invalid.
        sqlite3.Error:
            SQLite write failure.

    Side Effects:
        Inserts or replaces one derived secrets projection row.
    """
    payload = transaction.payload
    _validate_required_fields(payload=payload, required_fields=SET_REQUIRED_FIELDS)
    projection_created_at = (
        _optional_text(payload=payload, field_name="projection_created_at")
        or transaction.created_at
    )
    projection_updated_at = (
        _optional_text(payload=payload, field_name="projection_updated_at")
        or transaction.created_at
    )
    entry_type_name = _required_text(payload=payload, field_name="entry_type")
    entry_kind_name = _required_text(payload=payload, field_name="entry_kind")
    secret_id = _required_text(payload=payload, field_name="secret_id")
    entry_type_id, entry_kind_id = resolve_entry_type_and_kind_ids(
        conn=conn,
        entry_type=entry_type_name,
        entry_kind=entry_kind_name,
    )
    conn.execute(
        """
        INSERT INTO secrets (
            secret_id,
            owner_id,
            service_group_id,
            entry_type_id,
            entry_kind_id,
            schema_id,
            schema_version,
            locator_hash,
            encrypted_name,
            encrypted_metadata,
            encrypted_payload,
            content_hash,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(secret_id) DO UPDATE SET
            owner_id = excluded.owner_id,
            service_group_id = excluded.service_group_id,
            entry_type_id = excluded.entry_type_id,
            entry_kind_id = excluded.entry_kind_id,
            schema_id = excluded.schema_id,
            schema_version = excluded.schema_version,
            locator_hash = excluded.locator_hash,
            encrypted_name = excluded.encrypted_name,
            encrypted_metadata = excluded.encrypted_metadata,
            encrypted_payload = excluded.encrypted_payload,
            content_hash = excluded.content_hash,
            state = excluded.state,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at
        """,
        (
            _required_text(payload=payload, field_name="secret_id"),
            _required_text(payload=payload, field_name="owner_id"),
            _required_text(payload=payload, field_name="service_group_id"),
            entry_type_id,
            entry_kind_id,
            _optional_text(payload=payload, field_name="schema_id"),
            _optional_int(payload=payload, field_name="schema_version"),
            _required_b64(payload=payload, field_name="locator_hash_b64"),
            _required_b64(payload=payload, field_name="encrypted_name_b64"),
            _optional_b64(payload=payload, field_name="encrypted_metadata_b64"),
            _required_b64(payload=payload, field_name="encrypted_payload_b64"),
            _required_b64(payload=payload, field_name="content_hash_b64"),
            "active",
            projection_created_at,
            projection_updated_at,
        ),
    )
    sync_secret_tags(conn=conn, secret_id=secret_id, tags=tags_from_payload(payload=payload))


def apply_secret_delete_projection(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """
    Materialize a ``secret.delete`` transaction into a deleted tombstone.

    Args:
        conn:
            SQLite connection.
        transaction:
            Canonical transaction.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Projection payload is invalid.
        sqlite3.Error:
            SQLite write failure.

    Side Effects:
        Inserts or replaces one derived deleted secrets projection row.
    """
    payload = transaction.payload
    _validate_required_fields(payload=payload, required_fields=DELETE_REQUIRED_FIELDS)
    projection_updated_at = (
        _optional_text(payload=payload, field_name="projection_updated_at")
        or transaction.created_at
    )
    encrypted_payload = _optional_b64(payload=payload, field_name="encrypted_payload_b64") or b""
    entry_type_name = _required_text(payload=payload, field_name="entry_type")
    entry_kind_name = _required_text(payload=payload, field_name="entry_kind")
    secret_id = _required_text(payload=payload, field_name="secret_id")
    entry_type_id, entry_kind_id = resolve_entry_type_and_kind_ids(
        conn=conn,
        entry_type=entry_type_name,
        entry_kind=entry_kind_name,
    )
    conn.execute(
        """
        INSERT INTO secrets (
            secret_id,
            owner_id,
            service_group_id,
            entry_type_id,
            entry_kind_id,
            schema_id,
            schema_version,
            locator_hash,
            encrypted_name,
            encrypted_metadata,
            encrypted_payload,
            content_hash,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(secret_id) DO UPDATE SET
            owner_id = excluded.owner_id,
            service_group_id = excluded.service_group_id,
            entry_type_id = excluded.entry_type_id,
            entry_kind_id = excluded.entry_kind_id,
            schema_id = excluded.schema_id,
            schema_version = excluded.schema_version,
            locator_hash = excluded.locator_hash,
            encrypted_name = excluded.encrypted_name,
            encrypted_metadata = excluded.encrypted_metadata,
            encrypted_payload = excluded.encrypted_payload,
            content_hash = excluded.content_hash,
            state = excluded.state,
            created_at = secrets.created_at,
            updated_at = excluded.updated_at
        """,
        (
            _required_text(payload=payload, field_name="secret_id"),
            _required_text(payload=payload, field_name="owner_id"),
            _required_text(payload=payload, field_name="service_group_id"),
            entry_type_id,
            entry_kind_id,
            _optional_text(payload=payload, field_name="schema_id"),
            _optional_int(payload=payload, field_name="schema_version"),
            _required_b64(payload=payload, field_name="locator_hash_b64"),
            _required_b64(payload=payload, field_name="encrypted_name_b64"),
            _optional_b64(payload=payload, field_name="encrypted_metadata_b64"),
            encrypted_payload,
            _required_b64(payload=payload, field_name="content_hash_b64"),
            "deleted",
            transaction.created_at,
            projection_updated_at,
        ),
    )
    sync_secret_tags(conn=conn, secret_id=secret_id, tags=[])


__all__ = [
    "apply_secret_delete_projection",
    "apply_secret_set_projection",
]
