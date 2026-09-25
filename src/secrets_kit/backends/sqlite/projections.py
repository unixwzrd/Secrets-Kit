"""
secrets_kit.backends.sqlite.projections

Projection materialization helpers for SQLite replay.
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.storage_mode import read_sqlite_storage_mode
from secrets_kit.backends.sqlite.taxonomy import (
    resolve_entry_type_and_kind_ids,
    sync_secret_tags,
    tags_from_payload,
)
from secrets_kit.crypto.storage.sqlite import decrypt_payload as decrypt_storage_payload
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier

SET_REQUIRED_FIELDS = frozenset(
    {
        "secret_id",
        "owner_id",
        "service_group_id",
        "entry_type",
        "entry_kind",
        "service",
        "account",
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
        "service",
        "account",
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


def _required_identifier(*, payload: Mapping[str, Any], field_name: str, expected_type: str) -> str:
    value = _required_text(payload=payload, field_name=field_name)
    return _validate_identifier(value=value, field_name=field_name, expected_type=expected_type)


def _optional_identifier(
    *, payload: Mapping[str, Any], field_name: str, expected_type: str
) -> str | None:
    value = _optional_text(payload=payload, field_name=field_name)
    if value is None:
        return None
    return _validate_identifier(value=value, field_name=field_name, expected_type=expected_type)


def _validate_identifier(*, value: str, field_name: str, expected_type: str) -> str:
    try:
        return validate_identifier(
            value=value,
            expected_type=expected_type,  # type: ignore[arg-type]
            field=field_name,
        )
    except IdentifierValidationError as exc:
        raise SQLiteValidationError(str(exc)) from exc


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
    if isinstance(value, bool) or not isinstance(value, int):
        raise SQLiteValidationError(f"{field_name} must be an integer")
    return value


def _text_list(*, payload: Mapping[str, Any], field_name: str) -> list[str]:
    value = payload.get(field_name, [])
    if not isinstance(value, list):
        raise SQLiteValidationError(f"{field_name} must be a list")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SQLiteValidationError(f"{field_name} must contain non-empty strings")
        items.append(item)
    return items


def _custom_metadata(*, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    value = payload.get("custom", {})
    if not isinstance(value, Mapping):
        raise SQLiteValidationError("custom must be an object")
    for key in value:
        if not isinstance(key, str) or not key:
            raise SQLiteValidationError("custom keys must be non-empty strings")
    return value


def _canonical_json_text(*, value: Any, field_name: str) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SQLiteValidationError(f"{field_name} must be canonical JSON serializable") from exc


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


def _write_domains(
    *, conn: sqlite3.Connection, secret_id: str, domains: list[str], created_at: str
) -> None:
    conn.execute("DELETE FROM secret_domains WHERE secret_id = ?", (secret_id,))
    for domain in sorted(set(domains)):
        conn.execute(
            """
            INSERT INTO secret_domains (secret_id, domain, created_at)
            VALUES (?, ?, ?)
            """,
            (secret_id, domain, created_at),
        )


def _write_custom_metadata(
    *, conn: sqlite3.Connection, secret_id: str, custom: Mapping[str, Any], created_at: str
) -> None:
    conn.execute("DELETE FROM secret_custom_metadata WHERE secret_id = ?", (secret_id,))
    for key in sorted(custom):
        conn.execute(
            """
            INSERT INTO secret_custom_metadata (
                secret_id, metadata_key, metadata_value, created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                secret_id,
                key,
                _canonical_json_text(value=custom[key], field_name=f"custom[{key!r}]"),
                created_at,
            ),
        )


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
    secret_id = _required_identifier(
        payload=payload, field_name="secret_id", expected_type="secret"
    )
    encrypted_name = _required_b64(payload=payload, field_name="encrypted_name_b64")
    encrypted_payload = _required_b64(payload=payload, field_name="encrypted_payload_b64")
    storage_mode = read_sqlite_storage_mode(conn=conn)
    _validate_stored_payload(
        stored=encrypted_payload,
        field_name="encrypted_payload",
        storage_mode=storage_mode,
    )
    domains = _text_list(payload=payload, field_name="domains")
    custom = _custom_metadata(payload=payload)
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
            name,
            service,
            account,
            source,
            comment,
            source_url,
            source_label,
            rotation_days,
            rotation_warn_days,
            last_rotated_at,
            expires_at,
            locator_hash,
            encrypted_name,
            encrypted_payload,
            content_hash,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(secret_id) DO UPDATE SET
            owner_id = excluded.owner_id,
            service_group_id = excluded.service_group_id,
            entry_type_id = excluded.entry_type_id,
            entry_kind_id = excluded.entry_kind_id,
            schema_id = excluded.schema_id,
            schema_version = excluded.schema_version,
            name = excluded.name,
            service = excluded.service,
            account = excluded.account,
            source = excluded.source,
            comment = excluded.comment,
            source_url = excluded.source_url,
            source_label = excluded.source_label,
            rotation_days = excluded.rotation_days,
            rotation_warn_days = excluded.rotation_warn_days,
            last_rotated_at = excluded.last_rotated_at,
            expires_at = excluded.expires_at,
            locator_hash = excluded.locator_hash,
            encrypted_name = excluded.encrypted_name,
            encrypted_payload = excluded.encrypted_payload,
            content_hash = excluded.content_hash,
            state = excluded.state,
            created_at = secrets.created_at,
            updated_at = excluded.updated_at
        """,
        (
            secret_id,
            _required_identifier(payload=payload, field_name="owner_id", expected_type="owner"),
            _required_identifier(
                payload=payload,
                field_name="service_group_id",
                expected_type="service_group",
            ),
            entry_type_id,
            entry_kind_id,
            _optional_identifier(payload=payload, field_name="schema_id", expected_type="schema"),
            _optional_int(payload=payload, field_name="schema_version"),
            _projection_name(
                payload=payload,
                encrypted_name=encrypted_name,
                storage_mode=storage_mode,
            ),
            _required_text(payload=payload, field_name="service"),
            _required_text(payload=payload, field_name="account"),
            _optional_text(payload=payload, field_name="source") or "manual",
            _optional_text(payload=payload, field_name="comment") or "",
            _optional_text(payload=payload, field_name="source_url") or "",
            _optional_text(payload=payload, field_name="source_label") or "",
            _optional_int(payload=payload, field_name="rotation_days"),
            _optional_int(payload=payload, field_name="rotation_warn_days"),
            _optional_text(payload=payload, field_name="last_rotated_at") or "",
            _optional_text(payload=payload, field_name="expires_at") or "",
            _required_b64(payload=payload, field_name="locator_hash_b64"),
            encrypted_name,
            encrypted_payload,
            _required_b64(payload=payload, field_name="content_hash_b64"),
            "active",
            projection_created_at,
            projection_updated_at,
        ),
    )
    sync_secret_tags(conn=conn, secret_id=secret_id, tags=tags_from_payload(payload=payload))
    _write_domains(
        conn=conn, secret_id=secret_id, domains=domains, created_at=projection_updated_at
    )
    _write_custom_metadata(
        conn=conn, secret_id=secret_id, custom=custom, created_at=projection_updated_at
    )


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
    encrypted_name = _required_b64(payload=payload, field_name="encrypted_name_b64")
    storage_mode = read_sqlite_storage_mode(conn=conn)
    if encrypted_payload:
        _validate_stored_payload(
            stored=encrypted_payload,
            field_name="encrypted_payload",
            storage_mode=storage_mode,
        )
    entry_type_name = _required_text(payload=payload, field_name="entry_type")
    entry_kind_name = _required_text(payload=payload, field_name="entry_kind")
    secret_id = _required_identifier(
        payload=payload, field_name="secret_id", expected_type="secret"
    )
    domains = _text_list(payload=payload, field_name="domains")
    custom = _custom_metadata(payload=payload)
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
            name,
            service,
            account,
            source,
            comment,
            source_url,
            source_label,
            rotation_days,
            rotation_warn_days,
            last_rotated_at,
            expires_at,
            locator_hash,
            encrypted_name,
            encrypted_payload,
            content_hash,
            state,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(secret_id) DO UPDATE SET
            owner_id = excluded.owner_id,
            service_group_id = excluded.service_group_id,
            entry_type_id = excluded.entry_type_id,
            entry_kind_id = excluded.entry_kind_id,
            schema_id = excluded.schema_id,
            schema_version = excluded.schema_version,
            name = excluded.name,
            service = excluded.service,
            account = excluded.account,
            source = excluded.source,
            comment = excluded.comment,
            source_url = excluded.source_url,
            source_label = excluded.source_label,
            rotation_days = excluded.rotation_days,
            rotation_warn_days = excluded.rotation_warn_days,
            last_rotated_at = excluded.last_rotated_at,
            expires_at = excluded.expires_at,
            locator_hash = excluded.locator_hash,
            encrypted_name = excluded.encrypted_name,
            encrypted_payload = excluded.encrypted_payload,
            content_hash = excluded.content_hash,
            state = excluded.state,
            created_at = secrets.created_at,
            updated_at = excluded.updated_at
        """,
        (
            secret_id,
            _required_identifier(payload=payload, field_name="owner_id", expected_type="owner"),
            _required_identifier(
                payload=payload,
                field_name="service_group_id",
                expected_type="service_group",
            ),
            entry_type_id,
            entry_kind_id,
            _optional_identifier(payload=payload, field_name="schema_id", expected_type="schema"),
            _optional_int(payload=payload, field_name="schema_version"),
            _projection_name(
                payload=payload,
                encrypted_name=encrypted_name,
                storage_mode=storage_mode,
            ),
            _required_text(payload=payload, field_name="service"),
            _required_text(payload=payload, field_name="account"),
            _optional_text(payload=payload, field_name="source") or "manual",
            _optional_text(payload=payload, field_name="comment") or "",
            _optional_text(payload=payload, field_name="source_url") or "",
            _optional_text(payload=payload, field_name="source_label") or "",
            _optional_int(payload=payload, field_name="rotation_days"),
            _optional_int(payload=payload, field_name="rotation_warn_days"),
            _optional_text(payload=payload, field_name="last_rotated_at") or "",
            _optional_text(payload=payload, field_name="expires_at") or "",
            _required_b64(payload=payload, field_name="locator_hash_b64"),
            encrypted_name,
            encrypted_payload,
            _required_b64(payload=payload, field_name="content_hash_b64"),
            "deleted",
            transaction.created_at,
            projection_updated_at,
        ),
    )
    sync_secret_tags(conn=conn, secret_id=secret_id, tags=tags_from_payload(payload=payload))
    _write_domains(
        conn=conn, secret_id=secret_id, domains=domains, created_at=projection_updated_at
    )
    _write_custom_metadata(
        conn=conn, secret_id=secret_id, custom=custom, created_at=projection_updated_at
    )


def _projection_name(
    *, payload: Mapping[str, Any], encrypted_name: bytes, storage_mode: str
) -> str:
    plaintext_name = _optional_text(payload=payload, field_name="name")
    decoded = _decode_storage_text(
        stored=encrypted_name,
        field_name="encrypted_name",
        storage_mode=storage_mode,
    )
    if plaintext_name:
        if decoded != plaintext_name:
            raise SQLiteValidationError("encrypted_name_b64 does not match payload name")
        return plaintext_name
    return decoded


def _validate_stored_payload(*, stored: bytes, field_name: str, storage_mode: str) -> None:
    _decode_storage_text(stored=stored, field_name=field_name, storage_mode=storage_mode)


def _decode_storage_text(*, stored: bytes, field_name: str, storage_mode: str) -> str:
    try:
        return decrypt_storage_payload(
            stored=stored,
            field_name=field_name,
            storage_mode=storage_mode,
        ).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise SQLiteValidationError(f"{field_name}_b64 does not match SQLite storage mode") from exc


__all__ = [
    "apply_secret_delete_projection",
    "apply_secret_set_projection",
]
