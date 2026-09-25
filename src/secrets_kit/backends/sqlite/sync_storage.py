"""
secrets_kit.backends.sqlite.sync_storage

Rewrap SQLite-local encrypted fields at the end-to-end envelope boundary.

SQLite storage keys remain local to one peer.  Secret name and value bytes are
therefore decrypted only immediately before destination-specific envelope
encryption and are re-encrypted with the receiving peer's local storage key
immediately after authenticated envelope decryption.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import replace

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.hashing import sha256_hex
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.serialization import canonical_json_bytes
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    read_sqlite_storage_mode,
)
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.storage.sqlite import decrypt_payload, encrypt_payload

STORAGE_REWRAP_PROTOCOL = "sqlite_storage_rewrap/v1"
_LOCAL_FIELDS = {
    "encrypted_name_b64": "name_b64",
    "encrypted_payload_b64": "payload_b64",
}


def prepare_outbound_storage_payload(
    *, conn: sqlite3.Connection, transaction: Transaction, envelope_encrypted: bool
) -> Transaction:
    """Replace local-only ciphertext with envelope-protected plaintext bytes."""
    if transaction.transaction_type not in {"secret.set", "secret.delete"}:
        return transaction
    if read_sqlite_storage_mode(conn=conn) != SQLITE_STORAGE_MODE_ENCRYPTED:
        return transaction
    if not envelope_encrypted:
        raise SQLiteValidationError(
            "encrypted SQLite secret synchronization requires encrypted envelopes"
        )
    wire_payload = _wire_payload_from_local(payload=transaction.payload, transaction_type=transaction.transaction_type)
    return replace(
        transaction,
        payload=wire_payload,
        payload_hash=sha256_hex(data=canonical_json_bytes(payload=wire_payload)),
    )


def localize_inbound_storage_payload(
    *,
    conn: sqlite3.Connection,
    transaction_id: str,
    transaction_type: str,
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Re-encrypt one authenticated wire payload with the local SQLite key."""
    value = dict(payload)
    marker = value.get("storage_rewrap")
    if marker is None:
        return value
    if transaction_type not in {"secret.set", "secret.delete"} or marker != STORAGE_REWRAP_PROTOCOL:
        raise SQLiteValidationError("SQLite storage rewrap protocol is invalid")
    if any(field in value for field in _LOCAL_FIELDS):
        raise SQLiteValidationError("SQLite storage rewrap payload is ambiguous")

    existing = conn.execute(
        "SELECT payload, transaction_type FROM transactions WHERE transaction_id = ?",
        (transaction_id,),
    ).fetchone()
    if existing is not None:
        if existing["transaction_type"] != transaction_type:
            raise SQLiteValidationError("duplicate transaction type does not match")
        retained = _decode_retained_payload(existing["payload"])
        if _wire_payload_from_local(payload=retained, transaction_type=transaction_type) != value:
            raise SQLiteValidationError("duplicate transaction payload does not match")
        return retained

    localized = dict(value)
    localized.pop("storage_rewrap")
    storage_mode = read_sqlite_storage_mode(conn=conn)
    for local_field, wire_field in _LOCAL_FIELDS.items():
        if transaction_type == "secret.delete" and wire_field == "payload_b64" and wire_field not in localized:
            continue
        encoded = localized.pop(wire_field, None)
        if not isinstance(encoded, str) or not encoded:
            raise SQLiteValidationError(f"{wire_field} is required")
        try:
            plaintext = decode_b64url(encoded)
            stored = encrypt_payload(
                plaintext=plaintext,
                field_name=local_field.removesuffix("_b64"),
                storage_mode=storage_mode,
            )
        except (TypeError, ValueError) as exc:
            raise SQLiteValidationError(f"{wire_field} is invalid") from exc
        localized[local_field] = base64.b64encode(stored).decode("ascii")
    return localized


def _wire_payload_from_local(*, payload: Mapping[str, object], transaction_type: str) -> dict[str, object]:
    """Rewrap a set or tombstone; deletion may omit its value, never its name."""
    wire = dict(payload)
    wire["storage_rewrap"] = STORAGE_REWRAP_PROTOCOL
    for local_field, wire_field in _LOCAL_FIELDS.items():
        if transaction_type == "secret.delete" and local_field == "encrypted_payload_b64" and local_field not in wire:
            continue
        encoded = wire.pop(local_field, None)
        if not isinstance(encoded, str) or not encoded:
            raise SQLiteValidationError(f"{local_field} is required")
        try:
            stored = decode_b64url(encoded)
            plaintext = decrypt_payload(
                stored=stored,
                field_name=local_field.removesuffix("_b64"),
                storage_mode=SQLITE_STORAGE_MODE_ENCRYPTED,
            )
        except (TypeError, ValueError) as exc:
            raise SQLiteValidationError(f"{local_field} is invalid") from exc
        wire[wire_field] = encode_b64url(plaintext)
    return wire


def _decode_retained_payload(value: object) -> dict[str, object]:
    """Decode one canonical retained transaction payload."""
    try:
        decoded = json.loads(bytes(value).decode("utf-8"))
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SQLiteValidationError("retained transaction payload is invalid") from exc
    if not isinstance(decoded, dict):
        raise SQLiteValidationError("retained transaction payload is invalid")
    return decoded


__all__ = [
    "STORAGE_REWRAP_PROTOCOL",
    "localize_inbound_storage_payload",
    "prepare_outbound_storage_payload",
]
