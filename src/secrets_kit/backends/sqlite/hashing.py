"""
secrets_kit.backends.sqlite.hashing

SHA-256 hashing for canonical transaction payload bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.serialization import canonical_json_bytes


def sha256_hex(*, data: bytes) -> str:
    """
    Hash bytes with SHA-256.

    Args:
        data:
            Bytes to hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest.

    Side Effects:
        None.
    """
    return hashlib.sha256(data).hexdigest()


def hash_payload(*, payload: Mapping[str, Any]) -> str:
    """
    Hash a canonical JSON payload.

    Args:
        payload:
            JSON mapping to serialize and hash.

    Returns:
        Lowercase hexadecimal SHA-256 digest.

    Raises:
        SQLiteValidationError:
            Payload cannot be serialized deterministically.

    Side Effects:
        None.
    """
    return sha256_hex(data=canonical_json_bytes(payload=payload))


def payload_hash_hex_to_bytes(*, hash_hex: str) -> bytes:
    """
    Convert a Python-facing payload hash into raw SQLite storage bytes.

    Args:
        hash_hex:
            Lowercase hexadecimal SHA-256 digest.

    Returns:
        Raw 32-byte SHA-256 digest.

    Raises:
        SQLiteValidationError:
            Hash is not lowercase hexadecimal SHA-256.

    Side Effects:
        None.
    """
    if len(hash_hex) != 64 or hash_hex != hash_hex.lower():
        raise SQLiteValidationError("payload_hash must be lowercase hexadecimal SHA-256")
    try:
        hash_bytes = bytes.fromhex(hash_hex)
    except ValueError as exc:
        raise SQLiteValidationError("payload_hash must be lowercase hexadecimal SHA-256") from exc
    if len(hash_bytes) != 32:
        raise SQLiteValidationError("payload_hash must be 32 bytes")
    return hash_bytes


def payload_hash_bytes_to_hex(*, hash_bytes: bytes) -> str:
    """
    Convert raw SQLite payload hash bytes into Python-facing lowercase hex.

    Args:
        hash_bytes:
            Raw 32-byte SHA-256 digest.

    Returns:
        Lowercase hexadecimal SHA-256 digest.

    Raises:
        SQLiteValidationError:
            Stored hash is not 32 bytes.

    Side Effects:
        None.
    """
    if len(hash_bytes) != 32:
        raise SQLiteValidationError("stored payload_hash must be 32 bytes")
    return hash_bytes.hex()


__all__ = [
    "hash_payload",
    "payload_hash_bytes_to_hex",
    "payload_hash_hex_to_bytes",
    "sha256_hex",
]
