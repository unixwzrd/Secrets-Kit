"""
secrets_kit.crypto.storage.sqlite

Storage codec for SQLite backend payload columns.
"""

from __future__ import annotations

SQLITE_PLAINTEXT_DEBUG_ENV = "SECKIT_SQLITE_PLAINTEXT_DEBUG"


def encrypt_payload(*, plaintext: bytes, field_name: str) -> bytes:
    """
    Encode plaintext for SQLite storage.

    The codec boundary is storage-format agnostic so future encrypted-at-rest
    formats can be introduced without changing SecretStore semantics.
    """
    _ = field_name
    return bytes(plaintext)


def decrypt_payload(*, stored: bytes, field_name: str) -> bytes:
    """Decode bytes from SQLite storage."""
    _ = field_name
    return bytes(stored)


__all__ = ["SQLITE_PLAINTEXT_DEBUG_ENV", "decrypt_payload", "encrypt_payload"]
