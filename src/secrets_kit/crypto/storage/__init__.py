"""
secrets_kit.crypto.storage

Backend storage codecs (SQLite columns today; additional stores later).
"""

from __future__ import annotations

from secrets_kit.crypto.storage.sqlite import (
    SQLITE_PLAINTEXT_DEBUG_ENV,
    decrypt_payload,
    encrypt_payload,
)

__all__ = [
    "SQLITE_PLAINTEXT_DEBUG_ENV",
    "decrypt_payload",
    "encrypt_payload",
]
