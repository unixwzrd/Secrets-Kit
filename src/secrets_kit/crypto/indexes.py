"""
secrets_kit.crypto.indexes

Deterministic blind index helpers.
"""

from __future__ import annotations

import unicodedata

from secrets_kit.crypto.hashing import hmac_sha256


def blind_index(key: bytes, label: str, value: str) -> bytes:
    """Return deterministic HMAC-SHA-256 index material for ``label`` and ``value``."""
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty string")
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    normalized = unicodedata.normalize("NFC", value.strip()).casefold()
    message = label.encode("utf-8") + b"\0" + normalized.encode("utf-8")
    return hmac_sha256(key=key, data=message)


def blind_index_hex(key: bytes, label: str, value: str) -> str:
    """Return hex-encoded blind index material."""
    return blind_index(key=key, label=label, value=value).hex()


__all__ = ["blind_index", "blind_index_hex"]
