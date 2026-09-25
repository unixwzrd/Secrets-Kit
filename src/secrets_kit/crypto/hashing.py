"""
secrets_kit.crypto.hashing

Small hashing helpers for crypto subsystem building blocks.
"""

from __future__ import annotations

import hashlib
import hmac


def sha256_bytes(data: bytes) -> bytes:
    """Return the SHA-256 digest for ``data``."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest for ``data``."""
    return sha256_bytes(data).hex()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return HMAC-SHA-256 for ``data`` using ``key``."""
    if not isinstance(key, bytes) or not key:
        raise ValueError("key must be non-empty bytes")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hmac.new(key, data, hashlib.sha256).digest()


__all__ = ["hmac_sha256", "sha256_bytes", "sha256_hex"]
