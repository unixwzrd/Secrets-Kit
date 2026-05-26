"""
secrets_kit.crypto.errors

Cryptography dependency and capability errors.
"""

from __future__ import annotations


class CryptoUnavailable(RuntimeError):
    """Raised when cryptography dependencies are missing."""


__all__ = ["CryptoUnavailable"]
