"""
secrets_kit.crypto.random

Operating-system random byte helpers.
"""

from __future__ import annotations

import secrets


def random_bytes(length: int) -> bytes:
    """Return ``length`` bytes from the operating-system CSPRNG."""
    if not isinstance(length, int) or length < 1:
        raise ValueError("length must be a positive integer")
    return secrets.token_bytes(length)


__all__ = ["random_bytes"]
