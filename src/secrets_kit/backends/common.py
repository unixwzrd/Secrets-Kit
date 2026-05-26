"""
secrets_kit.backends.common

Backend identity and normalization helpers.
"""

from __future__ import annotations

from typing import Final


class BackendError(RuntimeError):
    """Backend selection or operation error."""


BACKEND_KEYCHAIN: Final[str] = "keychain"
"""Canonical backend id for the platform-native Keychain backend."""

BACKEND_SQLITE: Final[str] = "sqlite"
"""Canonical backend id for the standalone local SQLite backend."""

_KNOWN_NORMALIZED: frozenset[str] = frozenset({BACKEND_KEYCHAIN, BACKEND_SQLITE})

BACKEND_CHOICES: tuple[str, ...] = (BACKEND_KEYCHAIN, BACKEND_SQLITE)


def normalize_backend(backend: str) -> str:
    """Return canonical backend id."""
    raw = backend.strip().lower()
    if raw not in _KNOWN_NORMALIZED:
        raise BackendError(
            f"unsupported backend: {backend!r} (expected {BACKEND_KEYCHAIN} or {BACKEND_SQLITE})"
        )
    return raw


def is_keychain_backend(backend: str) -> bool:
    """Return whether backend resolves to the canonical Keychain backend."""
    return normalize_backend(backend) == BACKEND_KEYCHAIN


__all__ = [
    "BACKEND_CHOICES",
    "BACKEND_KEYCHAIN",
    "BACKEND_SQLITE",
    "BackendError",
    "is_keychain_backend",
    "normalize_backend",
]
