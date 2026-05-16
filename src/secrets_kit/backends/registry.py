"""Backend identifiers, normalization, and concrete store factory."""

from __future__ import annotations

import os
from typing import FrozenSet, Optional

from secrets_kit.backends.base import BackendStore
from secrets_kit.backends.errors import BackendError
from secrets_kit.backends.messages import BACKEND_NORMALIZE_HINT

BACKEND_SECURE = "secure"
"""Local macOS Keychain backend id (alias: ``local``)."""

BACKEND_SQLITE = "sqlite"
"""Portable encrypted SQLite backend id."""

_BACKEND_ALIASES: dict[str, str] = {
    "local": BACKEND_SECURE,
}

BACKEND_CHOICES: tuple[str, ...] = (
    BACKEND_SECURE,
    BACKEND_SQLITE,
    "local",
)
"""Accepted values for CLI/env/defaults input."""

_KNOWN_NORMALIZED: FrozenSet[str] = frozenset({BACKEND_SECURE, BACKEND_SQLITE})


def normalize_backend(backend: str) -> str:
    """Return canonical backend id (``secure`` or ``sqlite``)."""
    raw = backend.strip().lower().replace("_", "-")
    normalized = _BACKEND_ALIASES.get(raw, raw)
    if normalized not in _KNOWN_NORMALIZED:
        raise BackendError(
            f"unsupported backend: {backend!r} (expected {BACKEND_SECURE}, {BACKEND_SQLITE}, or alias local). "
            f"{BACKEND_NORMALIZE_HINT}"
        )
    return normalized


def is_secure_backend(backend: str) -> bool:
    """Return ``True`` when ``backend`` resolves to ``secure``."""
    return normalize_backend(backend) == BACKEND_SECURE


def is_sqlite_backend(backend: str) -> bool:
    """Return ``True`` when ``backend`` resolves to ``sqlite``."""
    return normalize_backend(backend) == BACKEND_SQLITE


def resolve_backend_store(
    *,
    backend: str,
    path: Optional[str] = None,
    kek_keychain_path: Optional[str] = None,
) -> BackendStore:
    """Construct the concrete ``BackendStore`` for a normalized backend id."""
    normalized = normalize_backend(backend)
    if normalized == BACKEND_SQLITE:
        from secrets_kit.backends.sqlite import (
            SqliteSecretStore,
            default_sqlite_db_path,
        )

        db_path = path or default_sqlite_db_path()
        kc = kek_keychain_path
        if not kc:
            env_kc = os.environ.get("SECKIT_SQLITE_KEK_KEYCHAIN", "").strip()
            kc = os.path.expanduser(env_kc) if env_kc else None
        else:
            kc = os.path.expanduser(kc)
        return SqliteSecretStore(db_path=os.path.expanduser(db_path), kek_keychain_path=kc)

    from secrets_kit.backends.keychain import KeychainBackendStore

    return KeychainBackendStore(path=path)

