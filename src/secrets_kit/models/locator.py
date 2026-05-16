"""
secrets_kit.models.locator

Mechanical locator_hash and opaque locator_hint (no semantic prefixes).
"""

from __future__ import annotations

import hashlib

from secrets_kit.models.core import make_registry_key


def locator_hash_hex(*, service: str, account: str, name: str) -> str:
    """SHA-256 hex of canonical locator string (integrity / dedup, decrypt-free)."""
    key = make_registry_key(service=service, account=account, name=name)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def opaque_locator_hint(*, entry_id: str) -> str:
    """Default low-information hint: ``item-`` + first 6 hex chars of SHA-256(entry_id).

    Does not derive from env-var prefixes or provider tokens.
    """
    digest = hashlib.sha256(entry_id.encode("utf-8")).hexdigest()[:6]
    return f"item-{digest}"
