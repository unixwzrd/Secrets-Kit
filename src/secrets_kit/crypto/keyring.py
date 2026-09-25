"""
secrets_kit.crypto.keyring

In-memory key management for standalone crypto-layer tests and future adapters.
"""

from __future__ import annotations

from dataclasses import replace

from secrets_kit.crypto.models import EncryptionKeypair, KeyMetadata, SigningKeypair

Keypair = SigningKeypair | EncryptionKeypair


class InMemoryKeyring:
    """Mutable in-memory keyring with no persistence or platform integration."""

    def __init__(self) -> None:
        self._signing_keys: dict[str, SigningKeypair] = {}
        self._encryption_keys: dict[str, EncryptionKeypair] = {}

    def add_signing_keypair(self, keypair: SigningKeypair) -> None:
        """Add a signing keypair by key id."""
        if not isinstance(keypair, SigningKeypair):
            raise TypeError("keypair must be a SigningKeypair")
        self._reject_duplicate_key_id(key_id=keypair.metadata.key_id)
        if keypair.metadata.active:
            self._deactivate_signing_keys()
        self._signing_keys[keypair.metadata.key_id] = keypair

    def add_encryption_keypair(self, keypair: EncryptionKeypair) -> None:
        """Add an encryption keypair by key id."""
        if not isinstance(keypair, EncryptionKeypair):
            raise TypeError("keypair must be an EncryptionKeypair")
        self._reject_duplicate_key_id(key_id=keypair.metadata.key_id)
        if keypair.metadata.active:
            self._deactivate_encryption_keys()
        self._encryption_keys[keypair.metadata.key_id] = keypair

    def lookup(self, key_id: str) -> Keypair | None:
        """Return a keypair by key id, or ``None`` when absent."""
        _validate_key_id(key_id=key_id)
        if key_id in self._signing_keys:
            return self._signing_keys[key_id]
        return self._encryption_keys.get(key_id)

    def list_keys(self) -> tuple[KeyMetadata, ...]:
        """Return metadata for all keys in insertion order."""
        return tuple(
            keypair.metadata
            for keypair in (
                *self._signing_keys.values(),
                *self._encryption_keys.values(),
            )
        )

    def activate(self, key_id: str) -> None:
        """Activate one key by id and deactivate other keys of the same type."""
        _validate_key_id(key_id=key_id)
        if key_id in self._signing_keys:
            self._deactivate_signing_keys()
            self._signing_keys[key_id] = _with_active(self._signing_keys[key_id], active=True)
            return
        if key_id in self._encryption_keys:
            self._deactivate_encryption_keys()
            self._encryption_keys[key_id] = _with_active(self._encryption_keys[key_id], active=True)
            return
        raise KeyError(key_id)

    def deactivate(self, key_id: str) -> None:
        """Deactivate a key by id."""
        _validate_key_id(key_id=key_id)
        if key_id in self._signing_keys:
            self._signing_keys[key_id] = _with_active(self._signing_keys[key_id], active=False)
            return
        if key_id in self._encryption_keys:
            self._encryption_keys[key_id] = _with_active(self._encryption_keys[key_id], active=False)
            return
        raise KeyError(key_id)

    def get_active_signing_key(self) -> SigningKeypair | None:
        """Return the active signing keypair, if one exists."""
        return next(
            (keypair for keypair in self._signing_keys.values() if keypair.metadata.active),
            None,
        )

    def get_active_encryption_key(self) -> EncryptionKeypair | None:
        """Return the active encryption keypair, if one exists."""
        return next(
            (keypair for keypair in self._encryption_keys.values() if keypair.metadata.active),
            None,
        )

    def _reject_duplicate_key_id(self, *, key_id: str) -> None:
        if key_id in self._signing_keys or key_id in self._encryption_keys:
            raise ValueError(f"key already exists: {key_id}")

    def _deactivate_signing_keys(self) -> None:
        self._signing_keys = {
            key_id: _with_active(keypair, active=False)
            for key_id, keypair in self._signing_keys.items()
        }

    def _deactivate_encryption_keys(self) -> None:
        self._encryption_keys = {
            key_id: _with_active(keypair, active=False)
            for key_id, keypair in self._encryption_keys.items()
        }


def create_keyring() -> InMemoryKeyring:
    """Create an empty in-memory keyring."""
    return InMemoryKeyring()


def _with_active(keypair: Keypair, *, active: bool) -> Keypair:
    return replace(
        keypair,
        metadata=replace(keypair.metadata, active=active),
    )


def _validate_key_id(*, key_id: str) -> None:
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id is required")


__all__ = ["InMemoryKeyring", "Keypair", "create_keyring"]
