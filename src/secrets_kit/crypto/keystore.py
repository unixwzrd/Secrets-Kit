"""
secrets_kit.crypto.keystore

Standalone key persistence abstractions with an in-memory implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from secrets_kit.crypto.models import EncryptionKeypair, KeyMetadata, SigningKeypair


class KeyStore(ABC):
    """
    Abstract keypair persistence interface for crypto-layer adapters.

    Implementations store and load crypto model keypairs by ``key_id``. This
    interface has no keychain, SQLite, daemon, CLI, or filesystem assumptions.
    """

    @abstractmethod
    def store_signing_keypair(self, keypair: SigningKeypair) -> None:
        """Store a signing keypair, rejecting duplicate key ids."""

    @abstractmethod
    def store_encryption_keypair(self, keypair: EncryptionKeypair) -> None:
        """Store an encryption keypair, rejecting duplicate key ids."""

    @abstractmethod
    def load_signing_keypair(self, key_id: str) -> SigningKeypair | None:
        """Load a signing keypair by key id."""

    @abstractmethod
    def load_encryption_keypair(self, key_id: str) -> EncryptionKeypair | None:
        """Load an encryption keypair by key id."""

    @abstractmethod
    def list_keys(self) -> tuple[KeyMetadata, ...]:
        """List stored key metadata."""


class InMemoryKeyStore(KeyStore):
    """
    In-memory key store with no external persistence or integration.

    The store is intentionally process-local and mutable. It rejects duplicate
    ``key_id`` values so callers cannot accidentally replace key material.
    """

    def __init__(self) -> None:
        self._signing_keys: dict[str, SigningKeypair] = {}
        self._encryption_keys: dict[str, EncryptionKeypair] = {}

    def store_signing_keypair(self, keypair: SigningKeypair) -> None:
        """Store a signing keypair by key id."""
        if not isinstance(keypair, SigningKeypair):
            raise TypeError("keypair must be a SigningKeypair")
        self._reject_duplicate_key_id(key_id=keypair.metadata.key_id)
        self._signing_keys[keypair.metadata.key_id] = keypair

    def store_encryption_keypair(self, keypair: EncryptionKeypair) -> None:
        """Store an encryption keypair by key id."""
        if not isinstance(keypair, EncryptionKeypair):
            raise TypeError("keypair must be an EncryptionKeypair")
        self._reject_duplicate_key_id(key_id=keypair.metadata.key_id)
        self._encryption_keys[keypair.metadata.key_id] = keypair

    def load_signing_keypair(self, key_id: str) -> SigningKeypair | None:
        """Load a signing keypair by key id."""
        _validate_key_id(key_id=key_id)
        return self._signing_keys.get(key_id)

    def load_encryption_keypair(self, key_id: str) -> EncryptionKeypair | None:
        """Load an encryption keypair by key id."""
        _validate_key_id(key_id=key_id)
        return self._encryption_keys.get(key_id)

    def list_keys(self) -> tuple[KeyMetadata, ...]:
        """List stored key metadata in insertion order."""
        return tuple(
            keypair.metadata
            for keypair in (
                *self._signing_keys.values(),
                *self._encryption_keys.values(),
            )
        )

    def _reject_duplicate_key_id(self, *, key_id: str) -> None:
        if key_id in self._signing_keys or key_id in self._encryption_keys:
            raise ValueError(f"key already exists: {key_id}")


def _validate_key_id(*, key_id: str) -> None:
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id is required")


__all__ = ["InMemoryKeyStore", "KeyStore"]
