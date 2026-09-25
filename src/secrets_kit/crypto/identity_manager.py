"""
secrets_kit.crypto.identity_manager

Coordinate standalone local identity key lifecycle state.

``IdentityManager`` is a pure crypto-layer coordinator. It stores key material
through a ``KeyStore`` and tracks active keys through an ``InMemoryKeyring``.
It has no SQLite, daemon, CLI, networking, keychain, schema, or runtime-service
integration. It manages exactly one authoritative local node identity and does
not model peers or remote node identities.
"""

from __future__ import annotations

from dataclasses import replace

from secrets_kit.crypto.keyring import InMemoryKeyring, create_keyring
from secrets_kit.crypto.keystore import InMemoryKeyStore, KeyStore
from secrets_kit.crypto.models import (
    EncryptionKeypair,
    KeyMetadata,
    NodeIdentity,
    SigningKeypair,
    generate_encryption_keypair,
    generate_node_identity,
    generate_signing_keypair,
)


class IdentityManager:
    """
    Coordinate local identity lifecycle operations over a key store and keyring.

    The manager owns one in-memory local node-to-key-id binding. Key material is
    stored in the supplied ``KeyStore`` and active key state is tracked in the
    supplied ``InMemoryKeyring``. Rotation applies only to the local identity
    created or loaded by this manager.
    """

    def __init__(
        self,
        *,
        key_store: KeyStore | None = None,
        keyring: InMemoryKeyring | None = None,
    ) -> None:
        self._key_store = key_store if key_store is not None else InMemoryKeyStore()
        self._keyring = keyring if keyring is not None else create_keyring()
        self._local_node_id: str | None = None
        self._local_identity_key_ids: tuple[str, str] | None = None

    def create_identity(self, node_id: str) -> NodeIdentity:
        """
        Create and store the local node identity.

        The generated signing and encryption keypairs are persisted in the key
        store and added to the keyring as active keys for their respective key
        types. Only one local identity may be authoritative at a time.
        """
        _validate_node_id(node_id=node_id)
        if self._local_node_id is not None:
            raise ValueError(f"local identity already exists: {self._local_node_id}")
        identity = generate_node_identity(node_id=node_id)
        self._key_store.store_signing_keypair(identity.signing)
        self._key_store.store_encryption_keypair(identity.encryption)
        self._keyring.add_signing_keypair(identity.signing)
        self._keyring.add_encryption_keypair(identity.encryption)
        self._local_node_id = node_id
        self._local_identity_key_ids = (
            identity.signing.metadata.key_id,
            identity.encryption.metadata.key_id,
        )
        return identity

    def load_identity(self, node_id: str) -> NodeIdentity | None:
        """
        Load the local node identity from the manager binding and key store.

        Returns ``None`` when ``node_id`` is not the local node id or when either
        referenced keypair is absent from the key store.
        """
        _validate_node_id(node_id=node_id)
        if node_id != self._local_node_id or self._local_identity_key_ids is None:
            return None
        signing_key_id, encryption_key_id = self._local_identity_key_ids
        signing = self._key_store.load_signing_keypair(signing_key_id)
        encryption = self._key_store.load_encryption_keypair(encryption_key_id)
        if signing is None or encryption is None:
            return None
        return NodeIdentity(node_id=node_id, signing=signing, encryption=encryption)

    def list_identity_keys(self) -> tuple[KeyMetadata, ...]:
        """
        Return key metadata tracked by the active-key keyring.

        This reflects lifecycle state coordinated by the manager, including
        activation and deactivation operations.
        """
        return self._keyring.list_keys()

    def activate_signing_key(self, key_id: str) -> None:
        """Activate a stored signing key and deactivate other signing keys."""
        self._ensure_signing_key_in_keyring(key_id=key_id)
        self._keyring.activate(key_id)

    def deactivate_signing_key(self, key_id: str) -> None:
        """Deactivate a stored signing key."""
        self._ensure_signing_key_in_keyring(key_id=key_id)
        self._keyring.deactivate(key_id)

    def activate_encryption_key(self, key_id: str) -> None:
        """Activate a stored encryption key and deactivate other encryption keys."""
        self._ensure_encryption_key_in_keyring(key_id=key_id)
        self._keyring.activate(key_id)

    def deactivate_encryption_key(self, key_id: str) -> None:
        """Deactivate a stored encryption key."""
        self._ensure_encryption_key_in_keyring(key_id=key_id)
        self._keyring.deactivate(key_id)

    def rotate_signing_key(self) -> SigningKeypair:
        """
        Generate, store, and activate a new signing key for the local identity.

        Raises ``ValueError`` when no local identity has been created.
        """
        self._require_local_identity()
        keypair = generate_signing_keypair()
        self._key_store.store_signing_keypair(keypair)
        self._keyring.add_signing_keypair(keypair)
        _old_signing_key_id, encryption_key_id = self._local_identity_key_ids
        self._local_identity_key_ids = (keypair.metadata.key_id, encryption_key_id)
        return keypair

    def rotate_encryption_key(self) -> EncryptionKeypair:
        """
        Generate, store, and activate a new encryption key for the local identity.

        Raises ``ValueError`` when no local identity has been created.
        """
        self._require_local_identity()
        keypair = generate_encryption_keypair()
        self._key_store.store_encryption_keypair(keypair)
        self._keyring.add_encryption_keypair(keypair)
        signing_key_id, _old_encryption_key_id = self._local_identity_key_ids
        self._local_identity_key_ids = (signing_key_id, keypair.metadata.key_id)
        return keypair

    def _ensure_signing_key_in_keyring(self, *, key_id: str) -> None:
        _validate_key_id(key_id=key_id)
        keypair = self._key_store.load_signing_keypair(key_id)
        if keypair is None:
            raise KeyError(key_id)
        if self._keyring.lookup(key_id) is None:
            self._keyring.add_signing_keypair(_as_inactive_signing_keypair(keypair=keypair))

    def _ensure_encryption_key_in_keyring(self, *, key_id: str) -> None:
        _validate_key_id(key_id=key_id)
        keypair = self._key_store.load_encryption_keypair(key_id)
        if keypair is None:
            raise KeyError(key_id)
        if self._keyring.lookup(key_id) is None:
            self._keyring.add_encryption_keypair(_as_inactive_encryption_keypair(keypair=keypair))

    def _require_local_identity(self) -> None:
        if self._local_node_id is None or self._local_identity_key_ids is None:
            raise ValueError("no local identity is active")


def create_identity_manager(
    *,
    key_store: KeyStore | None = None,
    keyring: InMemoryKeyring | None = None,
) -> IdentityManager:
    """Create an identity manager with optional injected key store and keyring."""
    return IdentityManager(key_store=key_store, keyring=keyring)


def _as_inactive_signing_keypair(*, keypair: SigningKeypair) -> SigningKeypair:
    return replace(keypair, metadata=replace(keypair.metadata, active=False))


def _as_inactive_encryption_keypair(*, keypair: EncryptionKeypair) -> EncryptionKeypair:
    return replace(keypair, metadata=replace(keypair.metadata, active=False))


def _validate_key_id(*, key_id: str) -> None:
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id is required")


def _validate_node_id(*, node_id: str) -> None:
    if not isinstance(node_id, str) or not node_id:
        raise ValueError("node_id is required")


__all__ = ["IdentityManager", "create_identity_manager"]
