from __future__ import annotations

import unittest

from secrets_kit.crypto.identity_manager import IdentityManager, create_identity_manager
from secrets_kit.crypto.keyring import create_keyring
from secrets_kit.crypto.keystore import InMemoryKeyStore
from secrets_kit.crypto.models import EncryptionKeypair, NodeIdentity, SigningKeypair
from secrets_kit.identifiers import deterministic_identifier

NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="node-1"
)
NODE_ID_2 = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="node-2"
)


class CryptoIdentityManagerTest(unittest.TestCase):
    def test_create_identity_stores_and_tracks_active_keys(self) -> None:
        manager = create_identity_manager()

        identity = manager.create_identity(NODE_ID)

        self.assertIsInstance(identity, NodeIdentity)
        self.assertEqual(identity.node_id, NODE_ID)
        self.assertEqual(
            {metadata.key_id for metadata in manager.list_identity_keys()},
            {identity.signing.metadata.key_id, identity.encryption.metadata.key_id},
        )
        self.assertTrue(all(metadata.active for metadata in manager.list_identity_keys()))

    def test_create_identity_rejects_duplicate_node_id(self) -> None:
        manager = create_identity_manager()
        manager.create_identity(NODE_ID)

        with self.assertRaises(ValueError):
            manager.create_identity(NODE_ID)

    def test_create_identity_rejects_second_local_identity(self) -> None:
        manager = create_identity_manager()
        manager.create_identity(NODE_ID)

        with self.assertRaises(ValueError):
            manager.create_identity(NODE_ID_2)

    def test_load_identity_returns_stored_identity(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        loaded = manager.load_identity(NODE_ID)

        self.assertEqual(loaded, identity)

    def test_load_identity_returns_none_for_non_local_node(self) -> None:
        manager = create_identity_manager()
        manager.create_identity(NODE_ID)

        self.assertIsNone(manager.load_identity(NODE_ID_2))

    def test_activate_and_deactivate_signing_key(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        manager.deactivate_signing_key(identity.signing.metadata.key_id)
        signing_metadata = _metadata_by_id(
            manager.list_identity_keys(),
            identity.signing.metadata.key_id,
        )
        self.assertFalse(signing_metadata.active)

        manager.activate_signing_key(identity.signing.metadata.key_id)
        signing_metadata = _metadata_by_id(
            manager.list_identity_keys(),
            identity.signing.metadata.key_id,
        )
        self.assertTrue(signing_metadata.active)

    def test_activate_and_deactivate_encryption_key(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        manager.deactivate_encryption_key(identity.encryption.metadata.key_id)
        encryption_metadata = _metadata_by_id(
            manager.list_identity_keys(),
            identity.encryption.metadata.key_id,
        )
        self.assertFalse(encryption_metadata.active)

        manager.activate_encryption_key(identity.encryption.metadata.key_id)
        encryption_metadata = _metadata_by_id(
            manager.list_identity_keys(),
            identity.encryption.metadata.key_id,
        )
        self.assertTrue(encryption_metadata.active)

    def test_activate_wrong_key_type_raises_key_error(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        with self.assertRaises(KeyError):
            manager.activate_signing_key(identity.encryption.metadata.key_id)
        with self.assertRaises(KeyError):
            manager.activate_encryption_key(identity.signing.metadata.key_id)

    def test_rotate_signing_key_updates_loaded_identity_and_active_key(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        rotated = manager.rotate_signing_key()
        loaded = manager.load_identity(NODE_ID)

        self.assertIsInstance(rotated, SigningKeypair)
        self.assertNotEqual(rotated.metadata.key_id, identity.signing.metadata.key_id)
        self.assertEqual(loaded.signing.metadata.key_id, rotated.metadata.key_id)  # type: ignore[union-attr]
        self.assertEqual(loaded.encryption.metadata.key_id, identity.encryption.metadata.key_id)  # type: ignore[union-attr]
        self.assertTrue(_metadata_by_id(manager.list_identity_keys(), rotated.metadata.key_id).active)
        self.assertFalse(
            _metadata_by_id(manager.list_identity_keys(), identity.signing.metadata.key_id).active
        )

    def test_rotate_encryption_key_updates_loaded_identity_and_active_key(self) -> None:
        manager = create_identity_manager()
        identity = manager.create_identity(NODE_ID)

        rotated = manager.rotate_encryption_key()
        loaded = manager.load_identity(NODE_ID)

        self.assertIsInstance(rotated, EncryptionKeypair)
        self.assertNotEqual(rotated.metadata.key_id, identity.encryption.metadata.key_id)
        self.assertEqual(loaded.signing.metadata.key_id, identity.signing.metadata.key_id)  # type: ignore[union-attr]
        self.assertEqual(loaded.encryption.metadata.key_id, rotated.metadata.key_id)  # type: ignore[union-attr]
        self.assertTrue(_metadata_by_id(manager.list_identity_keys(), rotated.metadata.key_id).active)
        self.assertFalse(
            _metadata_by_id(manager.list_identity_keys(), identity.encryption.metadata.key_id).active
        )

    def test_rotation_requires_current_identity(self) -> None:
        manager = create_identity_manager()

        with self.assertRaises(ValueError):
            manager.rotate_signing_key()
        with self.assertRaises(ValueError):
            manager.rotate_encryption_key()

    def test_manager_coordinates_injected_store_and_keyring(self) -> None:
        key_store = InMemoryKeyStore()
        keyring = create_keyring()
        manager = IdentityManager(key_store=key_store, keyring=keyring)

        identity = manager.create_identity(NODE_ID)

        self.assertEqual(
            key_store.load_signing_keypair(identity.signing.metadata.key_id),
            identity.signing,
        )
        self.assertEqual(
            key_store.load_encryption_keypair(identity.encryption.metadata.key_id),
            identity.encryption,
        )
        self.assertEqual(
            keyring.get_active_signing_key().metadata.key_id,  # type: ignore[union-attr]
            identity.signing.metadata.key_id,
        )
        self.assertEqual(
            keyring.get_active_encryption_key().metadata.key_id,  # type: ignore[union-attr]
            identity.encryption.metadata.key_id,
        )

    def test_invalid_ids_rejected(self) -> None:
        manager = create_identity_manager()

        with self.assertRaises(ValueError):
            manager.create_identity("")
        with self.assertRaises(ValueError):
            manager.load_identity("")
        with self.assertRaises(ValueError):
            manager.activate_signing_key("")
        with self.assertRaises(ValueError):
            manager.deactivate_encryption_key("")


def _metadata_by_id(metadata_items, key_id):
    for metadata in metadata_items:
        if metadata.key_id == key_id:
            return metadata
    raise AssertionError(f"missing metadata for key id: {key_id}")


if __name__ == "__main__":
    unittest.main()
