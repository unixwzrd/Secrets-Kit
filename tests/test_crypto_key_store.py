from __future__ import annotations

import unittest

from secrets_kit.crypto.keystore import InMemoryKeyStore, KeyStore
from secrets_kit.crypto.models import generate_encryption_keypair, generate_signing_keypair


class CryptoKeyStoreTest(unittest.TestCase):
    def test_key_store_is_abstract(self) -> None:
        with self.assertRaises(TypeError):
            KeyStore()  # type: ignore[abstract]

    def test_empty_store(self) -> None:
        store = InMemoryKeyStore()

        self.assertEqual(store.list_keys(), ())
        self.assertIsNone(store.load_signing_keypair("missing"))
        self.assertIsNone(store.load_encryption_keypair("missing"))

    def test_store_and_load_signing_keypair(self) -> None:
        store = InMemoryKeyStore()
        keypair = generate_signing_keypair()

        store.store_signing_keypair(keypair)

        self.assertEqual(store.load_signing_keypair(keypair.metadata.key_id), keypair)
        self.assertIsNone(store.load_encryption_keypair(keypair.metadata.key_id))

    def test_store_and_load_encryption_keypair(self) -> None:
        store = InMemoryKeyStore()
        keypair = generate_encryption_keypair()

        store.store_encryption_keypair(keypair)

        self.assertEqual(store.load_encryption_keypair(keypair.metadata.key_id), keypair)
        self.assertIsNone(store.load_signing_keypair(keypair.metadata.key_id))

    def test_list_keys_returns_metadata(self) -> None:
        store = InMemoryKeyStore()
        signing = generate_signing_keypair()
        encryption = generate_encryption_keypair()

        store.store_signing_keypair(signing)
        store.store_encryption_keypair(encryption)

        self.assertEqual(store.list_keys(), (signing.metadata, encryption.metadata))

    def test_store_rejects_duplicate_keypair_with_same_key_id(self) -> None:
        store = InMemoryKeyStore()
        keypair = generate_signing_keypair()

        store.store_signing_keypair(keypair)

        with self.assertRaises(ValueError):
            store.store_signing_keypair(keypair)

    def test_store_rejects_duplicate_encryption_keypair_with_same_key_id(self) -> None:
        store = InMemoryKeyStore()
        encryption = generate_encryption_keypair()

        store.store_encryption_keypair(encryption)

        with self.assertRaises(ValueError):
            store.store_encryption_keypair(encryption)

    def test_invalid_keypair_type_rejected(self) -> None:
        store = InMemoryKeyStore()

        with self.assertRaises(TypeError):
            store.store_signing_keypair(generate_encryption_keypair())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            store.store_encryption_keypair(generate_signing_keypair())  # type: ignore[arg-type]

    def test_invalid_key_id_rejected(self) -> None:
        store = InMemoryKeyStore()

        with self.assertRaises(ValueError):
            store.load_signing_keypair("")
        with self.assertRaises(ValueError):
            store.load_encryption_keypair("")


if __name__ == "__main__":
    unittest.main()
