from __future__ import annotations

import unittest
from dataclasses import replace

from secrets_kit.crypto.keyring import InMemoryKeyring, create_keyring
from secrets_kit.crypto.models import (
    generate_encryption_keypair,
    generate_signing_keypair,
)


class CryptoKeyringTest(unittest.TestCase):
    def test_create_empty_keyring(self) -> None:
        keyring = create_keyring()

        self.assertIsInstance(keyring, InMemoryKeyring)
        self.assertEqual(keyring.list_keys(), ())
        self.assertIsNone(keyring.get_active_signing_key())
        self.assertIsNone(keyring.get_active_encryption_key())

    def test_add_and_lookup_signing_keypair(self) -> None:
        keyring = create_keyring()
        keypair = generate_signing_keypair()

        keyring.add_signing_keypair(keypair)

        self.assertEqual(keyring.lookup(keypair.metadata.key_id), keypair)
        self.assertEqual(keyring.get_active_signing_key(), keypair)

    def test_add_and_lookup_encryption_keypair(self) -> None:
        keyring = create_keyring()
        keypair = generate_encryption_keypair()

        keyring.add_encryption_keypair(keypair)

        self.assertEqual(keyring.lookup(keypair.metadata.key_id), keypair)
        self.assertEqual(keyring.get_active_encryption_key(), keypair)

    def test_lookup_missing_key_returns_none(self) -> None:
        self.assertIsNone(create_keyring().lookup("missing"))

    def test_list_keys_returns_metadata(self) -> None:
        keyring = create_keyring()
        signing = generate_signing_keypair()
        encryption = generate_encryption_keypair()

        keyring.add_signing_keypair(signing)
        keyring.add_encryption_keypair(encryption)

        self.assertEqual(keyring.list_keys(), (signing.metadata, encryption.metadata))

    def test_add_active_signing_key_deactivates_previous_signing_key_only(self) -> None:
        keyring = create_keyring()
        first_signing = generate_signing_keypair()
        second_signing = generate_signing_keypair()
        encryption = generate_encryption_keypair()

        keyring.add_signing_keypair(first_signing)
        keyring.add_encryption_keypair(encryption)
        keyring.add_signing_keypair(second_signing)

        self.assertFalse(keyring.lookup(first_signing.metadata.key_id).metadata.active)  # type: ignore[union-attr]
        self.assertEqual(keyring.get_active_signing_key().metadata.key_id, second_signing.metadata.key_id)  # type: ignore[union-attr]
        self.assertEqual(keyring.get_active_encryption_key(), encryption)

    def test_add_active_encryption_key_deactivates_previous_encryption_key_only(self) -> None:
        keyring = create_keyring()
        signing = generate_signing_keypair()
        first_encryption = generate_encryption_keypair()
        second_encryption = generate_encryption_keypair()

        keyring.add_signing_keypair(signing)
        keyring.add_encryption_keypair(first_encryption)
        keyring.add_encryption_keypair(second_encryption)

        self.assertFalse(keyring.lookup(first_encryption.metadata.key_id).metadata.active)  # type: ignore[union-attr]
        self.assertEqual(
            keyring.get_active_encryption_key().metadata.key_id,  # type: ignore[union-attr]
            second_encryption.metadata.key_id,
        )
        self.assertEqual(keyring.get_active_signing_key(), signing)

    def test_activate_key_sets_single_active_key_for_that_key_type(self) -> None:
        keyring = create_keyring()
        active = generate_signing_keypair()
        generated_inactive = generate_signing_keypair()
        inactive = replace(
            generated_inactive,
            metadata=replace(generated_inactive.metadata, active=False),
        )

        keyring.add_signing_keypair(active)
        keyring.add_signing_keypair(inactive)
        keyring.activate(inactive.metadata.key_id)

        self.assertFalse(keyring.lookup(active.metadata.key_id).metadata.active)  # type: ignore[union-attr]
        self.assertTrue(keyring.lookup(inactive.metadata.key_id).metadata.active)  # type: ignore[union-attr]
        self.assertEqual(keyring.get_active_signing_key().metadata.key_id, inactive.metadata.key_id)  # type: ignore[union-attr]

    def test_deactivate_key(self) -> None:
        keyring = create_keyring()
        keypair = generate_encryption_keypair()

        keyring.add_encryption_keypair(keypair)
        keyring.deactivate(keypair.metadata.key_id)

        self.assertFalse(keyring.lookup(keypair.metadata.key_id).metadata.active)  # type: ignore[union-attr]
        self.assertIsNone(keyring.get_active_encryption_key())

    def test_missing_activate_or_deactivate_raises_key_error(self) -> None:
        keyring = create_keyring()

        with self.assertRaises(KeyError):
            keyring.activate("missing")
        with self.assertRaises(KeyError):
            keyring.deactivate("missing")

    def test_duplicate_key_id_rejected(self) -> None:
        keyring = create_keyring()
        keypair = generate_signing_keypair()

        keyring.add_signing_keypair(keypair)

        with self.assertRaises(ValueError):
            keyring.add_signing_keypair(keypair)

    def test_invalid_keypair_type_rejected(self) -> None:
        keyring = create_keyring()

        with self.assertRaises(TypeError):
            keyring.add_signing_keypair(generate_encryption_keypair())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            keyring.add_encryption_keypair(generate_signing_keypair())  # type: ignore[arg-type]

    def test_invalid_key_id_rejected(self) -> None:
        keyring = create_keyring()

        with self.assertRaises(ValueError):
            keyring.lookup("")


if __name__ == "__main__":
    unittest.main()
