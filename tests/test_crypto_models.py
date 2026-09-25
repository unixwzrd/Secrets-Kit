from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace

from secrets_kit.crypto.models import (
    ALGORITHM_ED25519,
    ALGORITHM_X25519,
    EncryptionKeypair,
    KeyMetadata,
    NodeIdentity,
    SigningKeypair,
    deserialize_private_key,
    deserialize_public_key,
    generate_encryption_keypair,
    generate_node_identity,
    generate_signing_keypair,
    key_id_for_public_key,
    serialize_private_key,
    serialize_public_key,
)
from secrets_kit.identifiers import deterministic_identifier

NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="node-1"
)


class CryptoModelsTest(unittest.TestCase):
    def test_signing_key_generation(self) -> None:
        keypair = generate_signing_keypair()
        self.assertIsInstance(keypair, SigningKeypair)
        self.assertEqual(keypair.metadata.algorithm, ALGORITHM_ED25519)
        self.assertTrue(keypair.metadata.active)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 32)

    def test_encryption_key_generation(self) -> None:
        keypair = generate_encryption_keypair()
        self.assertIsInstance(keypair, EncryptionKeypair)
        self.assertEqual(keypair.metadata.algorithm, ALGORITHM_X25519)
        self.assertTrue(keypair.metadata.active)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 32)

    def test_node_identity_generation(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        self.assertIsInstance(identity, NodeIdentity)
        self.assertEqual(identity.node_id, NODE_ID)
        self.assertIsInstance(identity.signing, SigningKeypair)
        self.assertIsInstance(identity.encryption, EncryptionKeypair)

    def test_key_id_generation_is_deterministic_from_public_key(self) -> None:
        keypair = generate_signing_keypair()
        key_id = key_id_for_public_key(
            algorithm=ALGORITHM_ED25519,
            public_key=keypair.public_key,
        )
        self.assertEqual(key_id, keypair.metadata.key_id)
        self.assertEqual(
            key_id,
            key_id_for_public_key(
                algorithm=ALGORITHM_ED25519,
                public_key=keypair.public_key,
            ),
        )

    def test_public_key_serialization_round_trip(self) -> None:
        keypair = generate_signing_keypair()
        payload = serialize_public_key(
            algorithm=keypair.metadata.algorithm,
            key=keypair.public_key,
        )
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["algorithm"], ALGORITHM_ED25519)
        self.assertEqual(
            deserialize_public_key(payload),
            (ALGORITHM_ED25519, keypair.public_key),
        )

    def test_private_key_serialization_round_trip(self) -> None:
        keypair = generate_encryption_keypair()
        payload = serialize_private_key(
            algorithm=keypair.metadata.algorithm,
            key=keypair.private_key,
        )
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["algorithm"], ALGORITHM_X25519)
        self.assertEqual(
            deserialize_private_key(payload),
            (ALGORITHM_X25519, keypair.private_key),
        )

    def test_unsupported_version_rejection(self) -> None:
        payload = serialize_public_key(algorithm=ALGORITHM_ED25519, key=b"k" * 32)
        payload["version"] = 2
        with self.assertRaises(ValueError):
            deserialize_public_key(payload)

    def test_unsupported_algorithm_rejection(self) -> None:
        with self.assertRaises(ValueError):
            serialize_public_key(algorithm="rsa", key=b"k" * 32)
        payload = serialize_public_key(algorithm=ALGORITHM_ED25519, key=b"k" * 32)
        payload["algorithm"] = "rsa"
        with self.assertRaises(ValueError):
            deserialize_public_key(payload)

    def test_invalid_key_size_rejection(self) -> None:
        with self.assertRaises(ValueError):
            serialize_private_key(algorithm=ALGORITHM_X25519, key=b"short")

        keypair = generate_signing_keypair()
        bad_metadata = KeyMetadata(
            key_id=keypair.metadata.key_id,
            algorithm=ALGORITHM_ED25519,
            created_at=keypair.metadata.created_at,
            active=True,
        )
        with self.assertRaises(ValueError):
            SigningKeypair(
                metadata=bad_metadata,
                private_key=b"short",
                public_key=keypair.public_key,
            )

    def test_keypair_rejects_mismatched_key_id(self) -> None:
        keypair = generate_signing_keypair()
        metadata = replace(keypair.metadata, key_id="wrong")
        with self.assertRaises(ValueError):
            SigningKeypair(
                metadata=metadata,
                private_key=keypair.private_key,
                public_key=keypair.public_key,
            )

    def test_keypair_rejects_wrong_algorithm(self) -> None:
        encryption = generate_encryption_keypair()
        with self.assertRaises(ValueError):
            SigningKeypair(
                metadata=encryption.metadata,
                private_key=encryption.private_key,
                public_key=encryption.public_key,
            )

    def test_immutable_dataclasses_behavior(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        with self.assertRaises(FrozenInstanceError):
            identity.node_id = "node-2"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            identity.signing.metadata.active = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
