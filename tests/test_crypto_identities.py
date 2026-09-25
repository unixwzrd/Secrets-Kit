from __future__ import annotations

import unittest

from secrets_kit.crypto.identities import (
    NodeIdentity,
    generate_node_identity,
    node_identity_from_dict,
    node_identity_to_dict,
)
from secrets_kit.identifiers import deterministic_identifier

NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="node-1"
)


class CryptoIdentitiesTest(unittest.TestCase):
    def test_generate_node_identity(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        self.assertIsInstance(identity, NodeIdentity)
        self.assertEqual(identity.node_id, NODE_ID)

    def test_node_identity_key_lengths(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        self.assertEqual(len(identity.signing.private_key), 32)
        self.assertEqual(len(identity.signing.public_key), 32)
        self.assertEqual(len(identity.encryption.private_key), 32)
        self.assertEqual(len(identity.encryption.public_key), 32)

    def test_node_identity_serialization_roundtrip(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        self.assertEqual(node_identity_from_dict(value=node_identity_to_dict(identity=identity)), identity)
        self.assertEqual(NodeIdentity.from_dict(identity.to_dict()), identity)

    def test_signing_and_encryption_keypairs_are_distinct(self) -> None:
        identity = generate_node_identity(node_id=NODE_ID)
        self.assertNotEqual(identity.signing.private_key, identity.encryption.private_key)
        self.assertNotEqual(identity.signing.public_key, identity.encryption.public_key)

    def test_node_identity_rejects_unsupported_version(self) -> None:
        payload = generate_node_identity(node_id=NODE_ID).to_dict()
        payload["version"] = 999
        with self.assertRaises(ValueError):
            node_identity_from_dict(value=payload)


if __name__ == "__main__":
    unittest.main()
