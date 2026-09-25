from __future__ import annotations

import unittest

from secrets_kit.crypto.keyring import create_keyring
from secrets_kit.crypto.models import (
    ALGORITHM_ED25519,
    generate_encryption_keypair,
    generate_signing_keypair,
)
from secrets_kit.crypto.transaction_signing import (
    TransactionSignature,
    sign_payload,
    sign_payload_with_keyring,
    verify_payload,
)


class CryptoTransactionSigningTest(unittest.TestCase):
    def test_sign_verify_round_trip(self) -> None:
        keypair = generate_signing_keypair()
        payload = {"transaction_id": "txn-1", "payload": {"name": "secret"}}

        signature = sign_payload(keypair=keypair, payload=payload)

        self.assertTrue(
            verify_payload(
                public_key=keypair.public_key,
                payload=payload,
                signature=signature,
            )
        )

    def test_payload_tampering_fails(self) -> None:
        keypair = generate_signing_keypair()
        payload = {"transaction_id": "txn-1", "payload": {"name": "secret"}}
        signature = sign_payload(keypair=keypair, payload=payload)

        self.assertFalse(
            verify_payload(
                public_key=keypair.public_key,
                payload={"transaction_id": "txn-1", "payload": {"name": "other"}},
                signature=signature,
            )
        )

    def test_wrong_public_key_fails(self) -> None:
        keypair = generate_signing_keypair()
        other_keypair = generate_signing_keypair()
        payload = {"transaction_id": "txn-1"}
        signature = sign_payload(keypair=keypair, payload=payload)

        self.assertFalse(
            verify_payload(
                public_key=other_keypair.public_key,
                payload=payload,
                signature=signature,
            )
        )

    def test_key_id_and_algorithm_preserved(self) -> None:
        keypair = generate_signing_keypair()
        signature = sign_payload(keypair=keypair, payload={"transaction_id": "txn-1"})

        self.assertEqual(signature.key_id, keypair.metadata.key_id)
        self.assertEqual(signature.algorithm, ALGORITHM_ED25519)
        self.assertTrue(signature.created_at.endswith("Z"))

    def test_active_key_signing_through_keyring(self) -> None:
        keyring = create_keyring()
        inactive_keypair = generate_signing_keypair()
        active_keypair = generate_signing_keypair()
        keyring.add_signing_keypair(inactive_keypair)
        keyring.add_signing_keypair(active_keypair)

        signature = sign_payload_with_keyring(
            keyring=keyring,
            payload={"transaction_id": "txn-1"},
        )

        self.assertEqual(signature.key_id, active_keypair.metadata.key_id)
        self.assertTrue(
            verify_payload(
                public_key=active_keypair.public_key,
                payload={"transaction_id": "txn-1"},
                signature=signature,
            )
        )

    def test_no_active_key_failure(self) -> None:
        keyring = create_keyring()
        keypair = generate_signing_keypair()
        keyring.add_signing_keypair(keypair)
        keyring.deactivate(keypair.metadata.key_id)

        with self.assertRaises(ValueError):
            sign_payload_with_keyring(keyring=keyring, payload={"transaction_id": "txn-1"})

    def test_deterministic_canonicalization_behavior(self) -> None:
        keypair = generate_signing_keypair()
        payload = {"b": 2, "a": {"d": 4, "c": 3}}
        same_payload_different_order = {"a": {"c": 3, "d": 4}, "b": 2}

        signature = sign_payload(keypair=keypair, payload=payload)

        self.assertTrue(
            verify_payload(
                public_key=keypair.public_key,
                payload=same_payload_different_order,
                signature=signature,
            )
        )

    def test_transaction_signature_validation(self) -> None:
        with self.assertRaises(ValueError):
            TransactionSignature(
                key_id="",
                signature=b"signature",
                algorithm=ALGORITHM_ED25519,
                created_at="2026-06-12T00:00:00Z",
            )
        with self.assertRaises(ValueError):
            TransactionSignature(
                key_id="key-1",
                signature=b"",
                algorithm=ALGORITHM_ED25519,
                created_at="2026-06-12T00:00:00Z",
            )
        with self.assertRaises(ValueError):
            TransactionSignature(
                key_id="key-1",
                signature=b"signature",
                algorithm="rsa",
                created_at="2026-06-12T00:00:00Z",
            )

    def test_non_signing_keypair_rejected(self) -> None:
        with self.assertRaises(TypeError):
            sign_payload(
                keypair=generate_encryption_keypair(),  # type: ignore[arg-type]
                payload={"transaction_id": "txn-1"},
            )


if __name__ == "__main__":
    unittest.main()
