from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from secrets_kit.crypto.canonical import canonical_json_text
from secrets_kit.crypto.records import (
    ALGORITHM_CHACHA20POLY1305,
    ALGORITHM_ED25519,
    ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305,
    CRYPTO_RECORD_VERSION,
    CiphertextRecord,
    SignatureRecord,
    WrappedKeyRecord,
    deserialize_ciphertext_record,
    deserialize_signature_record,
    deserialize_wrapped_key_record,
    serialize_ciphertext_record,
    serialize_signature_record,
    serialize_wrapped_key_record,
)


class CryptoRecordModelsTest(unittest.TestCase):
    def test_ciphertext_record_serialization_round_trip(self) -> None:
        record = CiphertextRecord(
            version=CRYPTO_RECORD_VERSION,
            algorithm=ALGORITHM_CHACHA20POLY1305,
            key_id="key-1",
            nonce=b"nonce",
            ciphertext=b"ciphertext",
            context="payload",
        )

        payload = serialize_ciphertext_record(record)

        self.assertEqual(deserialize_ciphertext_record(payload), record)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["algorithm"], ALGORITHM_CHACHA20POLY1305)

    def test_signature_record_serialization_round_trip(self) -> None:
        record = SignatureRecord(
            version=CRYPTO_RECORD_VERSION,
            algorithm=ALGORITHM_ED25519,
            key_id="signing-key-1",
            signature=b"signature",
            context="manifest",
        )

        payload = serialize_signature_record(record)

        self.assertEqual(deserialize_signature_record(payload), record)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["algorithm"], ALGORITHM_ED25519)

    def test_wrapped_key_record_serialization_round_trip(self) -> None:
        record = WrappedKeyRecord(
            version=CRYPTO_RECORD_VERSION,
            algorithm=ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305,
            key_id="recipient-key-1",
            nonce=b"nonce",
            wrapped_key=b"wrapped-key",
            context="export",
        )

        payload = serialize_wrapped_key_record(record)

        self.assertEqual(deserialize_wrapped_key_record(payload), record)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(
            payload["algorithm"],
            ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305,
        )

    def test_serialized_records_are_canonical_json_compatible(self) -> None:
        record = CiphertextRecord(
            version=CRYPTO_RECORD_VERSION,
            algorithm=ALGORITHM_CHACHA20POLY1305,
            key_id="key-1",
            nonce=b"nonce",
            ciphertext=b"ciphertext",
        )
        payload = serialize_ciphertext_record(record)

        self.assertEqual(canonical_json_text(payload), canonical_json_text(dict(reversed(payload.items()))))

    def test_unsupported_version_rejected(self) -> None:
        payload = serialize_signature_record(
            SignatureRecord(
                version=CRYPTO_RECORD_VERSION,
                algorithm=ALGORITHM_ED25519,
                key_id="key-1",
                signature=b"signature",
            )
        )
        payload["version"] = 2

        with self.assertRaises(ValueError):
            deserialize_signature_record(payload)

    def test_unsupported_algorithm_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CiphertextRecord(
                version=CRYPTO_RECORD_VERSION,
                algorithm="aes-gcm",
                key_id="key-1",
                nonce=b"nonce",
                ciphertext=b"ciphertext",
            )

        payload = serialize_wrapped_key_record(
            WrappedKeyRecord(
                version=CRYPTO_RECORD_VERSION,
                algorithm=ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305,
                key_id="key-1",
                nonce=b"nonce",
                wrapped_key=b"wrapped-key",
            )
        )
        payload["algorithm"] = "unsupported"

        with self.assertRaises(ValueError):
            deserialize_wrapped_key_record(payload)

    def test_missing_required_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            deserialize_ciphertext_record(
                {
                    "version": CRYPTO_RECORD_VERSION,
                    "algorithm": ALGORITHM_CHACHA20POLY1305,
                    "key_id": "key-1",
                    "nonce": "bm9uY2U",
                }
            )

    def test_empty_binary_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SignatureRecord(
                version=CRYPTO_RECORD_VERSION,
                algorithm=ALGORITHM_ED25519,
                key_id="key-1",
                signature=b"",
            )

    def test_invalid_base64_rejected(self) -> None:
        with self.assertRaises(ValueError):
            deserialize_wrapped_key_record(
                {
                    "version": CRYPTO_RECORD_VERSION,
                    "algorithm": ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305,
                    "key_id": "key-1",
                    "nonce": "not base64!",
                    "wrapped_key": "d3JhcHBlZA",
                }
            )

    def test_records_are_immutable(self) -> None:
        record = SignatureRecord(
            version=CRYPTO_RECORD_VERSION,
            algorithm=ALGORITHM_ED25519,
            key_id="key-1",
            signature=b"signature",
        )

        with self.assertRaises(FrozenInstanceError):
            record.key_id = "key-2"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
