from __future__ import annotations

import unittest

from secrets_kit.crypto.codecs import (
    CryptoHeader,
    EncryptedBlob,
    decode_b64url,
    decode_encrypted_blob,
    encode_b64url,
    encode_encrypted_blob,
)


class CryptoCodecsTest(unittest.TestCase):
    def test_b64url_roundtrip_omits_padding(self) -> None:
        encoded = encode_b64url(b"\x00\x01test")
        self.assertNotIn("=", encoded)
        self.assertEqual(decode_b64url(encoded), b"\x00\x01test")

    def test_encrypted_blob_roundtrip(self) -> None:
        blob = EncryptedBlob(
            header=CryptoHeader(
                version=1,
                algorithm="test-aead",
                key_id="key-1",
                context="unit-test",
            ),
            nonce=b"n" * 24,
            ciphertext=b"ciphertext",
        )
        encoded = encode_encrypted_blob(blob)
        decoded = decode_encrypted_blob(encoded)
        self.assertEqual(decoded, blob)

    def test_encrypted_blob_encoding_is_deterministic(self) -> None:
        blob = EncryptedBlob(
            header=CryptoHeader(version=1, algorithm="test-aead"),
            nonce=b"n" * 24,
            ciphertext=b"ciphertext",
        )
        self.assertEqual(encode_encrypted_blob(blob), encode_encrypted_blob(blob))

    def test_encrypted_blob_rejects_unsupported_version(self) -> None:
        blob = EncryptedBlob(
            header=CryptoHeader(version=999, algorithm="test-aead"),
            nonce=b"n" * 24,
            ciphertext=b"ciphertext",
        )
        with self.assertRaises(ValueError):
            encode_encrypted_blob(blob)


if __name__ == "__main__":
    unittest.main()
