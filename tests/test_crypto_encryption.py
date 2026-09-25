from __future__ import annotations

import unittest
from dataclasses import replace

from cryptography.exceptions import InvalidTag

from secrets_kit.crypto import decrypt_aead as root_decrypt_aead
from secrets_kit.crypto import encrypt_aead as root_encrypt_aead
from secrets_kit.crypto.codecs import CryptoHeader, EncryptedBlob
from secrets_kit.crypto.encryption import decrypt_aead, encrypt_aead
from secrets_kit.crypto.keys import generate_symmetric_key


class CryptoEncryptionTest(unittest.TestCase):
    def test_round_trip_succeeds(self) -> None:
        key = generate_symmetric_key()
        blob = encrypt_aead(key=key, plaintext=b"secret", aad=b"metadata")
        self.assertEqual(decrypt_aead(key=key, blob=blob, aad=b"metadata"), b"secret")
        self.assertEqual(len(blob.nonce), 12)
        self.assertEqual(blob.header.version, 1)
        self.assertEqual(blob.header.algorithm, "chacha20poly1305")

    def test_wrong_key_fails(self) -> None:
        blob = encrypt_aead(key=generate_symmetric_key(), plaintext=b"secret")
        with self.assertRaises(InvalidTag):
            decrypt_aead(key=generate_symmetric_key(), blob=blob)

    def test_wrong_aad_fails(self) -> None:
        key = generate_symmetric_key()
        blob = encrypt_aead(key=key, plaintext=b"secret", aad=b"metadata")
        with self.assertRaises(InvalidTag):
            decrypt_aead(key=key, blob=blob, aad=b"other")

    def test_tampered_ciphertext_fails(self) -> None:
        key = generate_symmetric_key()
        blob = encrypt_aead(key=key, plaintext=b"secret")
        tampered = replace(blob, ciphertext=blob.ciphertext[:-1] + bytes([blob.ciphertext[-1] ^ 1]))
        with self.assertRaises(InvalidTag):
            decrypt_aead(key=key, blob=tampered)

    def test_key_id_and_context_are_preserved(self) -> None:
        blob = encrypt_aead(
            key=generate_symmetric_key(),
            plaintext=b"secret",
            key_id="key-1",
            context="unit-test",
        )
        self.assertEqual(blob.header.key_id, "key-1")
        self.assertEqual(blob.header.context, "unit-test")

    def test_unsupported_algorithm_is_rejected_on_decrypt(self) -> None:
        key = generate_symmetric_key()
        blob = EncryptedBlob(
            header=CryptoHeader(version=1, algorithm="unsupported"),
            nonce=b"n" * 12,
            ciphertext=b"ciphertext",
        )
        with self.assertRaises(ValueError):
            decrypt_aead(key=key, blob=blob)

    def test_package_root_imports_work(self) -> None:
        key = generate_symmetric_key()
        blob = root_encrypt_aead(key=key, plaintext=b"secret", aad=b"metadata")
        self.assertEqual(root_decrypt_aead(key=key, blob=blob, aad=b"metadata"), b"secret")

    def test_invalid_key_size_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_aead(key=b"short", plaintext=b"secret")

    def test_invalid_nonce_size_is_rejected_on_decrypt(self) -> None:
        key = generate_symmetric_key()
        blob = encrypt_aead(key=key, plaintext=b"secret")
        with self.assertRaises(ValueError):
            decrypt_aead(key=key, blob=replace(blob, nonce=b"short"))


if __name__ == "__main__":
    unittest.main()
