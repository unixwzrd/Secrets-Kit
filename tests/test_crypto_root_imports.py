from __future__ import annotations

import unittest

from secrets_kit.crypto import (
    CiphertextRecord,
    CryptoHeader,
    CryptoUnavailable,
    EncryptedBlob,
    EncryptionKeypair,
    InMemoryKeyring,
    InMemoryKeyStore,
    KeyMetadata,
    KeyStore,
    NodeIdentity,
    SignatureRecord,
    SigningKeypair,
    TransactionSignature,
    WrappedKeyRecord,
    blind_index,
    blind_index_hex,
    decode_b64url,
    decode_encrypted_blob,
    derive_hkdf_sha256,
    derive_x25519_shared_key,
    encode_b64url,
    encode_encrypted_blob,
    generate_ed25519_keypair,
    generate_symmetric_key,
    generate_x25519_keypair,
    hmac_sha256,
    random_bytes,
    sha256_bytes,
    sha256_hex,
    sign_ed25519,
    sign_payload,
    sign_payload_with_keyring,
    verify_ed25519,
    verify_payload,
)


class CryptoRootImportsTest(unittest.TestCase):
    def test_root_exports_crypto_helpers(self) -> None:
        key = generate_symmetric_key()
        self.assertEqual(len(key), 32)
        self.assertEqual(len(random_bytes(8)), 8)
        self.assertEqual(len(sha256_bytes(b"data")), 32)
        self.assertEqual(sha256_hex(b"data"), sha256_bytes(b"data").hex())
        self.assertEqual(len(hmac_sha256(key, b"data")), 32)
        self.assertEqual(blind_index_hex(key, "label", "value"), blind_index(key, "label", "value").hex())

        private_key, public_key = generate_ed25519_keypair()
        signature = sign_ed25519(private_key, b"message")
        self.assertTrue(verify_ed25519(public_key, b"message", signature))

        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()
        self.assertEqual(
            derive_x25519_shared_key(alice_private, bob_public, b"context"),
            derive_x25519_shared_key(bob_private, alice_public, b"context"),
        )
        self.assertEqual(len(derive_hkdf_sha256(key, b"context")), 32)

        encoded = encode_b64url(b"data")
        self.assertEqual(decode_b64url(encoded), b"data")

        blob = EncryptedBlob(
            header=CryptoHeader(version=1, algorithm="test"),
            nonce=b"nonce",
            ciphertext=b"ciphertext",
        )
        self.assertEqual(decode_encrypted_blob(encode_encrypted_blob(blob)), blob)
        self.assertTrue(issubclass(CryptoUnavailable, RuntimeError))

    def test_root_exports_crypto_models_and_key_management(self) -> None:
        signing = SigningKeypair
        encryption = EncryptionKeypair
        metadata = KeyMetadata(
            key_id="key-1",
            algorithm="ed25519",
            created_at="2026-06-13T00:00:00Z",
            active=True,
        )
        self.assertEqual(metadata.key_id, "key-1")
        self.assertEqual(signing.__name__, "SigningKeypair")
        self.assertEqual(encryption.__name__, "EncryptionKeypair")
        self.assertEqual(NodeIdentity.__name__, "NodeIdentity")
        self.assertTrue(issubclass(InMemoryKeyStore, KeyStore))
        self.assertEqual(InMemoryKeyring.__name__, "InMemoryKeyring")

    def test_root_exports_record_models(self) -> None:
        ciphertext = CiphertextRecord(
            version=1,
            algorithm="chacha20poly1305",
            key_id="key-1",
            nonce=b"nonce",
            ciphertext=b"ciphertext",
        )
        signature = SignatureRecord(
            version=1,
            algorithm="ed25519",
            key_id="key-1",
            signature=b"signature",
        )
        wrapped = WrappedKeyRecord(
            version=1,
            algorithm="x25519-hkdf-sha256-chacha20poly1305",
            key_id="key-1",
            nonce=b"nonce",
            wrapped_key=b"wrapped",
        )
        self.assertEqual(ciphertext.key_id, "key-1")
        self.assertEqual(signature.algorithm, "ed25519")
        self.assertEqual(wrapped.wrapped_key, b"wrapped")

    def test_root_exports_transaction_signing_helpers(self) -> None:
        from secrets_kit.crypto.models import generate_signing_keypair

        keypair = generate_signing_keypair()
        payload = {"transaction_id": "txn-1"}
        signature = sign_payload(keypair=keypair, payload=payload)

        self.assertIsInstance(signature, TransactionSignature)
        self.assertTrue(
            verify_payload(
                public_key=keypair.public_key,
                payload=payload,
                signature=signature,
            )
        )

        keyring = InMemoryKeyring()
        keyring.add_signing_keypair(keypair)
        self.assertEqual(
            sign_payload_with_keyring(keyring=keyring, payload=payload).key_id,
            keypair.metadata.key_id,
        )


if __name__ == "__main__":
    unittest.main()
