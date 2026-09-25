from __future__ import annotations

import unittest

from secrets_kit.crypto.signatures import (
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
)


class CryptoSignaturesTest(unittest.TestCase):
    def test_ed25519_sign_verify_roundtrip(self) -> None:
        private_key, public_key = generate_ed25519_keypair()
        signature = sign_ed25519(private_key, b"message")
        self.assertTrue(verify_ed25519(public_key, b"message", signature))

    def test_ed25519_verify_rejects_tampered_message(self) -> None:
        private_key, public_key = generate_ed25519_keypair()
        signature = sign_ed25519(private_key, b"message")
        self.assertFalse(verify_ed25519(public_key, b"other", signature))

    def test_ed25519_rejects_invalid_private_key_size(self) -> None:
        with self.assertRaises(ValueError):
            sign_ed25519(b"short", b"message")


if __name__ == "__main__":
    unittest.main()
