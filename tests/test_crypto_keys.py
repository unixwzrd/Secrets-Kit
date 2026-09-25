from __future__ import annotations

import unittest

from secrets_kit.crypto.keys import (
    derive_hkdf_sha256,
    derive_x25519_shared_key,
    generate_symmetric_key,
    generate_x25519_keypair,
)


class CryptoKeysTest(unittest.TestCase):
    def test_generate_symmetric_key_returns_32_bytes(self) -> None:
        self.assertEqual(len(generate_symmetric_key()), 32)

    def test_hkdf_changes_with_context(self) -> None:
        root_key = b"r" * 32
        first = derive_hkdf_sha256(root_key=root_key, context=b"context-1")
        second = derive_hkdf_sha256(root_key=root_key, context=b"context-2")
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 32)

    def test_x25519_shared_key_matches_on_both_sides(self) -> None:
        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()
        alice_key = derive_x25519_shared_key(
            private_key=alice_private,
            peer_public_key=bob_public,
            context=b"seckit-test",
        )
        bob_key = derive_x25519_shared_key(
            private_key=bob_private,
            peer_public_key=alice_public,
            context=b"seckit-test",
        )
        self.assertEqual(alice_key, bob_key)


if __name__ == "__main__":
    unittest.main()
