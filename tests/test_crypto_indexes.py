from __future__ import annotations

import unittest

from secrets_kit.crypto.indexes import blind_index, blind_index_hex


class CryptoIndexesTest(unittest.TestCase):
    def test_blind_index_is_deterministic(self) -> None:
        key = b"k" * 32
        self.assertEqual(
            blind_index(key=key, label="secret-name", value=" API_KEY "),
            blind_index(key=key, label="secret-name", value="api_key"),
        )

    def test_blind_index_changes_with_label(self) -> None:
        key = b"k" * 32
        self.assertNotEqual(
            blind_index(key=key, label="name", value="api_key"),
            blind_index(key=key, label="service", value="api_key"),
        )

    def test_blind_index_hex_matches_bytes(self) -> None:
        key = b"k" * 32
        self.assertEqual(
            blind_index_hex(key=key, label="name", value="api_key"),
            blind_index(key=key, label="name", value="api_key").hex(),
        )


if __name__ == "__main__":
    unittest.main()
