from __future__ import annotations

import unittest

from secrets_kit.crypto.random import random_bytes


class CryptoRandomTest(unittest.TestCase):
    def test_random_bytes_returns_requested_length(self) -> None:
        self.assertEqual(len(random_bytes(32)), 32)

    def test_random_bytes_rejects_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            random_bytes(0)


if __name__ == "__main__":
    unittest.main()
