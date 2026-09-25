from __future__ import annotations

import hashlib
import hmac
import unittest

from secrets_kit.crypto.hashing import hmac_sha256, sha256_bytes, sha256_hex


class CryptoHashingTest(unittest.TestCase):
    def test_sha256_helpers_match_stdlib(self) -> None:
        data = b"payload"
        self.assertEqual(sha256_bytes(data), hashlib.sha256(data).digest())
        self.assertEqual(sha256_hex(data), hashlib.sha256(data).hexdigest())

    def test_hmac_sha256_matches_stdlib(self) -> None:
        key = b"k" * 32
        data = b"payload"
        self.assertEqual(hmac_sha256(key, data), hmac.new(key, data, hashlib.sha256).digest())

    def test_hmac_sha256_rejects_empty_key(self) -> None:
        with self.assertRaises(ValueError):
            hmac_sha256(b"", b"payload")


if __name__ == "__main__":
    unittest.main()
