from __future__ import annotations

import unittest

from secrets_kit.crypto.cli.export_json import (
    build_plain_export,
    decrypt_payload,
    encrypt_payload,
    ensure_crypto_available,
)


class CryptoExportJsonTest(unittest.TestCase):
    def test_roundtrip_encrypt_decrypt(self) -> None:
        ensure_crypto_available()
        plain = build_plain_export(
            entries=[
                {
                    "metadata": {"name": "DEMO", "service": "svc", "account": "acct"},
                    "value": "secret",
                }
            ]
        )
        encrypted = encrypt_payload(payload=plain, password="test-pass")
        decrypted = decrypt_payload(payload=encrypted.__dict__, password="test-pass")
        self.assertEqual(decrypted["format"], "seckit.export")
        self.assertEqual(decrypted["entries"], plain["entries"])


if __name__ == "__main__":
    unittest.main()
