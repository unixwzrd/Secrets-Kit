from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag

from secrets_kit.crypto.storage.sqlite import (
    SQLITE_STORAGE_KEY_ALGORITHM,
    SQLITE_STORAGE_KEY_ENV,
    SQLITE_STORAGE_KEY_VERSION,
    decrypt_payload,
    encrypt_payload,
)


class SQLiteStorageCodecTest(unittest.TestCase):
    def test_encrypt_decrypt_round_trip_uses_local_storage_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "home" / ".config" / "seckit" / "sqlite-storage.key"
            with mock.patch.dict(os.environ, {SQLITE_STORAGE_KEY_ENV: str(key_path)}, clear=False):
                encrypted = encrypt_payload(
                    plaintext=b"stored-secret",
                    field_name="encrypted_payload",
                )
                decrypted = decrypt_payload(stored=encrypted, field_name="encrypted_payload")

            self.assertNotEqual(encrypted, b"stored-secret")
            self.assertEqual(decrypted, b"stored-secret")
            self.assertTrue(key_path.exists())

            payload = json.loads(key_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], SQLITE_STORAGE_KEY_VERSION)
            self.assertEqual(payload["algorithm"], SQLITE_STORAGE_KEY_ALGORITHM)
            self.assertIsInstance(payload["created_at"], str)
            self.assertIsInstance(payload["key_b64"], str)

            config_mode = stat.S_IMODE(key_path.parent.stat().st_mode)
            key_mode = stat.S_IMODE(key_path.stat().st_mode)
            self.assertEqual(config_mode, 0o700)
            self.assertEqual(key_mode, 0o600)

    def test_field_context_is_bound_to_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "home" / ".config" / "seckit" / "sqlite-storage.key"
            with mock.patch.dict(os.environ, {SQLITE_STORAGE_KEY_ENV: str(key_path)}, clear=False):
                encrypted = encrypt_payload(
                    plaintext=b"OPENAI_API_KEY",
                    field_name="encrypted_name",
                )
                with self.assertRaises(InvalidTag):
                    decrypt_payload(stored=encrypted, field_name="encrypted_payload")


if __name__ == "__main__":
    unittest.main()
