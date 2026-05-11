"""Phase 5D: SECKIT_SQLITE_PLAINTEXT_DEBUG joint-payload storage (development only)."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest

if importlib.util.find_spec("nacl") is None:

    class SqlitePlaintextDebugTests(unittest.TestCase):
        def test_skip_without_nacl(self) -> None:
            self.skipTest("PyNaCl required")

else:
    from secrets_kit.backends.sqlite import PLAINTEXT_DEBUG_CRYPTO_VERSION, SqliteSecretStore, clear_sqlite_crypto_cache

    class SqlitePlaintextDebugTests(unittest.TestCase):
        def setUp(self) -> None:
            clear_sqlite_crypto_cache()
            self._dir = tempfile.TemporaryDirectory()
            self.db = os.path.join(self._dir.name, "pt.db")
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "unit-test-passphrase-32chars!"
            os.environ["SECKIT_SQLITE_PLAINTEXT_DEBUG"] = "1"

        def tearDown(self) -> None:
            clear_sqlite_crypto_cache()
            for k in ("SECKIT_SQLITE_PASSPHRASE", "SECKIT_SQLITE_PLAINTEXT_DEBUG"):
                if k in os.environ:
                    del os.environ[k]
            self._dir.cleanup()

        def test_roundtrip_and_metadata_crypto_version(self) -> None:
            store = SqliteSecretStore(db_path=self.db)
            store.set(
                service="s",
                account="a",
                name="K",
                value="secret-value",
                comment='{"name":"K","service":"s","account":"a"}',
                label="K",
            )
            self.assertEqual(store.get(service="s", account="a", name="K"), "secret-value")
            meta = store.metadata(service="s", account="a", name="K")
            self.assertEqual(int(meta["crypto_version"]), PLAINTEXT_DEBUG_CRYPTO_VERSION)
            posture = store.security_posture()
            self.assertFalse(posture.metadata_encrypted)

        def test_sqlite_row_has_zero_nonce_pattern(self) -> None:
            import sqlite3

            SqliteSecretStore(db_path=self.db).set(service="s", account="a", name="K", value="v", comment="{}")
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute(
                    "SELECT crypto_version, nonce FROM secrets WHERE name = 'K'",
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(int(row[0]), PLAINTEXT_DEBUG_CRYPTO_VERSION)
                self.assertEqual(row[1], b"\x00" * 24)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
