from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest

from secrets_kit.backends.base import resolve_backend_store
from secrets_kit.backends.security import BACKEND_SQLITE, BackendError, get_secret, set_secret

# Importing secrets_kit.backends.sqlite requires PyNaCl; keep collection working without it.
if importlib.util.find_spec("nacl") is None:

    class SqliteBackendTest(unittest.TestCase):
        def test_pynacl_required_for_sqlite_tests(self) -> None:
            self.skipTest("Install project dependencies to run SQLite backend tests (pip install -e .)")

else:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache, default_sqlite_db_path, iter_secrets_plaintext_index

    class SqliteBackendTest(unittest.TestCase):
        def setUp(self) -> None:
            clear_sqlite_crypto_cache()
            self._dir = tempfile.TemporaryDirectory()
            self.db = os.path.join(self._dir.name, "test.db")
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "unit-test-passphrase-32chars!"

        def tearDown(self) -> None:
            clear_sqlite_crypto_cache()
            if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
                del os.environ["SECKIT_SQLITE_PASSPHRASE"]
            self._dir.cleanup()

        def test_roundtrip_set_get_delete_metadata(self) -> None:
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
            self.assertNotIn("secret-value", str(meta))
            import json

            comment_obj = json.loads(meta["comment"])
            self.assertEqual(comment_obj["name"], "K")
            self.assertEqual(comment_obj["service"], "s")
            self.assertEqual(comment_obj["account"], "a")
            self.assertTrue(comment_obj.get("entry_id"))
            self.assertIn("sqlite_updated_at", meta)
            self.assertIn("origin_host", meta)
            self.assertEqual(meta["crypto_version"], 1)
            store.delete(service="s", account="a", name="K")
            self.assertFalse(store.exists(service="s", account="a", name="K"))

        def test_wrong_passphrase_decrypt_fails(self) -> None:
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "correct-passphrase-here!!"
            store = SqliteSecretStore(db_path=self.db)
            store.set(service="s", account="a", name="K", value="x")
            clear_sqlite_crypto_cache()
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "wrong-passphrase-here!!!!"
            store2 = SqliteSecretStore(db_path=self.db)
            with self.assertRaisesRegex(BackendError, "decryption failed"):
                store2.get(service="s", account="a", name="K")

        def test_tampered_ciphertext_fails(self) -> None:
            import sqlite3

            store = SqliteSecretStore(db_path=self.db)
            store.set(service="s", account="a", name="K", value="x")
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute("SELECT ciphertext FROM secrets WHERE name = 'K'").fetchone()
                self.assertIsNotNone(row)
                bad = bytearray(row[0])
                bad[0] ^= 0xFF
                conn.execute("UPDATE secrets SET ciphertext = ? WHERE name = 'K'", (bytes(bad),))
                conn.commit()
            finally:
                conn.close()
            clear_sqlite_crypto_cache()
            store2 = SqliteSecretStore(db_path=self.db)
            with self.assertRaisesRegex(BackendError, "decryption failed"):
                store2.get(service="s", account="a", name="K")

        def test_module_level_helpers_and_resolve(self) -> None:
            set_secret(service="svc", account="acct", name="N", value="v", path=self.db, backend=BACKEND_SQLITE)
            self.assertEqual(
                get_secret(service="svc", account="acct", name="N", path=self.db, backend=BACKEND_SQLITE),
                "v",
            )
            store = resolve_backend_store(backend=BACKEND_SQLITE, path=self.db)
            self.assertIsInstance(store, SqliteSecretStore)

        def test_plaintext_index_for_recover(self) -> None:
            store = SqliteSecretStore(db_path=self.db)
            store.set(
                service="hermes",
                account="miafour",
                name="API_KEY",
                value="s",
                comment='{"name":"API_KEY","service":"hermes","account":"miafour","entry_type":"secret"}',
            )
            store.set(
                service="other",
                account="miafour",
                name="OTHER_KEY",
                value="t",
                comment="",
            )
            all_rows = list(iter_secrets_plaintext_index(db_path=self.db))
            self.assertEqual(len(all_rows), 2)
            filtered = list(iter_secrets_plaintext_index(db_path=self.db, service_filter="hermes"))
            self.assertEqual(len(filtered), 1)
            self.assertEqual(filtered[0].name, "API_KEY")

        def test_default_sqlite_db_path(self) -> None:
            p = default_sqlite_db_path()
            self.assertTrue(p.endswith("secrets.db"))


if __name__ == "__main__":
    unittest.main()
