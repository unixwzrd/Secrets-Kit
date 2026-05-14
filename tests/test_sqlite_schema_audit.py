"""SQLite schema version, audit table, and trigger behavior (unittest).

pytest can run this module; project CI uses ``python -m unittest discover``.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import tempfile
import unittest

if importlib.util.find_spec("nacl") is None:

    class SqliteSchemaAuditTest(unittest.TestCase):
        def test_pynacl_required(self) -> None:
            self.skipTest("Install project dependencies to run SQLite audit tests (pip install -e .)")

else:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
    from secrets_kit.backends.sqlite.schema import SQLITE_USER_VERSION_V3

    class SqliteSchemaAuditTest(unittest.TestCase):
        def setUp(self) -> None:
            clear_sqlite_crypto_cache()
            self._dir = tempfile.TemporaryDirectory()
            self.db = os.path.join(self._dir.name, "audit_test.db")
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "unit-test-passphrase-32chars!!"

        def tearDown(self) -> None:
            clear_sqlite_crypto_cache()
            if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
                del os.environ["SECKIT_SQLITE_PASSPHRASE"]
            self._dir.cleanup()

        def test_fresh_db_user_version_audit_table_triggers(self) -> None:
            store = SqliteSecretStore(db_path=self.db)
            # Opening via the store runs migrate_if_needed (constructor does not).
            conn = store._conn()
            try:
                ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
                self.assertEqual(ver, SQLITE_USER_VERSION_V3)
                cur = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='secrets_audit' LIMIT 1"
                )
                self.assertIsNotNone(cur.fetchone())
                trig = {
                    str(r[0])
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'secrets_audit_%'"
                    )
                }
                self.assertTrue(trig.issuperset({"secrets_audit_ai", "secrets_audit_au", "secrets_audit_ad"}))
                cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(secrets_audit)").fetchall()}
                self.assertNotIn("ciphertext", cols)
                self.assertNotIn("nonce", cols)
            finally:
                conn.close()

        def test_audit_rows_on_insert_and_tombstone_update(self) -> None:
            store = SqliteSecretStore(db_path=self.db)
            store.set(
                service="svc",
                account="acct",
                name="KEY",
                value="v1",
                comment='{"name":"KEY","service":"svc","account":"acct"}',
            )
            conn = sqlite3.connect(self.db)
            try:
                ops = [r[0] for r in conn.execute("SELECT operation FROM secrets_audit ORDER BY audit_id").fetchall()]
                self.assertIn("insert", ops)
                last = conn.execute(
                    "SELECT content_hash FROM secrets_audit WHERE operation='insert' ORDER BY audit_id DESC LIMIT 1"
                ).fetchone()
                self.assertIsNotNone(last)
            finally:
                conn.close()
            store.delete(service="svc", account="acct", name="KEY")
            conn = sqlite3.connect(self.db)
            try:
                ops = [r[0] for r in conn.execute("SELECT operation FROM secrets_audit ORDER BY audit_id").fetchall()]
                self.assertIn("update", ops)
                del_rows = [r for r in conn.execute(
                    "SELECT deleted FROM secrets_audit WHERE operation='update' ORDER BY audit_id"
                ).fetchall()]
                self.assertTrue(any(int(r[0]) == 1 for r in del_rows))
            finally:
                conn.close()

        def test_content_hash_column_persisted_on_row(self) -> None:
            store = SqliteSecretStore(db_path=self.db)
            store.set(service="s", account="a", name="N", value="x", comment='{"name":"N","service":"s","account":"a"}')
            conn = sqlite3.connect(self.db)
            try:
                row = conn.execute(
                    "SELECT content_hash FROM secrets WHERE service='s' AND account='a' AND name='N'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertTrue(str(row[0] or ""))
            finally:
                conn.close()
