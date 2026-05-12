"""Operational checks for ``sqlite_reconcile_verify`` (synthetic corrupted DBs)."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.sync.sqlite_verify import sqlite_reconcile_verify


def _minimal_secrets_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE secrets (
            entry_id TEXT NOT NULL,
            service TEXT NOT NULL,
            account TEXT NOT NULL,
            name TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            generation INTEGER NOT NULL DEFAULT 1,
            tombstone_generation INTEGER NOT NULL DEFAULT 0,
            content_hash TEXT NOT NULL DEFAULT ''
        )
        """
    )


class SqliteVerifyOperationalTest(unittest.TestCase):
    def test_secrets_row_locator_collision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "t.db"
            conn = sqlite3.connect(str(db))
            _minimal_secrets_schema(conn)
            conn.execute(
                "INSERT INTO secrets(entry_id, service, account, name, deleted, generation, tombstone_generation, content_hash) VALUES (?,?,?,?,?,?,?,?)",
                ("id-a", "s", "a", "n", 0, 1, 0, "aa"),
            )
            conn.execute(
                "INSERT INTO secrets(entry_id, service, account, name, deleted, generation, tombstone_generation, content_hash) VALUES (?,?,?,?,?,?,?,?)",
                ("id-b", "s", "a", "n", 0, 1, 0, "bb"),
            )
            conn.commit()
            conn.close()
            report = sqlite_reconcile_verify(db_path=str(db))
            codes = [i["code"] for i in report["issues"]]
            self.assertIn("secrets_row_locator_collision", codes)

    def test_content_hash_empty_on_active_strict_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "t.db"
            conn = sqlite3.connect(str(db))
            _minimal_secrets_schema(conn)
            conn.execute(
                "INSERT INTO secrets(entry_id, service, account, name, deleted, generation, tombstone_generation, content_hash) VALUES (?,?,?,?,?,?,?,?)",
                ("id-a", "s", "a", "n", 0, 2, 0, ""),
            )
            conn.commit()
            conn.close()
            relaxed = sqlite_reconcile_verify(db_path=str(db), strict_content_hash=False)
            strict = sqlite_reconcile_verify(db_path=str(db), strict_content_hash=True)
            r_codes = [i["code"] for i in relaxed["issues"]]
            s_codes = [i["code"] for i in strict["issues"]]
            self.assertNotIn("content_hash_empty_on_active", r_codes)
            self.assertIn("content_hash_empty_on_active", s_codes)


if __name__ == "__main__":
    unittest.main()
