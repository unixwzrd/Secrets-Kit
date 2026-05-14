"""Operational audit constants stay aligned with schema DDL (unittest)."""

from __future__ import annotations

import sqlite3
import unittest

from secrets_kit.backends.sqlite.audit import (
    SECRETS_AUDIT_TABLE,
    SECRETS_AUDIT_TRIGGER_AFTER_DELETE,
    SECRETS_AUDIT_TRIGGER_AFTER_INSERT,
    SECRETS_AUDIT_TRIGGER_AFTER_UPDATE,
    count_audit_rows,
    fetch_audit_tail,
)
from secrets_kit.backends.sqlite.schema import AUDIT_TRIGGERS_SQL, SECRETS_AUDIT_TABLE_SQL


class SqliteAuditConstantsTest(unittest.TestCase):
    def test_trigger_names_embedded_in_canonical_ddl(self) -> None:
        for name in (
            SECRETS_AUDIT_TRIGGER_AFTER_INSERT,
            SECRETS_AUDIT_TRIGGER_AFTER_UPDATE,
            SECRETS_AUDIT_TRIGGER_AFTER_DELETE,
        ):
            self.assertIn(name, AUDIT_TRIGGERS_SQL)
        self.assertIn(SECRETS_AUDIT_TABLE, SECRETS_AUDIT_TABLE_SQL)

    def test_count_audit_rows_none_without_table(self) -> None:
        conn = sqlite3.connect(":memory:")
        self.assertIsNone(count_audit_rows(conn=conn))

    def test_fetch_audit_tail_restores_row_factory(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t(x INTEGER)")
        self.assertIsNone(conn.row_factory)
        with self.assertRaises(sqlite3.OperationalError):
            fetch_audit_tail(conn=conn, limit=1)
        self.assertIsNone(conn.row_factory)


if __name__ == "__main__":
    unittest.main()
