"""Contract checks for canonical SQLite query composition (unittest)."""

from __future__ import annotations

import unittest

from secrets_kit.backends.sqlite.queries import (
    SECRETS_COLUMNS_FULL_ROW,
    SECRETS_COLUMNS_INDEX_SAFE,
    SECRETS_COLUMNS_LINEAGE,
    SECRETS_COLUMNS_RECONCILE_INDEX,
    sql_select_full_row_by_entry_id,
    sql_select_iter_index,
)


class SqliteQueriesTest(unittest.TestCase):
    def test_iter_index_select_contains_index_columns_in_order(self) -> None:
        sql = " ".join(sql_select_iter_index().split())
        pos = 0
        for col in SECRETS_COLUMNS_INDEX_SAFE:
            idx = sql.find(col, pos)
            self.assertGreaterEqual(idx, 0, f"missing column {col!r} in {sql!r}")
            pos = idx + len(col)

    def test_full_row_select_matches_tuple_length(self) -> None:
        sql = sql_select_full_row_by_entry_id()
        for col in SECRETS_COLUMNS_FULL_ROW:
            self.assertIn(col, sql)

    def test_lineage_and_reconcile_are_distinct(self) -> None:
        self.assertNotEqual(SECRETS_COLUMNS_LINEAGE, SECRETS_COLUMNS_RECONCILE_INDEX)

if __name__ == "__main__":
    unittest.main()
