"""SQLite entry type/kind vocabulary and tag assignment tables."""

from __future__ import annotations

import os
import re
import tempfile
import unittest
import uuid
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV, set_sqlite_secret
from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.taxonomy import entry_type_id_for_name, tag_id_for_name
from secrets_kit.models import EntryMetadata, now_utc_iso

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class SqliteTaxonomyTest(unittest.TestCase):
    def test_bootstrap_seeds_type_kind_with_uuid_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "seckit.sqlite")
            conn = connect_sqlite(path=path)
            bootstrap_schema(conn=conn)
            types = conn.execute("SELECT entry_type_id, name FROM entry_types").fetchall()
            kinds = conn.execute("SELECT entry_kind_id, name FROM entry_kinds").fetchall()
            conn.close()
            type_names = {row["name"] for row in types}
            self.assertIn("secret", type_names)
            self.assertIn("pii", type_names)
            for row in types:
                self.assertRegex(row["entry_type_id"], _UUID_RE)
                self.assertEqual(row["entry_type_id"], entry_type_id_for_name(name=row["name"]))
            for row in kinds:
                self.assertRegex(row["entry_kind_id"], _UUID_RE)
            self.assertIn("api_key", {row["name"] for row in kinds})

    def test_set_secret_syncs_tag_assignments_by_uuid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: db_path, "SECKIT_SQLITE_DEVELOPER_MODE": "1"},
                clear=False,
            ):
                meta = EntryMetadata(
                    name="TAGGED_KEY",
                    service="svc",
                    account="acct",
                    entry_type="secret",
                    entry_kind="api_key",
                    tags=["prod", "openai"],
                    updated_at=now_utc_iso(),
                )
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="TAGGED_KEY",
                    value="v",
                    metadata=meta,
                    sqlite_dev_mode=True,
                )
                conn = connect_sqlite(path=db_path)
                secret_row = conn.execute(
                    """
                    SELECT secret_id, entry_type_id, entry_kind_id
                    FROM secrets
                    WHERE state = 'active'
                    """
                ).fetchone()
                self.assertRegex(secret_row["entry_type_id"], _UUID_RE)
                self.assertRegex(secret_row["entry_kind_id"], _UUID_RE)
                rows = conn.execute(
                    """
                    SELECT st.tag_id, st.name
                    FROM secret_tag_assignments sta
                    JOIN secret_tags st ON st.tag_id = sta.tag_id
                    WHERE sta.secret_id = ?
                    ORDER BY st.name
                    """,
                    (secret_row["secret_id"],),
                ).fetchall()
                conn.close()
                self.assertEqual([row["name"] for row in rows], ["openai", "prod"])
                for row in rows:
                    self.assertRegex(row["tag_id"], _UUID_RE)

    def test_tag_id_is_stable_for_same_name(self) -> None:
        self.assertEqual(
            tag_id_for_name(name="Prod"),
            tag_id_for_name(name="prod"),
        )
        uuid.UUID(tag_id_for_name(name="prod"))


if __name__ == "__main__":
    unittest.main()
