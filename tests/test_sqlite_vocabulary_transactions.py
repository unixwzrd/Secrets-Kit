"""SQLite vocabulary transaction replay."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV, set_sqlite_secret
from secrets_kit.backends.sqlite.connection import connect_sqlite, transaction
from secrets_kit.backends.sqlite.replay import SUPPORTED_REPLAY_TRANSACTION_TYPES, apply_transaction
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.transactions import create_transaction, insert_transaction
from secrets_kit.backends.sqlite.vocabulary_projections import (
    vocabulary_entry_kind_payload,
    vocabulary_entry_type_payload,
)
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.taxonomy.uuid import entry_kind_id_for_name, entry_type_id_for_name


class SqliteVocabularyTransactionsTest(unittest.TestCase):
    def test_vocabulary_types_supported_for_replay(self) -> None:
        self.assertIn("vocabulary.entry_type.upsert", SUPPORTED_REPLAY_TRANSACTION_TYPES)
        self.assertIn("vocabulary.entry_kind.upsert", SUPPORTED_REPLAY_TRANSACTION_TYPES)

    def test_secret_set_after_vocabulary_upserts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: db_path, "SECKIT_SQLITE_DEVELOPER_MODE": "1"},
                clear=False,
            ):
                conn = connect_sqlite(path=db_path)
                bootstrap_schema(conn=conn)
                with transaction(conn=conn):
                    for tx_type, payload in (
                        (
                            "vocabulary.entry_type.upsert",
                            vocabulary_entry_type_payload(
                                entry_type_id=entry_type_id_for_name(name="secret"),
                                name="secret",
                            ),
                        ),
                        (
                            "vocabulary.entry_kind.upsert",
                            vocabulary_entry_kind_payload(
                                entry_kind_id=entry_kind_id_for_name(name="jwt"),
                                name="jwt",
                            ),
                        ),
                    ):
                        tx = create_transaction(
                            transaction_id=f"tx-{tx_type}",
                            transaction_type=tx_type,
                            origin_node_id="node-test",
                            created_at=now_utc_iso(),
                            payload=payload,
                        )
                        insert_transaction(conn=conn, transaction=tx)
                        apply_transaction(conn=conn, transaction=tx)
                conn.close()

                meta = EntryMetadata(
                    name="JWT_KEY",
                    service="svc",
                    account="acct",
                    entry_type="secret",
                    entry_kind="jwt",
                    updated_at=now_utc_iso(),
                )
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="JWT_KEY",
                    value="token-value",
                    metadata=meta,
                    sqlite_dev_mode=True,
                )
                conn = connect_sqlite(path=db_path)
                kind_row = conn.execute(
                    "SELECT name FROM entry_kinds WHERE name = ?", ("jwt",)
                ).fetchone()
                conn.close()
                self.assertIsNotNone(kind_row)


if __name__ == "__main__":
    unittest.main()
