"""Security invariants: safe index and listings must not leak sensitive metadata fields."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.registry import resolve_backend_store
from tests.leakage_needles import LEAKAGE_NEEDLES
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.models.locator import opaque_locator_hint
from secrets_kit.models.core import EntryMetadata

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


_MARK_SOURCE = "SRCLEAKINV8833x"
_MARK_TAG = "TAGLEAKINV7722y"
_MARK_DOMAIN = "leaktest.invalid"
_MARK_KIND = "api_key"


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class SqliteSafeIndexLeakageTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.db = self.td / "vault.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "leakage-invariant-passphrase-test!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_sqlite_index_columns_exclude_sensitive_metadata_markers(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(
            name="LEAKTESTKEY",
            service="svc",
            account="ac",
            entry_kind=_MARK_KIND,  # type: ignore[arg-type]
            source=_MARK_SOURCE,
            source_url=f"https://{_MARK_DOMAIN}/p",
            source_label=_MARK_SOURCE,
            tags=[_MARK_TAG],
            domains=[_MARK_DOMAIN],
            comment='{"nested":"LEAKCOMMENT"}',
            custom={"k": "LEAKCUSTOM"},
        )
        store.set_entry(service="svc", account="ac", name="LEAKTESTKEY", secret="v1", metadata=meta)

        import sqlite3

        conn = sqlite3.connect(str(self.db))
        cur = conn.execute(
            """
            SELECT entry_id, locator_hash, locator_hint,
                   updated_at, deleted, deleted_at, generation, tombstone_generation, backend_version,
                   corrupt, corrupt_reason, last_validation_at
            FROM secrets
            """
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        concat = "|".join("" if c is None else str(c) for c in row)
        conn.close()

        for needle in (
            _MARK_SOURCE,
            _MARK_TAG,
            _MARK_DOMAIN,
            "LEAKCUSTOM",
            "LEAKCOMMENT",
            "nested",
            "entry_kind",
            _MARK_KIND,
            "source_url",
            "source_label",
            "LEAKTESTKEY",
        ):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, concat)

        eid = str(row[0])
        self.assertTrue(opaque_locator_hint(entry_id=eid).startswith("item-"))

    def test_sqlite_decrypt_free_iter_index_matches_safe_column_contract(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="N3", service="s3", account="a3", source=_MARK_SOURCE, tags=[_MARK_TAG])
        store.set_entry(service="s3", account="a3", name="N3", secret="z", metadata=meta)
        safe = [r.to_safe_dict() for r in store.iter_index()]
        blob = json.dumps(safe, sort_keys=True)
        self.assertNotIn(_MARK_SOURCE, blob)
        self.assertNotIn(_MARK_TAG, blob)
        self.assertNotIn("s3", blob)
        self.assertNotIn("N3", blob)

    def test_index_row_safe_dict_has_no_classification_keys(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(
            name="K2",
            service="s2",
            account="a2",
            source=_MARK_SOURCE,
            tags=[_MARK_TAG],
        )
        store.set_entry(service="s2", account="a2", name="K2", secret="x", metadata=meta)
        dumped = json.dumps([r.to_safe_dict() for r in store.iter_index()], sort_keys=True)
        self.assertNotIn(_MARK_SOURCE, dumped)
        self.assertNotIn(_MARK_TAG, dumped)
        self.assertNotIn("service", dumped)
        self.assertNotIn("account", dumped)
        self.assertNotIn("name", dumped)
        self.assertNotIn("backend_version", dumped)
        self.assertIn("backend_impl_version", dumped)

    def test_safe_surfaces_exclude_needles_in_repr_and_json(self) -> None:
        from secrets_kit.backends.base import PAYLOAD_SCHEMA_VERSION, IndexRow

        row = IndexRow(
            entry_id="550e8400-e29b-41d4-a716-446655440000",
            locator_hash="aa" * 32,
            locator_hint="item-adeda9",
            updated_at="2020-01-01T00:00:00Z",
            deleted=False,
            deleted_at="",
            generation=1,
            tombstone_generation=0,
            index_schema_version=1,
            payload_schema_version=PAYLOAD_SCHEMA_VERSION,
            backend_impl_version=1,
            payload_ref="row-x",
            corrupt=False,
            corrupt_reason="",
            last_validation_at="",
        )
        rtxt = repr(row)
        jtxt = json.dumps(row.to_safe_dict(), sort_keys=True)
        for needle in LEAKAGE_NEEDLES:
            self.assertNotIn(needle, rtxt)
            self.assertNotIn(needle, jtxt)


if __name__ == "__main__":
    unittest.main()
