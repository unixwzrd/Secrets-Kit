"""Shared BackendStore contract checks (SQLite; Keychain optional on macOS)."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backend_store import INDEX_SCHEMA_VERSION, PAYLOAD_SCHEMA_VERSION, resolve_backend_store
from secrets_kit.keychain_backend import BACKEND_SQLITE
from secrets_kit.models import EntryMetadata

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.sqlite_backend import clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class SqliteBackendContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.db = Path(self._td.name) / "contract.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "backend-contract-passphrase-xx!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_capabilities_and_selective_resolve(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        cap = store.capabilities()
        self.assertTrue(cap.supports_safe_index)
        self.assertTrue(cap.supports_selective_resolve)
        self.assertEqual(cap.set_atomicity, "atomic")

    def test_crud_resolve_iter_index_has_no_locator_triple_in_safe_dict(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="KEY1", service="svc1", account="acct1")
        store.set_entry(service="svc1", account="acct1", name="KEY1", secret="secret1", metadata=meta)
        rows = [r.to_safe_dict() for r in store.iter_index()]
        self.assertEqual(len(rows), 1)
        blob = json.dumps(rows, sort_keys=True)
        self.assertNotIn("svc1", blob)
        self.assertNotIn("acct1", blob)
        self.assertNotIn("KEY1", blob)
        self.assertEqual(rows[0]["index_schema_version"], INDEX_SCHEMA_VERSION)
        self.assertEqual(rows[0]["payload_schema_version"], PAYLOAD_SCHEMA_VERSION)
        res = store.resolve_by_locator(service="svc1", account="acct1", name="KEY1")
        self.assertIsNotNone(res)
        assert res is not None
        self.assertEqual(res.secret, "secret1")
        self.assertEqual(res.metadata.name, "KEY1")

    def test_generation_increments_on_update(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="G", service="s", account="a")
        store.set_entry(service="s", account="a", name="G", secret="v1", metadata=meta)
        g1 = next(iter(store.iter_index())).generation
        store.set_entry(service="s", account="a", name="G", secret="v2", metadata=meta)
        g2 = next(iter(store.iter_index())).generation
        self.assertGreater(g2, g1)

    def test_rename_preserves_entry_id(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="R1", service="s", account="a")
        store.set_entry(service="s", account="a", name="R1", secret="x", metadata=meta)
        eid = next(iter(store.iter_index())).entry_id
        store.rename_entry(entry_id=eid, new_service="s2", new_account="a2", new_name="R2")
        res = store.resolve_by_entry_id(entry_id=eid)
        self.assertIsNotNone(res)
        assert res is not None
        self.assertEqual(res.metadata.entry_id, eid)
        self.assertEqual(res.metadata.name, "R2")

    def test_tombstone_delete_blocks_resolve(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="D", service="s", account="a")
        store.set_entry(service="s", account="a", name="D", secret="z", metadata=meta)
        store.delete_entry(service="s", account="a", name="D")
        self.assertIsNone(store.resolve_by_locator(service="s", account="a", name="D"))

    def test_rebuild_index_runs(self) -> None:
        store = resolve_backend_store(backend=BACKEND_SQLITE, path=str(self.db))
        meta = EntryMetadata(name="B", service="s", account="a")
        store.set_entry(service="s", account="a", name="B", secret="y", metadata=meta)
        store.rebuild_index()
        self.assertEqual(len(list(store.iter_index())), 1)


if __name__ == "__main__":
    unittest.main()
