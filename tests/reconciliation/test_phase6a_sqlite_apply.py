"""SQLite apply integration: tombstone import and replay suppression."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from dataclasses import replace

from secrets_kit.backends.security import BACKEND_SQLITE, get_secret, secret_exists, set_secret
from secrets_kit.models.core import EntryMetadata
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.canonical_record import compute_record_content_hash
from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class Phase6aSqliteApplyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home = self.td / "h"
        self.home.mkdir(parents=True, exist_ok=True)
        self.db = self.home / "v.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "phase6a-sqlite-apply-test-passphrase!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_tombstone_import_deletes_and_replay_active_suppressed(self) -> None:
        ensure_registry_storage(home=self.home)
        set_secret(
            service="s",
            account="a",
            name="K",
            value="secret-val",
            path=str(self.db),
            backend=BACKEND_SQLITE,
        )
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st.resolve_by_locator(service="s", account="a", name="K")
        self.assertIsNotNone(r0)
        eid = r0.metadata.entry_id
        ls0 = st.read_lineage_snapshot(entry_id=eid)
        self.assertIsNotNone(ls0)
        self.assertFalse(ls0.deleted)

        meta = r0.metadata
        upsert_metadata(metadata=meta, home=self.home)

        tomb_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": max(ls0.generation, 1),
        }
        stats = apply_peer_sync_import(
            inner_entries=[tomb_row],
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(stats["tombstone_applied"], 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))

        ls1 = st.read_lineage_snapshot(entry_id=eid)
        self.assertIsNotNone(ls1)
        self.assertTrue(ls1.deleted)

        active_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "stale-active",
            "disposition": "active",
            "generation": ls1.generation - 1,
        }
        stats2 = apply_peer_sync_import(
            inner_entries=[active_row],
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(stats2["replay_suppressed"], 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))

    def test_import_renames_when_bundle_uses_new_locator_same_entry_id(self) -> None:
        ensure_registry_storage(home=self.home)
        set_secret(
            service="s",
            account="a",
            name="K",
            value="v0",
            path=str(self.db),
            backend=BACKEND_SQLITE,
        )
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st.resolve_by_locator(service="s", account="a", name="K")
        self.assertIsNotNone(r0)
        eid = r0.metadata.entry_id
        ls0 = st.read_lineage_snapshot(entry_id=eid)
        self.assertIsNotNone(ls0)
        meta0 = r0.metadata
        upsert_metadata(metadata=meta0, home=self.home)

        meta1 = replace(meta0, name="K2", entry_id=eid)
        ch = compute_record_content_hash(secret="v1", metadata=replace(meta1, content_hash=""))
        row = {
            "metadata": meta1.to_dict(),
            "origin_host": "peer-1",
            "value": "v1",
            "disposition": "active",
            "generation": ls0.generation + 1,
            "content_hash": ch,
        }
        stats = apply_peer_sync_import(
            inner_entries=[row],
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(stats["updated"], 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))
        self.assertTrue(secret_exists(service="s", account="a", name="K2", path=str(self.db), backend=BACKEND_SQLITE))
        self.assertEqual(get_secret(service="s", account="a", name="K2", path=str(self.db), backend=BACKEND_SQLITE), "v1")
        ls1 = st.read_lineage_snapshot(entry_id=eid)
        self.assertIsNotNone(ls1)
        self.assertEqual(ls1.name, "K2")

    def test_batch_continues_after_row_content_hash_mismatch(self) -> None:
        ensure_registry_storage(home=self.home)
        meta_bad = EntryMetadata(name="B", service="s", account="a")
        row_bad = {
            "metadata": meta_bad.to_dict(),
            "origin_host": "peer-1",
            "value": "vb",
            "disposition": "active",
            "generation": 1,
            "content_hash": "aa" * 32,
        }
        meta_ok = EntryMetadata(name="G", service="s", account="a")
        ch_ok = compute_record_content_hash(secret="vg", metadata=replace(meta_ok, content_hash=""))
        row_ok = {
            "metadata": meta_ok.to_dict(),
            "origin_host": "peer-1",
            "value": "vg",
            "disposition": "active",
            "generation": 1,
            "content_hash": ch_ok,
        }
        stats = apply_peer_sync_import(
            inner_entries=[row_bad, row_ok],
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(stats["hash_conflicts"], 1)
        self.assertGreaterEqual(stats["conflicts"], 1)
        self.assertGreaterEqual(stats["created"], 1)
        details = stats.get("hash_conflict_details")
        self.assertIsInstance(details, list)
        assert isinstance(details, list)
        self.assertGreaterEqual(len(details), 1)
        self.assertEqual(details[0].get("reason"), "content_hash_mismatch")
        self.assertIn("declared_content_hash", details[0])
        self.assertIn("computed_content_hash", details[0])
        self.assertTrue(secret_exists(service="s", account="a", name="G", path=str(self.db), backend=BACKEND_SQLITE))

    def test_run_reconcile_transaction_rolls_back_on_error(self) -> None:
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)

        def _boom(_conn: object) -> None:
            raise RuntimeError("deliberate")

        with self.assertRaises(RuntimeError):
            st.run_reconcile_transaction(_boom)
        # Store remains usable (no partial txn left open — smoke open)
        st.capabilities()


if __name__ == "__main__":
    unittest.main()
