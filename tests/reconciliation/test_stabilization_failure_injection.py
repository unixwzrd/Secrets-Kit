"""Mid-reconcile failure injection: SQLite transactions must roll back deterministically."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secrets_kit.backends.security import BACKEND_SQLITE, get_secret, secret_exists, set_secret
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class StabilizationFailureInjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home = self.td / "h"
        self.home.mkdir(parents=True, exist_ok=True)
        self.db = self.home / "v.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "stabilization-failure-injection-test-passphrase!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_active_apply_rolls_back_when_set_entry_fails(self) -> None:
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
        meta = r0.metadata
        ls0 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertIsNotNone(ls0)
        g0 = ls0.generation
        upsert_metadata(metadata=meta, home=self.home)

        from secrets_kit.sync.canonical_record import compute_record_content_hash

        ch = compute_record_content_hash(secret="v1", metadata=meta)
        row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "v1",
            "disposition": "active",
            "generation": g0 + 1,
            "content_hash": ch,
        }
        with patch.object(SqliteSecretStore, "_set_entry_conn", side_effect=RuntimeError("injected_set_failure")):
            with self.assertRaises(RuntimeError):
                apply_peer_sync_import(
                    inner_entries=[row],
                    local_host_id="local-host",
                    dry_run=False,
                    path=str(self.db),
                    backend=BACKEND_SQLITE,
                    kek_keychain_path=None,
                    domain_filter=None,
                    home=self.home,
                )
        st2 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        ls1 = st2.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertIsNotNone(ls1)
        self.assertEqual(ls1.generation, g0)
        self.assertEqual(get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE), "v0")

    def test_tombstone_apply_rolls_back_when_delete_conn_fails(self) -> None:
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
        meta = r0.metadata
        ls0 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertIsNotNone(ls0)
        upsert_metadata(metadata=meta, home=self.home)

        tomb_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": max(ls0.generation, 1),
        }
        with patch.object(
            SqliteSecretStore,
            "_delete_entry_locator_conn",
            side_effect=RuntimeError("injected_tomb_failure"),
        ):
            with self.assertRaises(RuntimeError):
                apply_peer_sync_import(
                    inner_entries=[tomb_row],
                    local_host_id="local-host",
                    dry_run=False,
                    path=str(self.db),
                    backend=BACKEND_SQLITE,
                    kek_keychain_path=None,
                    domain_filter=None,
                    home=self.home,
                )
        self.assertTrue(
            secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE),
            "row must remain active after failed tombstone transaction",
        )
        st2 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        ls1 = st2.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertIsNotNone(ls1)
        self.assertFalse(ls1.deleted)

    def test_tombstone_bump_rolls_back_when_bump_fails(self) -> None:
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
        meta = r0.metadata
        upsert_metadata(metadata=meta, home=self.home)
        ls0 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertIsNotNone(ls0)
        tomb_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": max(ls0.generation, 1),
        }
        apply_peer_sync_import(
            inner_entries=[tomb_row],
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        ls1 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None).read_lineage_snapshot(
            entry_id=meta.entry_id
        )
        self.assertIsNotNone(ls1)
        self.assertTrue(ls1.deleted)
        t0 = ls1.tombstone_generation

        bump_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-2",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": t0 + 2,
        }
        with patch.object(
            SqliteSecretStore,
            "_bump_tombstone_lineage_conn",
            side_effect=RuntimeError("injected_bump_failure"),
        ):
            with self.assertRaises(RuntimeError):
                apply_peer_sync_import(
                    inner_entries=[bump_row],
                    local_host_id="local-host",
                    dry_run=False,
                    path=str(self.db),
                    backend=BACKEND_SQLITE,
                    kek_keychain_path=None,
                    domain_filter=None,
                    home=self.home,
                )
        ls2 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None).read_lineage_snapshot(
            entry_id=meta.entry_id
        )
        self.assertIsNotNone(ls2)
        self.assertEqual(ls2.tombstone_generation, t0)


if __name__ == "__main__":
    unittest.main()
