"""Fresh SqliteSecretStore / connection after failures; replay must stay deterministic."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.operations import secret_exists, set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.canonical_record import compute_record_content_hash
from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


def _lineage_dict(db: Path, entry_id: str) -> dict:
    st = SqliteSecretStore(db_path=str(db), kek_keychain_path=None)
    ls = st.read_lineage_snapshot(entry_id=entry_id)
    assert ls is not None
    return {
        "generation": ls.generation,
        "tombstone_generation": ls.tombstone_generation,
        "deleted": ls.deleted,
        "service": ls.service,
        "account": ls.account,
        "name": ls.name,
    }


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class StabilizationCrashRestartTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home = self.td / "h"
        self.home.mkdir(parents=True, exist_ok=True)
        self.db = self.home / "v.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "stabilization-crash-restart-test-passphrase!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_replay_after_new_store_replay_suppressed_no_resurrection(self) -> None:
        ensure_registry_storage(home=self.home)
        set_secret(
            service="s",
            account="a",
            name="K",
            value="secret-val",
            path=str(self.db),
            backend=BACKEND_SQLITE,
        )
        st0 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st0.resolve_by_locator(service="s", account="a", name="K")
        meta = r0.metadata
        ls0 = st0.read_lineage_snapshot(entry_id=meta.entry_id)
        upsert_metadata(metadata=meta, home=self.home)
        eid = meta.entry_id

        tomb_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": max(ls0.generation, 1),
        }
        apply_peer_sync_import(
            inner_entries=[tomb_row],
            local_host_id="local",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        gold = _lineage_dict(self.db, eid)
        self.assertTrue(gold["deleted"])

        active_row = {
            "metadata": meta.to_dict(),
            "origin_host": "peer-1",
            "value": "stale",
            "disposition": "active",
            "generation": gold["generation"] - 1,
        }
        stats = apply_peer_sync_import(
            inner_entries=[active_row],
            local_host_id="local",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(stats["replay_suppressed"], 1)
        # New store instance (simulates restart)
        again = apply_peer_sync_import(
            inner_entries=[active_row],
            local_host_id="local",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )
        self.assertGreaterEqual(again["replay_suppressed"], 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))
        self.assertEqual(_lineage_dict(self.db, eid), gold)

    def test_permuted_duplicate_replay_idempotent_lineage(self) -> None:
        ensure_registry_storage(home=self.home)
        set_secret(service="s", account="a", name="A", value="x", path=str(self.db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r = st.resolve_by_locator(service="s", account="a", name="A")
        meta = r.metadata
        ls = st.read_lineage_snapshot(entry_id=meta.entry_id)
        upsert_metadata(metadata=meta, home=self.home)
        ch = compute_record_content_hash(secret="y", metadata=meta)
        g1 = ls.generation + 1
        row = {
            "metadata": meta.to_dict(),
            "origin_host": "p",
            "value": "y",
            "generation": g1,
            "content_hash": ch,
        }
        apply_peer_sync_import(
            inner_entries=[row, row],
            local_host_id="local",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            home=self.home,
        )
        st2 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        ls2 = st2.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertEqual(ls2.generation, g1)
        apply_peer_sync_import(
            inner_entries=[row],
            local_host_id="local",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            home=self.home,
        )
        st3 = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        ls3 = st3.read_lineage_snapshot(entry_id=meta.entry_id)
        self.assertEqual(ls3.generation, g1)


if __name__ == "__main__":
    unittest.main()
