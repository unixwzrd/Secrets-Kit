"""Phase 6A convergence behaviors: ordering, duplicate delivery, tombstone idempotence."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.operations import get_secret, secret_exists, set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class Phase6aConvergenceSqliteTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home = self.td / "h"
        self.home.mkdir(parents=True, exist_ok=True)
        self.db = self.home / "v.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "phase6a-convergence-test-passphrase!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def _apply(self, rows: list[dict]) -> dict:
        return apply_peer_sync_import(
            inner_entries=rows,
            local_host_id="local-host",
            dry_run=False,
            path=str(self.db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home,
        )

    def test_stale_generation_skipped_after_newer_applied(self) -> None:
        """Lower peer generation must not apply once local lineage has advanced."""
        ensure_registry_storage(home=self.home)
        set_secret(service="s", account="a", name="K", value="v0", path=str(self.db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st.resolve_by_locator(service="s", account="a", name="K")
        assert r0 is not None
        meta = r0.metadata
        upsert_metadata(metadata=meta, home=self.home)
        ls = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls is not None
        g0 = ls.generation

        s1 = self._apply(
            [
                {
                    "metadata": meta.to_dict(),
                    "origin_host": "p1",
                    "value": "v1",
                    "disposition": "active",
                    "generation": g0 + 1,
                }
            ]
        )
        self.assertGreaterEqual(s1.get("updated", 0) + s1.get("created", 0), 1)
        self.assertEqual(get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE), "v1")

        ls2 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls2 is not None
        g_mid = ls2.generation

        s2 = self._apply(
            [
                {
                    "metadata": meta.to_dict(),
                    "origin_host": "p1",
                    "value": "v2",
                    "disposition": "active",
                    "generation": g_mid + 1,
                }
            ]
        )
        self.assertGreaterEqual(s2.get("updated", 0), 1)
        self.assertEqual(get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE), "v2")

        ls3 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls3 is not None
        # Older peer generation than current local index (not the intermediate g_mid + 1).
        s_stale = self._apply(
            [
                {
                    "metadata": meta.to_dict(),
                    "origin_host": "p1",
                    "value": "v-stale",
                    "disposition": "active",
                    "generation": g_mid,
                }
            ]
        )
        self.assertGreaterEqual(s_stale.get("skipped", 0), 1)
        self.assertEqual(get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE), "v2")

    def test_duplicate_delivery_same_secret_stable(self) -> None:
        """Echo with current generation + same value is unchanged; secret remains stable."""
        ensure_registry_storage(home=self.home)
        set_secret(service="s", account="a", name="K", value="v0", path=str(self.db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st.resolve_by_locator(service="s", account="a", name="K")
        assert r0 is not None
        meta = r0.metadata
        upsert_metadata(metadata=meta, home=self.home)
        ls0 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls0 is not None

        row_adv = {
            "metadata": meta.to_dict(),
            "origin_host": "p1",
            "value": "v-final",
            "disposition": "active",
            "generation": ls0.generation + 1,
        }
        s1 = self._apply([row_adv])
        self.assertEqual(s1.get("conflicts", 0), 0)
        v1 = get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE)

        ls1 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls1 is not None
        row_echo = {
            "metadata": meta.to_dict(),
            "origin_host": "p1",
            "value": "v-final",
            "disposition": "active",
            "generation": ls1.generation,
        }
        s2 = self._apply([row_echo])
        self.assertEqual(s2.get("conflicts", 0), 0)
        self.assertGreaterEqual(s2.get("unchanged", 0), 1)
        v2 = get_secret(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE)
        self.assertEqual(v1, v2)
        self.assertEqual(v2, "v-final")

    def test_tombstone_replay_idempotent(self) -> None:
        ensure_registry_storage(home=self.home)
        set_secret(service="s", account="a", name="K", value="x", path=str(self.db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(self.db), kek_keychain_path=None)
        r0 = st.resolve_by_locator(service="s", account="a", name="K")
        assert r0 is not None
        meta = r0.metadata
        upsert_metadata(metadata=meta, home=self.home)
        ls0 = st.read_lineage_snapshot(entry_id=meta.entry_id)
        assert ls0 is not None
        tgen = max(ls0.generation, 1)
        tomb = {
            "metadata": meta.to_dict(),
            "origin_host": "p1",
            "value": "",
            "disposition": "tombstone",
            "tombstone_generation": tgen,
        }
        a = self._apply([tomb])
        self.assertGreaterEqual(a["tombstone_applied"], 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))

        b = self._apply([tomb])
        self.assertGreaterEqual(b.get("unchanged", 0) + b.get("skipped", 0), 1)
        self.assertFalse(secret_exists(service="s", account="a", name="K", path=str(self.db), backend=BACKEND_SQLITE))


if __name__ == "__main__":
    unittest.main()
