"""Identical seed + bundle sequence twice → identical lineage + trace."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

from secrets_kit.backends.operations import set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.canonical_record import compute_record_content_hash

from tests.support.ops_reconcile import lineage_projection, run_import_sequence

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


def _run_once() -> Tuple[List[Tuple[object, ...]], List[Dict[str, Any]]]:
    td = tempfile.TemporaryDirectory()
    home = Path(td.name) / "h"
    home.mkdir(parents=True, exist_ok=True)
    db = home / "v.db"
    os.environ["SECKIT_SQLITE_PASSPHRASE"] = "stabilization-convergence-test-passphrase!!"
    clear_sqlite_crypto_cache()
    try:
        ensure_registry_storage(home=home)
        set_secret(service="s", account="a", name="K", value="v0", path=str(db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(db), kek_keychain_path=None)
        r = st.resolve_by_locator(service="s", account="a", name="K")
        meta = r.metadata
        ls = st.read_lineage_snapshot(entry_id=meta.entry_id)
        upsert_metadata(metadata=meta, home=home)
        ch = compute_record_content_hash(secret="v1", metadata=meta)
        row = {
            "metadata": meta.to_dict(),
            "origin_host": "p",
            "value": "v1",
            "generation": ls.generation + 1,
            "content_hash": ch,
        }
        _, trace = run_import_sequence(
            inner_entries=[row],
            local_host_id="host-a",
            dry_run=False,
            path=str(db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            home=home,
        )
        full = lineage_projection(db)
        proj = [(t[0], t[4], t[5], t[6]) for t in full]
        return proj, trace
    finally:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        td.cleanup()


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class StabilizationConvergenceReplayTest(unittest.TestCase):
    def test_identical_sequence_twice(self) -> None:
        p1, t1 = _run_once()
        p2, t2 = _run_once()
        self.assertEqual(len(p1), 1)
        self.assertEqual(len(p1), len(p2))
        # entry_id is UUID per fresh DB; compare monotonic lineage integers only
        self.assertEqual(
            (p1[0][1], p1[0][2], p1[0][3]),
            (p2[0][1], p2[0][2], p2[0][3]),
        )
        self.assertEqual(len(t1), len(t2))
        for a, b in zip(t1, t2):
            self.assertEqual(a.get("decision"), b.get("decision"))
            self.assertEqual(a.get("reason"), b.get("reason"))
            self.assertEqual(a.get("incoming_generation"), b.get("incoming_generation"))
            self.assertEqual(a.get("local_generation"), b.get("local_generation"))
        for row in t1 + t2:
            self.assertNotIn("value", row)


if __name__ == "__main__":
    unittest.main()
