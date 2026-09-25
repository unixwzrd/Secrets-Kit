"""Taxonomy registry system-object roundtrip (Keychain + SQLite)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.backends.keychain import delete_keychain, make_temp_keychain
from secrets_kit.backends.sqlite import SQLITE_PATH_ENV
from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.taxonomy.registry_store import (
    load_taxonomy_registry,
    merge_seed_files_into_taxonomy_store,
    save_taxonomy_registry,
)
from secrets_kit.taxonomy.seed import load_bundled_taxonomy_seeds


class TaxonomyStoreRoundtripTest(unittest.TestCase):
    def test_sqlite_taxonomy_registry_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: db_path},
                clear=False,
            ):
                conn = provision_sqlite_datastore(path=Path(db_path), storage_mode="encrypted")
                ensure_sqlite_node_identity(conn=conn)
                conn.close()
                merge_seed_files_into_taxonomy_store(backend="sqlite")
                registry = load_taxonomy_registry(backend="sqlite")
                self.assertTrue(any(item.name == "api_key" for item in registry.entry_kinds))
                conn = sqlite3.connect(db_path)
                try:
                    self.assertEqual(
                        conn.execute(
                            "SELECT count(*) FROM secrets WHERE name = '__taxonomy_registry__'"
                        ).fetchone()[0],
                        0,
                    )
                    self.assertGreater(
                        conn.execute("SELECT count(*) FROM entry_types").fetchone()[0], 0
                    )
                    self.assertGreater(
                        conn.execute("SELECT count(*) FROM entry_kinds").fetchone()[0], 0
                    )
                finally:
                    conn.close()

    def test_keychain_taxonomy_save_still_uses_backend_dispatch(self) -> None:
        registry = load_bundled_taxonomy_seeds()

        with mock.patch("secrets_kit.taxonomy.registry_store.write_secret") as write_secret:
            save_taxonomy_registry(registry=registry, backend="keychain")

        write_secret.assert_called_once()
        self.assertEqual(write_secret.call_args.kwargs["backend"], "keychain")
        self.assertEqual(write_secret.call_args.kwargs["name"], "__taxonomy_registry__")

    @unittest.skipUnless(os.uname().sysname == "Darwin", "macOS Keychain only")
    def test_keychain_taxonomy_registry_roundtrip(self) -> None:
        fixture = make_temp_keychain(password="tax-store-pass")
        try:
            seeds = load_bundled_taxonomy_seeds()
            save_taxonomy_registry(
                registry=seeds,
                backend="keychain",
                keychain_path=fixture["path"],
            )
            loaded = load_taxonomy_registry(
                backend="keychain",
                keychain_path=fixture["path"],
            )
            self.assertTrue(any(item.name == "secret" for item in loaded.entry_types))
            self.assertTrue(any(item.name == "api_key" for item in loaded.entry_kinds))
        finally:
            try:
                delete_keychain(path=fixture["path"])
            finally:
                import shutil

                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
