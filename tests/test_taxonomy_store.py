"""Taxonomy registry system-object roundtrip (Keychain + SQLite)."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from secrets_kit.backends.keychain import delete_keychain, make_temp_keychain
from secrets_kit.backends.sqlite import SQLITE_PATH_ENV
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
                {SQLITE_PATH_ENV: db_path, "SECKIT_SQLITE_DEVELOPER_MODE": "1"},
                clear=False,
            ):
                merge_seed_files_into_taxonomy_store(backend="sqlite", sqlite_dev_mode=True)
                registry = load_taxonomy_registry(backend="sqlite", sqlite_dev_mode=True)
                self.assertTrue(any(item.name == "api_key" for item in registry.entry_kinds))

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
