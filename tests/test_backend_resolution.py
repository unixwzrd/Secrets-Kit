from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from unittest import mock

from secrets_kit.keychain_backend import (
    BackendError,
    BACKEND_SECURE,
    ICLOUD_BACKEND_REMOVED_MESSAGE,
    get_secret,
    normalize_backend,
    set_secret,
)


class BackendResolutionTest(unittest.TestCase):
    def test_normalize_backend_aliases(self) -> None:
        self.assertEqual(normalize_backend("local"), BACKEND_SECURE)
        self.assertEqual(normalize_backend("secure"), BACKEND_SECURE)

    def test_normalize_backend_rejects_icloud(self) -> None:
        for bad in ("icloud", "iCloud", "icloud-helper", "iCloud-Helper"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(BackendError, "icloud / icloud-helper backend was removed"):
                    normalize_backend(bad)

    def test_icloud_removed_message_constant(self) -> None:
        self.assertIn("removed", ICLOUD_BACKEND_REMOVED_MESSAGE)

    def test_normalize_backend_sqlite(self) -> None:
        from secrets_kit.keychain_backend import BACKEND_SQLITE

        self.assertEqual(normalize_backend("sqlite"), BACKEND_SQLITE)

    @unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
    def test_resolve_sqlite_store(self) -> None:
        from secrets_kit.keychain_backend import resolve_secret_store
        from secrets_kit.sqlite_backend import SqliteSecretStore

        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "x.db")
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "test-passphrase-for-sqlite!!"
            try:
                store = resolve_secret_store(backend="sqlite", path=db)
                self.assertIsInstance(store, SqliteSecretStore)
            finally:
                del os.environ["SECKIT_SQLITE_PASSPHRASE"]

    @unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
    def test_resolve_sqlite_store_with_explicit_kek_path(self) -> None:
        from secrets_kit.keychain_backend import resolve_secret_store
        from secrets_kit.sqlite_backend import SqliteSecretStore

        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "x.db")
            os.environ["SECKIT_SQLITE_PASSPHRASE"] = "test-passphrase-for-sqlite!!"
            try:
                store = resolve_secret_store(backend="sqlite", path=db, kek_keychain_path="/tmp/nonexistent-for-resolve-only.kc")
                self.assertIsInstance(store, SqliteSecretStore)
            finally:
                del os.environ["SECKIT_SQLITE_PASSPHRASE"]

    def test_local_backend_with_path_uses_security(self) -> None:
        with mock.patch("secrets_kit.keychain_backend._run_security", return_value="secret") as run_security_mock:
            value = get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                path="/tmp/test.keychain-db",
                backend="local",
            )
        self.assertEqual(value, "secret")
        run_security_mock.assert_called_once()

    def test_local_backend_login_keychain_uses_security_only(self) -> None:
        with mock.patch("secrets_kit.keychain_backend._run_security", return_value="") as run_security_mock:
            set_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                backend="local",
            )
        run_security_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
