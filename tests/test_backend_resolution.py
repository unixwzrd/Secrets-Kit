from __future__ import annotations

import unittest
from unittest import mock

from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BACKEND_SQLITE,
    BackendError,
    is_keychain_backend,
    normalize_backend,
)
from secrets_kit.backends.keychain import (
    get_secret,
    keychain_path,
    set_secret,
)


class BackendResolutionTest(unittest.TestCase):
    def test_normalize_backend_accepts_canonical_ids(self) -> None:
        self.assertEqual(normalize_backend("keychain"), BACKEND_KEYCHAIN)
        self.assertEqual(normalize_backend("sqlite"), BACKEND_SQLITE)
        self.assertTrue(is_keychain_backend("keychain"))
        self.assertFalse(is_keychain_backend("sqlite"))

    def test_normalize_backend_rejects_legacy_aliases(self) -> None:
        removed_backend = "i" + "cloud"
        removed_alias = removed_backend + "-helper"
        for bad in (
            "secure",
            "local",
            "Secure",
            "LOCAL",
            removed_backend,
            removed_backend[0] + "Cloud",
            removed_alias,
            removed_alias.title(),
        ):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(BackendError, "unsupported backend"):
                    normalize_backend(bad)

    def test_keychain_backend_with_path_uses_security(self) -> None:
        with mock.patch(
            "secrets_kit.backends.keychain.security_cli.run_security", return_value="secret"
        ) as run_security_mock:
            value = get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                path="/tmp/test.keychain-db",
                backend="keychain",
            )
        self.assertEqual(value, "secret")
        run_security_mock.assert_called_once()

    def test_keychain_set_uses_security_only(self) -> None:
        with mock.patch(
            "secrets_kit.backends.keychain.security_cli.run_security", return_value=""
        ) as run_security_mock:
            set_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                backend="keychain",
            )
        run_security_mock.assert_called_once()

    def test_sqlite_backend_does_not_route_through_keychain_store(self) -> None:
        with self.assertRaisesRegex(BackendError, "not the keychain backend"):
            get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                backend="sqlite",
            )

    def test_keychain_path_prefers_security_default_keychain(self) -> None:
        proc = mock.MagicMock(returncode=0, stdout='    "/Users/test/Library/Keychains/login.keychain-db"\n')
        with mock.patch(
            "secrets_kit.backends.keychain.security_cli.subprocess.run",
            return_value=proc,
        ):
            self.assertEqual(keychain_path(), "/Users/test/Library/Keychains/login.keychain-db")


if __name__ == "__main__":
    unittest.main()
