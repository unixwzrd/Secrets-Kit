from __future__ import annotations

import unittest
from unittest import mock

from secrets_kit.keychain_backend import (
    BackendError,
    BACKEND_ICLOUD_HELPER,
    BACKEND_SECURE,
    get_secret,
    normalize_backend,
    set_secret,
)


class BackendResolutionTest(unittest.TestCase):
    def test_normalize_backend_aliases(self) -> None:
        self.assertEqual(normalize_backend("local"), BACKEND_SECURE)
        self.assertEqual(normalize_backend("icloud"), BACKEND_ICLOUD_HELPER)
        self.assertEqual(normalize_backend("secure"), BACKEND_SECURE)
        self.assertEqual(normalize_backend("iCloud-Helper"), BACKEND_ICLOUD_HELPER)

    def test_icloud_backend_requires_helper(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.icloud_backend_available", return_value=False), \
            mock.patch("secrets_kit.keychain_backend.icloud_backend_error", return_value="Install a macOS wheel with the bundled helper"):
            with self.assertRaisesRegex(BackendError, "macOS wheel"):
                get_secret(service="sync-test", account="local", name="SECKIT_TEST_ALPHA", backend="icloud")

    def test_icloud_helper_canonical_backend_uses_helper_when_installed(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.icloud_backend_available", return_value=True), \
            mock.patch("secrets_kit.keychain_backend.run_helper_request", return_value={"ok": True, "value": "alpha-1"}) as helper_mock:
            value = get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                backend="icloud-helper",
            )
        self.assertEqual(value, "alpha-1")
        self.assertEqual(helper_mock.call_args.kwargs["payload"]["backend"], "icloud")

    def test_icloud_alias_backend_uses_helper_when_installed(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.icloud_backend_available", return_value=True), \
            mock.patch("secrets_kit.keychain_backend.run_helper_request", return_value={"ok": True, "value": "alpha-1"}) as helper_mock:
            value = get_secret(service="sync-test", account="local", name="SECKIT_TEST_ALPHA", backend="icloud")
        self.assertEqual(value, "alpha-1")
        self.assertEqual(helper_mock.call_args.kwargs["payload"]["backend"], "icloud")

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
        with mock.patch("secrets_kit.keychain_backend._run_security", return_value="") as run_security_mock, \
            mock.patch("secrets_kit.keychain_backend.run_helper_request") as helper_mock:
            set_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                backend="local",
            )
        run_security_mock.assert_called_once()
        helper_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
