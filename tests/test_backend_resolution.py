from __future__ import annotations

import os
import unittest
from unittest import mock

from secrets_kit.keychain_backend import BackendError, get_secret, set_secret


class BackendResolutionTest(unittest.TestCase):
    def test_icloud_backend_requires_helper(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.helper_installed", return_value=False), \
            mock.patch("secrets_kit.keychain_backend.icloud_backend_error", return_value="Run `seckit helper install-local`"):
            with self.assertRaisesRegex(BackendError, "install-local"):
                get_secret(service="sync-test", account="local", name="SECKIT_TEST_ALPHA", backend="icloud")

    def test_icloud_backend_uses_helper_when_installed(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.helper_installed", return_value=True), \
            mock.patch("secrets_kit.keychain_backend.run_helper_request", return_value={"ok": True, "value": "alpha-1"}) as helper_mock:
            value = get_secret(service="sync-test", account="local", name="SECKIT_TEST_ALPHA", backend="icloud")
        self.assertEqual(value, "alpha-1")
        self.assertEqual(helper_mock.call_args.kwargs["payload"]["backend"], "icloud")

    def test_local_backend_with_path_does_not_use_helper(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.helper_installed", return_value=True), \
            mock.patch("secrets_kit.keychain_backend._run_security", return_value="secret") as run_security_mock:
            value = get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                path="/tmp/test.keychain-db",
                backend="local",
            )
        self.assertEqual(value, "secret")
        run_security_mock.assert_called_once()

    def test_local_backend_without_path_uses_security_by_default(self) -> None:
        with mock.patch("secrets_kit.keychain_backend.helper_installed", return_value=True), \
            mock.patch("secrets_kit.keychain_backend._run_security", return_value="") as run_security_mock, \
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

    def test_local_backend_without_path_uses_helper_when_opted_in(self) -> None:
        with mock.patch.dict(os.environ, {"SECKIT_USE_LOCAL_HELPER": "1"}, clear=False), \
            mock.patch("secrets_kit.keychain_backend.helper_installed", return_value=True), \
            mock.patch("secrets_kit.keychain_backend.run_helper_request", return_value={"ok": True}) as helper_mock:
            set_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                backend="local",
            )
        self.assertEqual(helper_mock.call_args.kwargs["payload"]["backend"], "local")


if __name__ == "__main__":
    unittest.main()
