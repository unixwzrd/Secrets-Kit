"""Tests for seckit info command."""

from __future__ import annotations

import unittest
from unittest import mock

from secrets_kit.cli.commands.info import build_info_dict
from secrets_kit.cli.operator_defaults import initial_operator_defaults


class InfoCommandTest(unittest.TestCase):
    def test_initial_defaults_use_sqlite_off_macos(self) -> None:
        with mock.patch("secrets_kit.cli.operator_defaults.sys.platform", "linux"):
            payload = initial_operator_defaults(account="dev")
        self.assertEqual(payload["backend"], "sqlite")

    def test_build_info_keychain_skipped_on_linux(self) -> None:
        with (
            mock.patch("secrets_kit.cli.commands.info._is_macos", return_value=False),
            mock.patch(
                "secrets_kit.cli.commands.info._load_defaults", return_value={"backend": "sqlite"}
            ),
            mock.patch("secrets_kit.cli.commands.info.ensure_defaults_storage"),
            mock.patch(
                "secrets_kit.cli.commands.info.defaults_path", return_value="/tmp/defaults.json"
            ),
            mock.patch(
                "secrets_kit.cli.commands.info.registry_path", return_value="/tmp/registry.json"
            ),
            mock.patch(
                "secrets_kit.cli.commands.info._sqlite_status_dict",
                return_value={
                    "path": "/tmp/x.sqlite",
                    "exists": False,
                    "encryption": {
                        "enabled": False,
                        "warning": "WARNING: encryption-at-rest is OFF",
                    },
                },
            ),
        ):
            data = build_info_dict()
        self.assertFalse(data["backend_availability"]["keychain"])
        self.assertTrue(data["backend_availability"]["sqlite"])
        self.assertFalse(data["keychain"]["supported"])
        self.assertIn("path", data["sqlite"])
        sqlite_encryption = data["sqlite"]["encryption"]
        self.assertFalse(sqlite_encryption["enabled"])
        self.assertIn("encryption-at-rest is OFF", sqlite_encryption["warning"])

    def test_keychain_info_reports_encryption_enabled(self) -> None:
        with (
            mock.patch("secrets_kit.cli.commands.info._is_macos", return_value=True),
            mock.patch("secrets_kit.cli.commands.info.check_security_cli", return_value=True),
            mock.patch(
                "secrets_kit.cli.commands.info.keychain_path",
                return_value="/tmp/login.keychain-db",
            ),
            mock.patch("secrets_kit.cli.commands.info.keychain_accessible", return_value=True),
            mock.patch(
                "secrets_kit.cli.commands.info.keychain_policy",
                return_value={
                    "no_timeout": False,
                    "lock_on_sleep": True,
                    "timeout_seconds": 3600,
                    "raw": "",
                },
            ),
            mock.patch(
                "secrets_kit.cli.commands.info._load_defaults", return_value={"backend": "keychain"}
            ),
            mock.patch("secrets_kit.cli.commands.info.ensure_defaults_storage"),
            mock.patch(
                "secrets_kit.cli.commands.info.defaults_path", return_value="/tmp/defaults.json"
            ),
            mock.patch(
                "secrets_kit.cli.commands.info.registry_path", return_value="/tmp/registry.json"
            ),
        ):
            data = build_info_dict()
        keychain_encryption = data["keychain"]["encryption"]
        self.assertTrue(keychain_encryption["enabled"])
        self.assertEqual(keychain_encryption["mode"], "macOS Keychain")


if __name__ == "__main__":
    unittest.main()
