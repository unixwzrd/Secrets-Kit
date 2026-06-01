"""Tests for seckit init commands."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.init_cmd import cmd_init, cmd_init_operator, cmd_init_sqlite
from secrets_kit.cli.operator_defaults import initial_operator_defaults, resolve_operator_account
from secrets_kit.registry import (
    defaults_path,
    load_defaults,
    load_registry,
    registry_path,
    save_defaults,
)


class InitCommandTest(unittest.TestCase):
    def test_resolve_operator_account_prefers_home_over_root_env(self) -> None:
        env = {
            "USER": "root",
            "LOGNAME": "root",
            "HOME": "/Users/seckit",
        }
        with mock.patch.dict("os.environ", env, clear=False):
            self.assertEqual(resolve_operator_account(), "seckit")

    def test_initial_operator_defaults_shape(self) -> None:
        with mock.patch("secrets_kit.cli.operator_defaults.sys.platform", "darwin"):
            payload = initial_operator_defaults(account="tester")
        self.assertEqual(payload["backend"], "keychain")
        self.assertEqual(payload["type"], "secret")
        self.assertEqual(payload["kind"], "api_key")
        self.assertEqual(payload["account"], "tester")
        self.assertEqual(payload["default_rotation_days"], 90)

    def test_init_operator_writes_defaults_and_empty_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            args = argparse.Namespace(yes=True, home=str(home), init_target=None)
            code = cmd_init_operator(args=args)
            self.assertEqual(code, 0)
            defaults = load_defaults(home=home)
            self.assertEqual(defaults["backend"], "keychain")
            self.assertEqual(load_registry(home=home), {})
            self.assertTrue(defaults_path(home=home).exists())
            self.assertTrue(registry_path(home=home).exists())

    def test_init_operator_requires_confirmation_without_yes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            save_defaults(payload={"backend": "keychain"}, home=home)
            args = argparse.Namespace(yes=False, home=str(home), init_target=None)
            with mock.patch("secrets_kit.cli.commands.init_cmd._confirm", return_value=False):
                code = cmd_init_operator(args=args)
            self.assertEqual(code, 1)

    def test_init_sqlite_recreates_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "seckit.sqlite"
            with mock.patch.dict(
                "os.environ",
                {"SECKIT_SQLITE_PATH": str(db_path), "SECKIT_SQLITE_DEVELOPER_MODE": "1"},
                clear=False,
            ):
                db_path.write_text("stale", encoding="utf-8")
                args = argparse.Namespace(yes=True, sqlite_dev_mode=False, init_target="sqlite")
                code = cmd_init_sqlite(args=args)
            self.assertEqual(code, 0)
            self.assertTrue(db_path.exists())
            self.assertGreater(db_path.stat().st_size, 0)

    def test_cmd_init_dispatches_sqlite(self) -> None:
        args = argparse.Namespace(init_target="sqlite")
        with mock.patch(
            "secrets_kit.cli.commands.init_cmd.cmd_init_sqlite", return_value=0
        ) as sqlite_mock:
            code = cmd_init(args=args)
        self.assertEqual(code, 0)
        sqlite_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
