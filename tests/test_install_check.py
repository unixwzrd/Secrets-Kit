"""Tests for fast install verification."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.install_check import (
    _read_runtime_root_from_file,
    install_state_path,
    run_install_check,
)


class InstallCheckTest(unittest.TestCase):
    def test_run_install_check_ok(self) -> None:
        result = run_install_check()
        self.assertIn("ok", result)
        self.assertIn("version", result)
        self.assertIn("backend_hints", result)
        self.assertIsInstance(result["issues"], list)

    def test_run_install_check_fails_when_check_fails(self) -> None:
        with mock.patch(
            "secrets_kit.cli.install_check._check_package_seeds",
            return_value=False,
        ):
            result = run_install_check()
        self.assertFalse(result["ok"])

    def test_read_runtime_root_strips_legacy_literal_backslash_n(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime-path"
            path.write_text("/tmp/runtime\\n", encoding="utf-8")
            self.assertEqual(_read_runtime_root_from_file(path), "/tmp/runtime")

    def test_install_state_path_under_config(self) -> None:
        path = install_state_path()
        self.assertTrue(str(path).endswith(".config/seckit/install.json"))

    def test_doctor_install_check_flag(self) -> None:
        import argparse
        import io
        from contextlib import redirect_stdout

        args = argparse.Namespace(
            install_check=True,
            backend=None,
            keychain=None,
            sqlite_dev_mode=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_doctor(args=args)
        payload = json.loads(stdout.getvalue())
        self.assertIn("ok", payload)
        self.assertEqual(code, 0 if payload["ok"] else 1)


if __name__ == "__main__":
    unittest.main()
