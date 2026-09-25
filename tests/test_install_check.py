"""Tests for fast install verification."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.install_check import (
    _check_config_writable,
    _read_runtime_root_from_file,
    install_state_path,
    run_install_check,
)


class InstallCheckTest(unittest.TestCase):
    def test_writable_probe_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            existing = config / ".install_check_probe"
            existing.write_bytes(b"preserve")
            with mock.patch("secrets_kit.cli.install_check.registry_dir", return_value=config):
                self.assertTrue(_check_config_writable(issues=[]))
            self.assertEqual(existing.read_bytes(), b"preserve")
            self.assertEqual(list(config.iterdir()), [existing])

    def test_writable_probe_preserves_symlink_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            target = root / "target"
            target.write_bytes(b"preserve")
            link = config / ".install_check_probe"
            link.symlink_to(target)
            with mock.patch("secrets_kit.cli.install_check.registry_dir", return_value=config):
                self.assertTrue(_check_config_writable(issues=[]))
            self.assertTrue(link.is_symlink())
            self.assertEqual(target.read_bytes(), b"preserve")
            self.assertEqual(list(config.iterdir()), [link])

    def test_writable_probe_creation_failure_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            issues = []
            with mock.patch("secrets_kit.cli.install_check.registry_dir", return_value=Path(directory)), mock.patch("secrets_kit.cli.install_check.tempfile.TemporaryFile", side_effect=PermissionError("denied")):
                self.assertFalse(_check_config_writable(issues=issues))
            self.assertEqual(len(issues), 1)

    def test_run_install_check_ok(self) -> None:
        result = run_install_check()
        self.assertIn("ok", result)
        self.assertIn("version", result)
        self.assertIn("backend_hints", result)
        self.assertIn("mcp_launcher", result)
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
        from contextlib import redirect_stderr, redirect_stdout

        args = argparse.Namespace(
            install_check=True,
            backend=None,
            keychain=None,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = cmd_doctor(args=args)
        payload = json.loads(stdout.getvalue())
        self.assertIn("ok", payload)
        self.assertEqual(code, 0 if payload["ok"] else 1)


if __name__ == "__main__":
    unittest.main()
