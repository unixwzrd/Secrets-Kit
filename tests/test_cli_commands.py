from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

from secrets_kit.cli import _apply_defaults, build_parser, cmd_doctor, cmd_lock


class CliCommandsTest(unittest.TestCase):
    def test_parser_has_expected_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        for expected in {"set", "get", "list", "explain", "delete", "import", "export", "doctor", "migrate", "lock", "unlock", "keychain-status"}:
            self.assertIn(expected, commands)

    def test_kind_flags_parse(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token"])
        self.assertEqual(args.kind, "token")

        args = parser.parse_args(["import", "file", "--file", "secrets.json", "--kind", "auto"])
        self.assertEqual(args.kind, "auto")

    def test_doctor_reports_metadata_keychain_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_registry = {
                "openclaw::miafour::OPENAI_API_KEY": {
                    "name": "OPENAI_API_KEY",
                    "entry_type": "secret",
                    "entry_kind": "api_key",
                    "tags": [],
                    "comment": "",
                    "service": "openclaw",
                    "account": "miafour",
                    "created_at": "2026-03-10T00:00:00Z",
                    "updated_at": "2026-03-10T00:00:00Z",
                    "source": "manual",
                }
            }

            out = io.StringIO()
            err = io.StringIO()
            with mock.patch("secrets_kit.cli.check_security_cli", return_value=True), \
                mock.patch("secrets_kit.cli.ensure_registry_storage", return_value=f"{tmp}/registry.json"), \
                mock.patch("secrets_kit.cli.doctor_roundtrip", return_value=None), \
                mock.patch("secrets_kit.cli.load_registry") as load_registry_mock, \
                mock.patch("secrets_kit.cli.secret_exists", return_value=False), \
                redirect_stdout(out), \
                redirect_stderr(err):
                from secrets_kit.models import EntryMetadata

                load_registry_mock.return_value = {
                    key: EntryMetadata.from_dict(value) for key, value in fake_registry.items()
                }
                code = cmd_doctor(args=argparse.Namespace())

            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertTrue(payload["security_cli"])
            self.assertTrue(payload["registry"])
            self.assertTrue(payload["keychain_roundtrip"])
            self.assertEqual(
                payload["metadata_keychain_drift"],
                [{"name": "OPENAI_API_KEY", "service": "openclaw", "account": "miafour"}],
            )
            self.assertIn("metadata/keychain drift detected", err.getvalue())
            self.assertTrue(payload["defaults"])
            self.assertEqual(payload["entries_using_registry_fallback"], [])

    def test_lock_dry_run_shows_backend_command(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("secrets_kit.cli.check_security_cli", return_value=True), \
            redirect_stdout(out), \
            redirect_stderr(err):
            code = cmd_lock(args=argparse.Namespace(keychain=None, dry_run=True, yes=False))

        self.assertEqual(code, 0)
        self.assertIn("security lock-keychain", out.getvalue())

    def test_lock_runs_backend(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("secrets_kit.cli.check_security_cli", return_value=True), \
            mock.patch("secrets_kit.cli.lock_keychain", return_value="/tmp/login.keychain-db"), \
            redirect_stdout(out), \
            redirect_stderr(err):
            code = cmd_lock(args=argparse.Namespace(keychain="/tmp/login.keychain-db", dry_run=False, yes=True))

        self.assertEqual(code, 0)
        self.assertIn("locking keychain: /tmp/login.keychain-db", out.getvalue())
        self.assertIn("locked: /tmp/login.keychain-db", out.getvalue())

    def test_defaults_json_applies_rotation_and_scope_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "defaults.json").write_text(
                json.dumps(
                    {
                        "service": "hermes",
                        "account": "default",
                        "type": "secret",
                        "kind": "api_key",
                        "default_rotation_days": 90,
                        "rotation_warn_days": 14,
                    }
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                command="set",
                service=None,
                account=None,
                type=None,
                kind=None,
                tags=None,
                tag=None,
                rotation_days=None,
                rotation_warn_days=None,
            )
            with mock.patch("pathlib.Path.home", return_value=home):
                _apply_defaults(args=args)
            self.assertEqual(args.service, "hermes")
            self.assertEqual(args.account, "default")
            self.assertEqual(args.kind, "api_key")
            self.assertEqual(args.rotation_days, 90)
            self.assertEqual(args.rotation_warn_days, 14)


if __name__ == "__main__":
    unittest.main()
