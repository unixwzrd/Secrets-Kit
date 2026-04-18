from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

from secrets_kit.cli import _apply_defaults, _read_password, build_parser, cmd_delete, cmd_doctor, cmd_get, cmd_helper_install_icloud, cmd_helper_install_local, cmd_helper_status, cmd_lock, cmd_run, cmd_set


class CliCommandsTest(unittest.TestCase):
    def test_parser_has_expected_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        for expected in {"set", "get", "list", "explain", "delete", "import", "export", "run", "doctor", "migrate", "lock", "unlock", "keychain-status", "helper"}:
            self.assertIn(expected, commands)

    def test_run_parser_preserves_separator_and_command(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "run",
                "--service",
                "openclaw",
                "--account",
                "miafour",
                "--",
                "/usr/bin/env",
                "python3",
            ]
        )
        self.assertEqual(args.command, "run")
        self.assertEqual(args.child_command, ["--", "/usr/bin/env", "python3"])

    def test_kind_flags_parse(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token"])
        self.assertEqual(args.kind, "token")
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token", "--keychain", "/tmp/test.keychain-db"])
        self.assertEqual(args.keychain, "/tmp/test.keychain-db")
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--backend", "icloud"])
        self.assertEqual(args.backend, "icloud")

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
                        "backend": "icloud",
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
                backend=None,
                keychain=None,
            )
            with mock.patch("pathlib.Path.home", return_value=home), \
                mock.patch("secrets_kit.cli.icloud_backend_available", return_value=True):
                _apply_defaults(args=args)
            self.assertEqual(args.service, "hermes")
            self.assertEqual(args.account, "default")
            self.assertEqual(args.kind, "api_key")
            self.assertEqual(args.rotation_days, 90)
            self.assertEqual(args.rotation_warn_days, 14)
            self.assertEqual(args.backend, "icloud")

    def test_apply_defaults_rejects_icloud_with_keychain(self) -> None:
        args = argparse.Namespace(
            command="get",
            service="sync-test",
            account="local",
            type=None,
            kind=None,
            tags=None,
            tag=None,
            rotation_days=None,
            rotation_warn_days=None,
            backend="icloud",
            keychain="/tmp/test.keychain-db",
        )
        with self.assertRaisesRegex(Exception, "--keychain is only supported with --backend local"):
            _apply_defaults(args=args)

    def test_apply_defaults_rejects_icloud_without_helper(self) -> None:
        args = argparse.Namespace(
            command="get",
            service="sync-test",
            account="local",
            type=None,
            kind=None,
            tags=None,
            tag=None,
            rotation_days=None,
            rotation_warn_days=None,
            backend="icloud",
            keychain=None,
        )
        with mock.patch("secrets_kit.cli.icloud_backend_available", return_value=False), \
            mock.patch("secrets_kit.cli.icloud_backend_error", return_value="Run `seckit helper install-local`"):
            with self.assertRaisesRegex(Exception, "install-local"):
                _apply_defaults(args=args)

    def test_read_password_uses_custom_prompt(self) -> None:
        with mock.patch("getpass.getpass", return_value="backup-pass") as getpass_mock:
            value = _read_password(value=None, use_stdin=False, prompt="new password to encrypt the backup file: ")
        self.assertEqual(value, "backup-pass")
        getpass_mock.assert_called_once_with("new password to encrypt the backup file: ")

    def test_set_passes_keychain_path(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="sync-test",
            account="local",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain="/tmp/test.keychain-db",
        )
        fake_meta = mock.Mock(entry_type="secret", entry_kind="api_key", to_keychain_comment=mock.Mock(return_value="{}"))
        with mock.patch("secrets_kit.cli._build_metadata", return_value=fake_meta), \
            mock.patch("secrets_kit.cli.set_secret") as set_secret_mock, \
            mock.patch("secrets_kit.cli.upsert_metadata"):
            code = cmd_set(args=args)
        self.assertEqual(code, 0)
        set_secret_mock.assert_called_once()
        self.assertEqual(set_secret_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")

    def test_get_passes_keychain_path(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="sync-test",
            account="local",
            keychain="/tmp/test.keychain-db",
        )
        out = io.StringIO()
        with mock.patch("secrets_kit.cli.get_secret", return_value="secret") as get_secret_mock, \
            mock.patch("secrets_kit.cli._read_metadata", return_value=None), \
            redirect_stdout(out):
            code = cmd_get(args=args)
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "secret")
        self.assertEqual(get_secret_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")

    def test_delete_passes_keychain_path(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            yes=True,
            service="sync-test",
            account="local",
            keychain="/tmp/test.keychain-db",
        )
        with mock.patch("secrets_kit.cli.delete_secret") as delete_secret_mock, \
            mock.patch("secrets_kit.cli.delete_metadata", return_value=True), \
            redirect_stdout(io.StringIO()):
            code = cmd_delete(args=args)
        self.assertEqual(code, 0)
        self.assertEqual(delete_secret_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")

    def test_doctor_passes_keychain_path(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("secrets_kit.cli.check_security_cli", return_value=True), \
            mock.patch("secrets_kit.cli.ensure_registry_storage", return_value="/tmp/registry.json"), \
            mock.patch("secrets_kit.cli.ensure_defaults_storage", return_value="/tmp/defaults.json"), \
            mock.patch("secrets_kit.cli.doctor_roundtrip") as doctor_roundtrip_mock, \
            mock.patch("secrets_kit.cli.load_registry", return_value={}), \
            redirect_stdout(out), \
            redirect_stderr(err):
            code = cmd_doctor(args=argparse.Namespace(keychain="/tmp/test.keychain-db"))
        self.assertEqual(code, 0)
        self.assertEqual(doctor_roundtrip_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")

    def test_run_injects_selected_secrets_and_execs_child(self) -> None:
        from secrets_kit.models import EntryMetadata

        args = argparse.Namespace(
            service="openclaw",
            account="miafour",
            names="OPENAI_API_KEY,TELEGRAM_BOT_TOKEN",
            tag=None,
            type=None,
            kind=None,
            all=False,
            keychain="/tmp/test.keychain-db",
            backend="local",
            child_command=["--", "/usr/bin/env", "python3"],
        )
        openai_meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="openclaw",
            account="miafour",
            entry_type="secret",
            entry_kind="api_key",
            source="manual",
        )
        telegram_meta = EntryMetadata(
            name="TELEGRAM_BOT_TOKEN",
            service="openclaw",
            account="miafour",
            entry_type="secret",
            entry_kind="token",
            source="manual",
        )

        with mock.patch("secrets_kit.cli.load_registry", return_value={}), \
            mock.patch(
                "secrets_kit.cli._read_metadata",
                side_effect=[
                    {"metadata": openai_meta},
                    {"metadata": telegram_meta},
                ],
            ), \
            mock.patch("secrets_kit.cli.get_secret", side_effect=["sk-openai", "bot-token"]), \
            mock.patch("secrets_kit.cli._exec_child", return_value=0) as exec_mock:
            code = cmd_run(args=args)

        self.assertEqual(code, 0)
        exec_mock.assert_called_once()
        self.assertEqual(exec_mock.call_args.kwargs["argv"], ["/usr/bin/env", "python3"])
        injected_env = exec_mock.call_args.kwargs["env"]
        self.assertEqual(injected_env["OPENAI_API_KEY"], "sk-openai")
        self.assertEqual(injected_env["TELEGRAM_BOT_TOKEN"], "bot-token")

    def test_run_requires_target_command(self) -> None:
        err = io.StringIO()
        args = argparse.Namespace(
            service="openclaw",
            account="miafour",
            names=None,
            tag=None,
            type=None,
            kind=None,
            all=False,
            keychain=None,
            backend="local",
            child_command=["--"],
        )
        with redirect_stderr(err):
            code = cmd_run(args=args)
        self.assertEqual(code, 2)
        self.assertIn("run requires a target command", err.getvalue())

    def test_migrate_metadata_passes_keychain_path(self) -> None:
        from secrets_kit.cli import cmd_migrate_metadata
        from secrets_kit.models import EntryMetadata

        registry = {
            "sync-test::local::OPENAI_API_KEY": EntryMetadata(
                name="OPENAI_API_KEY",
                service="sync-test",
                account="local",
                entry_type="secret",
                entry_kind="api_key",
                source="manual",
            )
        }
        args = argparse.Namespace(
            service="sync-test",
            account="local",
            dry_run=True,
            force=False,
            keychain="/tmp/test.keychain-db",
            backend="local",
        )
        out = io.StringIO()
        with mock.patch("secrets_kit.cli.load_registry", return_value=registry), \
            mock.patch("secrets_kit.cli.secret_exists", return_value=True) as secret_exists_mock, \
            mock.patch("secrets_kit.cli._read_metadata", return_value=None) as read_metadata_mock, \
            redirect_stdout(out):
            code = cmd_migrate_metadata(args=args)
        self.assertEqual(code, 0)
        self.assertEqual(secret_exists_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")
        self.assertEqual(read_metadata_mock.call_args.kwargs["path"], "/tmp/test.keychain-db")

    def test_helper_status_command_prints_json(self) -> None:
        out = io.StringIO()
        payload = {"backend_availability": {"local": True, "icloud": False}}
        with mock.patch("secrets_kit.cli.helper_status", return_value=payload), redirect_stdout(out):
            code = cmd_helper_status(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), payload)

    def test_helper_install_local_reports_install(self) -> None:
        out = io.StringIO()
        with mock.patch("secrets_kit.cli.build_and_install_local_helper", return_value=Path("/tmp/seckit-keychain-helper")), \
            mock.patch("secrets_kit.cli.helper_status", return_value={"backend_availability": {"local": True, "icloud": True}}), \
            redirect_stdout(out):
            code = cmd_helper_install_local(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertIn("installed local helper: /tmp/seckit-keychain-helper", out.getvalue())

    def test_helper_install_icloud_aliases_standard_install(self) -> None:
        out = io.StringIO()
        with mock.patch("secrets_kit.cli.build_and_install_local_helper", return_value=Path("/tmp/seckit-keychain-helper")), \
            mock.patch("secrets_kit.cli.helper_status", return_value={"backend_availability": {"local": True, "icloud": True}}), \
            redirect_stdout(out):
            code = cmd_helper_install_icloud(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertIn("alias for the standard helper install", out.getvalue())
        self.assertIn("installed local helper: /tmp/seckit-keychain-helper", out.getvalue())


if __name__ == "__main__":
    unittest.main()
