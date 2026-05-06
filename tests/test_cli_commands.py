from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout, redirect_stderr

from secrets_kit.cli import (
    _apply_defaults,
    _cli_version,
    _read_password,
    build_parser,
    cmd_config_path,
    cmd_config_set,
    cmd_config_show,
    cmd_config_unset,
    cmd_delete,
    cmd_doctor,
    cmd_get,
    cmd_helper_status,
    cmd_import_env,
    cmd_lock,
    cmd_run,
    cmd_service_copy,
    cmd_set,
    cmd_version,
)


class CliCommandsTest(unittest.TestCase):
    def test_parser_has_expected_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        for expected in {
            "set",
            "get",
            "list",
            "explain",
            "delete",
            "import",
            "export",
            "run",
            "service",
            "doctor",
            "migrate",
            "lock",
            "unlock",
            "keychain-status",
            "helper",
            "config",
            "version",
        }:
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

    def test_service_copy_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "service",
                "copy",
                "--from-service",
                "OpenClaw",
                "--to-service",
                "Hermes",
                "--dry-run",
            ]
        )
        self.assertEqual(args.command, "service")
        self.assertEqual(args.service_command, "copy")
        self.assertEqual(args.from_service, "OpenClaw")
        self.assertEqual(args.to_service, "Hermes")

    def test_config_parser_routes_subcommands(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["config", "set", "backend", "icloud"])
        self.assertEqual(args.command, "config")
        self.assertEqual(args.config_command, "set")
        self.assertEqual(args.key, "backend")
        self.assertEqual(args.value, "icloud")

    def test_config_set_writes_defaults_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with mock.patch.object(Path, "home", return_value=home):
                code = cmd_config_set(args=argparse.Namespace(key="backend", value="local"))
                self.assertEqual(code, 0)
                dpath = home / ".config" / "seckit" / "defaults.json"
                payload = json.loads(dpath.read_text(encoding="utf-8"))
                self.assertEqual(payload.get("backend"), "secure")

    def test_config_set_rejects_icloud_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "home", return_value=Path(tmp)), redirect_stderr(io.StringIO()):
                code = cmd_config_set(args=argparse.Namespace(key="backend", value="icloud"))
        self.assertEqual(code, 1)

    def test_config_set_rejects_invalid_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "home", return_value=Path(tmp)), redirect_stderr(io.StringIO()):
                code = cmd_config_set(args=argparse.Namespace(key="backend", value="nosuch"))
        self.assertEqual(code, 1)

    def test_config_unset_removes_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with mock.patch.object(Path, "home", return_value=home):
                self.assertEqual(cmd_config_set(args=argparse.Namespace(key="service", value="my-svc")), 0)
                self.assertEqual(cmd_config_unset(args=argparse.Namespace(key="service")), 0)
                dpath = home / ".config" / "seckit" / "defaults.json"
                payload = json.loads(dpath.read_text(encoding="utf-8"))
                self.assertNotIn("service", payload)

    def test_config_path_prints_file(self) -> None:
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with mock.patch.object(Path, "home", return_value=home), redirect_stdout(out):
                code = cmd_config_path(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertIn(str(home), out.getvalue())

    def test_kind_flags_parse(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token"])
        self.assertEqual(args.kind, "token")
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token", "--keychain", "/tmp/test.keychain-db"])
        self.assertEqual(args.keychain, "/tmp/test.keychain-db")
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--backend", "local"])
        self.assertEqual(args.backend, "local")

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
            with mock.patch.object(Path, "home", return_value=Path(tmp)), \
                mock.patch("secrets_kit.cli.check_security_cli", return_value=True), \
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
                        "backend": "secure",
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
            with mock.patch("pathlib.Path.home", return_value=home):
                _apply_defaults(args=args)
            self.assertEqual(args.service, "hermes")
            self.assertEqual(args.account, "default")
            self.assertEqual(args.kind, "api_key")
            self.assertEqual(args.rotation_days, 90)
            self.assertEqual(args.rotation_warn_days, 14)
            self.assertEqual(args.backend, "secure")

    def test_apply_defaults_rejects_icloud_in_defaults_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "defaults.json").write_text(
                json.dumps({"service": "s", "account": "a", "backend": "icloud"}),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                command="get",
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
            with mock.patch("pathlib.Path.home", return_value=home):
                with self.assertRaisesRegex(Exception, "unsupported backend"):
                    _apply_defaults(args=args)

    def test_apply_defaults_rejects_icloud_explicit_backend(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "home", return_value=Path(tmp)):
                with self.assertRaisesRegex(Exception, "unsupported backend"):
                    _apply_defaults(args=args)

    def test_account_defaults_to_current_user(self) -> None:
        args = argparse.Namespace(
            command="run",
            service="openclaw",
            account=None,
            type=None,
            kind=None,
            tags=None,
            tag=None,
            rotation_days=None,
            rotation_warn_days=None,
            backend="local",
            keychain=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "home", return_value=Path(tmp)), \
                mock.patch("getpass.getuser", return_value="miafour"):
                _apply_defaults(args=args)
        self.assertEqual(args.account, "miafour")

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

    def test_run_without_names_injects_service_scope(self) -> None:
        from secrets_kit.models import EntryMetadata

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
            child_command=["--", "/usr/bin/env"],
        )
        meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="openclaw",
            account="miafour",
            entry_type="secret",
            entry_kind="api_key",
            source="manual",
        )
        with mock.patch("secrets_kit.cli._select_entries", return_value=[meta]) as select_mock, \
            mock.patch("secrets_kit.cli.get_secret", return_value="sk-openai"), \
            mock.patch("secrets_kit.cli._exec_child", return_value=0) as exec_mock:
            code = cmd_run(args=args)
        self.assertEqual(code, 0)
        self.assertFalse(select_mock.call_args.kwargs["require_explicit_selection"])
        self.assertEqual(exec_mock.call_args.kwargs["env"]["OPENAI_API_KEY"], "sk-openai")

    def test_service_copy_skips_existing_by_default(self) -> None:
        from secrets_kit.models import EntryMetadata

        meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="OpenClaw",
            account="miafour",
            entry_type="secret",
            entry_kind="api_key",
            source="manual",
        )
        args = argparse.Namespace(
            from_service="OpenClaw",
            from_account="miafour",
            to_service="Hermes",
            to_account="miafour",
            names=None,
            tag=None,
            type=None,
            kind=None,
            overwrite=False,
            dry_run=False,
            keychain=None,
            backend="local",
        )
        out = io.StringIO()
        with mock.patch("secrets_kit.cli._select_entries", return_value=[meta]), \
            mock.patch("secrets_kit.cli.get_secret", return_value="sk-openai"), \
            mock.patch("secrets_kit.cli.secret_exists", return_value=True), \
            mock.patch("secrets_kit.cli.set_secret") as set_secret_mock, \
            redirect_stdout(out):
            code = cmd_service_copy(args=args)
        self.assertEqual(code, 0)
        self.assertFalse(set_secret_mock.called)
        self.assertEqual(json.loads(out.getvalue()), {"created": 0, "skipped": 1, "updated": 0})

    def test_import_env_upsert_allows_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text("OPENAI_API_KEY=sk-new\n", encoding="utf-8")
            args = argparse.Namespace(
                dotenv=str(dotenv),
                from_env=None,
                account="miafour",
                service="Hermes",
                keychain=None,
                backend="local",
                type="secret",
                kind="auto",
                tags=None,
                dry_run=False,
                allow_overwrite=False,
                upsert=True,
                allow_empty=False,
                yes=True,
            )
            out = io.StringIO()
            with mock.patch("secrets_kit.cli._apply_candidates", return_value={"created": 0, "updated": 1, "skipped": 0, "unchanged": 0}) as apply_mock, \
                redirect_stdout(out):
                code = cmd_import_env(args=args)
        self.assertEqual(code, 0)
        self.assertTrue(apply_mock.call_args.kwargs["allow_overwrite"])

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

    def test_run_reports_which_secret_failed_to_read(self) -> None:
        from secrets_kit.keychain_backend import BackendError
        from secrets_kit.models import EntryMetadata

        args = argparse.Namespace(
            service="openclaw",
            account="miafour",
            names="APPLE_APP_PASSWORD",
            tag=None,
            type=None,
            kind=None,
            all=False,
            keychain=None,
            backend="local",
            child_command=["--", "/usr/bin/env"],
        )
        apple_meta = EntryMetadata(
            name="APPLE_APP_PASSWORD",
            service="openclaw",
            account="miafour",
            entry_type="secret",
            entry_kind="password",
            source="manual",
        )
        err = io.StringIO()
        with mock.patch("secrets_kit.cli.load_registry", return_value={}), \
            mock.patch("secrets_kit.cli._read_metadata", return_value={"metadata": apple_meta}), \
            mock.patch("secrets_kit.cli.get_secret", side_effect=BackendError("security find-generic-password failed")), \
            redirect_stderr(err):
            code = cmd_run(args=args)

        self.assertEqual(code, 1)
        self.assertIn("failed to read secret for run", err.getvalue())
        self.assertIn("name=APPLE_APP_PASSWORD", err.getvalue())
        self.assertIn("--names/--tag", err.getvalue())

    def test_read_metadata_falls_back_to_registry_when_keychain_metadata_read_fails(self) -> None:
        from secrets_kit.cli import _read_metadata
        from secrets_kit.keychain_backend import BackendError
        from secrets_kit.models import EntryMetadata

        registry_entry = EntryMetadata(
            name="APPLE_APP_PASSWORD",
            service="hermes",
            account="miafour",
            entry_type="secret",
            entry_kind="password",
            source="manual",
        )
        registry = {registry_entry.key(): registry_entry}

        with mock.patch("secrets_kit.cli.secret_exists", return_value=True), \
            mock.patch("secrets_kit.cli.get_secret_metadata", side_effect=BackendError("metadata denied")):
            resolved = _read_metadata(
                service="hermes",
                account="miafour",
                name="APPLE_APP_PASSWORD",
                registry=registry,
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved["metadata_source"], "registry-fallback")
        self.assertTrue(resolved["registry_fallback_used"])
        self.assertEqual(resolved["metadata"], registry_entry)
        self.assertEqual(resolved["keychain_fields"], {})

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
        payload = {"backend_availability": {"local": True, "secure": True, "sqlite": False}}
        with mock.patch("secrets_kit.cli.helper_status", return_value=payload), redirect_stdout(out):
            code = cmd_helper_status(args=argparse.Namespace())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), payload)

    def test_version_default_prints_only_package_version(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cmd_version(args=argparse.Namespace(version_info=False, version_json=False))
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), f"{_cli_version()}\n")

    def test_version_json_contains_core_keys(self) -> None:
        fake = {
            "version": "9.9.9",
            "platform": "darwin",
            "python": "3.12.0",
            "defaults_path": "/x/defaults.json",
            "defaults": {"backend": "secure"},
            "backend_availability": {"secure": True, "local": True, "sqlite": True},
            "helper": {"installed": False, "path": None, "bundled_path": None},
        }
        out = io.StringIO()
        with mock.patch("secrets_kit.cli._version_info_dict", return_value=fake), redirect_stdout(out):
            code = cmd_version(args=argparse.Namespace(version_info=False, version_json=True))
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed, fake)
        for key in ("version", "backend_availability", "helper", "defaults", "platform", "python"):
            self.assertIn(key, parsed)

    def test_version_info_includes_version_line(self) -> None:
        fake_data = {
            "version": "1.0.0",
            "platform": "linux",
            "python": "3.12.0",
            "defaults_path": None,
            "defaults": {},
            "backend_availability": {"secure": True, "local": True, "sqlite": False},
            "helper": {"installed": False, "path": None, "bundled_path": None},
        }
        out = io.StringIO()
        with mock.patch("secrets_kit.cli._version_info_dict", return_value=fake_data), redirect_stdout(out):
            code = cmd_version(args=argparse.Namespace(version_info=True, version_json=False))
        self.assertEqual(code, 0)
        self.assertIn("version: 1.0.0", out.getvalue())
        self.assertIn("platform: linux", out.getvalue())
        self.assertIn("backend_availability:", out.getvalue())

    def test_version_parse_flags(self) -> None:
        parser = build_parser()
        a = parser.parse_args(["version"])
        self.assertFalse(a.version_info)
        self.assertFalse(a.version_json)
        b = parser.parse_args(["version", "--json"])
        self.assertTrue(b.version_json)
        c = parser.parse_args(["version", "--info"])
        self.assertTrue(c.version_info)


if __name__ == "__main__":
    unittest.main()
