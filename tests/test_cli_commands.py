from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit import __version__
from secrets_kit.cli import (
    _apply_defaults,
    _read_password,
    build_parser,
    cmd_config_path,
    cmd_config_set,
    cmd_config_unset,
    cmd_delete,
    cmd_doctor,
    cmd_get,
    cmd_import_env,
    cmd_info,
    cmd_list,
    cmd_lock,
    cmd_run,
    cmd_service_copy,
    cmd_set,
)


class CliCommandsTest(unittest.TestCase):
    def test_keychain_metadata_lookup_does_not_request_password(self) -> None:
        """Metadata lookup must not ask security to disclose the secret."""
        from secrets_kit.backends.keychain.security_cli import SecurityCliStore

        store = SecurityCliStore()
        with mock.patch.object(store, "_target", return_value=None), mock.patch(
            "secrets_kit.backends.keychain.security_cli.run_security_capture",
            return_value=argparse.Namespace(stdout="", stderr=""),
        ) as capture:
            store.raw_metadata(service="test", account="test", name="TOKEN")
        self.assertNotIn("-g", capture.call_args.kwargs["args"])
        self.assertNotIn("-w", capture.call_args.kwargs["args"])

    def test_keychain_metadata_parser_discards_raw_password_output(self) -> None:
        """Unexpected secret-bearing lines must not survive metadata parsing."""
        from secrets_kit.backends.keychain.security_run import parse_find_generic_password_output

        marker = "synthetic-metadata-password-marker"
        metadata = parse_find_generic_password_output(
            raw='attributes:\n    "acct"<blob>="test"\npassword: "' + marker + '"\n'
        )
        self.assertEqual(metadata["account"], "test")
        self.assertNotIn("raw", metadata)
        self.assertNotIn(marker, json.dumps(metadata))

    def test_explain_does_not_expose_keychain_password_output(self) -> None:
        """Trace captured Keychain output through metadata resolution and explain."""
        from secrets_kit.backends.keychain.security_cli import SecurityCliStore
        from secrets_kit.cli.commands.explain import cmd_explain

        marker = "synthetic-explain-password-marker"
        store = SecurityCliStore()
        output = io.StringIO()
        args = argparse.Namespace(name="TOKEN", service="test", account="test", backend="keychain", keychain=None)
        with mock.patch.object(store, "_target", return_value=None), mock.patch(
            "secrets_kit.backends.keychain.security_cli.run_security_capture",
            return_value=argparse.Namespace(stdout='attributes:\n    "acct"<blob>="test"', stderr='password: "' + marker + '"'),
        ), mock.patch("secrets_kit.registry.resolve.secret_exists", return_value=True), mock.patch(
            "secrets_kit.registry.resolve.get_secret_metadata",
            side_effect=lambda **_kwargs: store.raw_metadata(service="test", account="test", name="TOKEN"),
        ), redirect_stdout(output):
            result = cmd_explain(args=args)
        self.assertEqual(result, 0)
        self.assertNotIn(marker, output.getvalue())
        self.assertNotIn("raw", json.loads(output.getvalue())["keychain_fields"])

    def test_backend_default_and_explicit_configuration(self) -> None:
        """Fresh CLI defaults to SQLite; configured and explicit choices win."""
        for configured, explicit, expected in (
            ({}, None, "sqlite"),
            ({"backend": "keychain"}, None, "keychain"),
            ({"backend": "sqlite"}, None, "sqlite"),
            ({"backend": "keychain"}, "sqlite", "sqlite"),
            ({}, "keychain", "keychain"),
        ):
            with self.subTest(configured=configured, explicit=explicit):
                args = argparse.Namespace(command="list", backend=explicit)
                with mock.patch("secrets_kit.cli.defaults._load_defaults", return_value=configured):
                    _apply_defaults(args=args)
                self.assertEqual(args.backend, expected)

    def test_acceptance_fixtures_are_not_a_customer_option(self) -> None:
        """Reject the removed private fixture command."""
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            build_parser().parse_args(["doctor", "--acceptance-test"])
        self.assertEqual(error.exception.code, 2)

    def test_development_lab_is_not_a_customer_command(self) -> None:
        """Keep private test orchestration out of the installed CLI surface."""
        parser = build_parser()
        choices = next(action.choices for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        self.assertNotIn("lab", choices)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            parser.parse_args(["lab", "init"])
        self.assertEqual(error.exception.code, 2)

    def test_defaults_preserve_explicit_rotation_zero_and_tag_alias(self) -> None:
        """Retain absent, empty and zero behavior in compact default assignment."""
        for rotation in (None, 0, 7):
            for tag in (None, "", "explicit"):
                with self.subTest(rotation=rotation, tag=tag):
                    args = argparse.Namespace(command="list", tag=tag, rotation_days=rotation)
                    with mock.patch("secrets_kit.cli.defaults._load_defaults", return_value={"tags": "default", "default_rotation_days": "90"}):
                        _apply_defaults(args=args)
                    self.assertEqual(args.tag, tag or "default")
                    self.assertEqual(args.rotation_days, 90 if rotation is None else rotation)
                    self.assertFalse(hasattr(args, "rotation_warn_days"))
                    self.assertFalse(hasattr(args, "type"))

    def test_invalid_root_flag_prints_full_help(self) -> None:
        parser = build_parser()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                parser.parse_args(["--jelp"])
        self.assertEqual(ctx.exception.code, 2)
        help_text = stdout.getvalue()
        self.assertIn("set", help_text)
        self.assertIn("schema", help_text)
        self.assertIn("taxonomy", help_text)
        self.assertIn("commands:", help_text)
        self.assertIn("error:", stderr.getvalue())

    def test_parser_has_expected_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        for expected in {
            "set",
            "daemon",
            "envelope",
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
            "init",
            "config",
            "info",
            "schema",
            "taxonomy",
            "install",
            "transaction",
            "peer",
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

    def test_sqlite_backend_is_allowed_for_registry_and_service_commands(self) -> None:
        parser = build_parser()
        commands = (
            ["taxonomy", "list", "--backend", "sqlite"],
            ["schema", "list", "--backend", "sqlite"],
            [
                "service",
                "copy",
                "--from-service",
                "OpenClaw",
                "--to-service",
                "Hermes",
                "--backend",
                "sqlite",
            ],
        )
        for argv in commands:
            with self.subTest(command=argv[0]):
                args = parser.parse_args(argv)
                _apply_defaults(args=args)
                self.assertEqual(args.backend, "sqlite")

    def test_service_copy_accounts_use_cli_defaults_before_os_login(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "defaults.json").write_text(
                json.dumps({"account": "local", "backend": "sqlite"}),
                encoding="utf-8",
            )
            args = build_parser().parse_args(
                [
                    "service",
                    "copy",
                    "--from-service",
                    "source",
                    "--to-service",
                    "dest",
                    "--backend",
                    "sqlite",
                ]
            )
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch("getpass.getuser", return_value="mps"),
            ):
                _apply_defaults(args=args)

        self.assertEqual(args.from_account, "local")
        self.assertEqual(args.to_account, "local")
        self.assertEqual(args.account, "local")

    def test_config_parser_routes_subcommands(self) -> None:
        parser = build_parser()
        invalid_backend = "i" + "cloud"
        args = parser.parse_args(["config", "set", "backend", invalid_backend])
        self.assertEqual(args.command, "config")
        self.assertEqual(args.config_command, "set")
        self.assertEqual(args.key, "backend")
        self.assertEqual(args.value, invalid_backend)

    def test_config_set_writes_defaults_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with (
                mock.patch.object(Path, "home", return_value=home),
                redirect_stdout(io.StringIO()),
            ):
                code = cmd_config_set(args=argparse.Namespace(key="backend", value="keychain"))
                self.assertEqual(code, 0)
                dpath = home / ".config" / "seckit" / "defaults.json"
                payload = json.loads(dpath.read_text(encoding="utf-8"))
                self.assertEqual(payload.get("backend"), "keychain")

    def test_config_set_rejects_invalid_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(Path, "home", return_value=Path(tmp)):
                for bad in ("nosuch", "i" + "cloud"):
                    with self.subTest(bad=bad):
                        with redirect_stderr(io.StringIO()):
                            code = cmd_config_set(
                                args=argparse.Namespace(key="backend", value=bad)
                            )
                        self.assertEqual(code, 1)

    def test_config_unset_removes_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with (
                mock.patch.object(Path, "home", return_value=home),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    cmd_config_set(args=argparse.Namespace(key="service", value="my-svc")), 0
                )
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
        args = parser.parse_args(
            ["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token"]
        )
        self.assertEqual(args.kind, "token")
        args = parser.parse_args(
            [
                "set",
                "--name",
                "OPENAI_API_KEY",
                "--value",
                "x",
                "--kind",
                "token",
                "--keychain",
                "/tmp/test.keychain-db",
            ]
        )
        self.assertEqual(args.keychain, "/tmp/test.keychain-db")
        args = parser.parse_args(
            ["set", "--name", "OPENAI_API_KEY", "--value", "x", "--backend", "keychain"]
        )
        self.assertEqual(args.backend, "keychain")

        args = parser.parse_args(["import", "file", "--file", "secrets.json", "--kind", "auto"])
        self.assertEqual(args.kind, "auto")

    def test_doctor_reports_catalog_validation_issues(self) -> None:
        from secrets_kit.models import EntryMetadata
        from secrets_kit.schemas.descriptor import SchemaDescriptor
        from secrets_kit.schemas.registry_doc import SchemaRegistryDocument

        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            err = io.StringIO()
            meta = EntryMetadata(
                name="OPENAI_API_KEY",
                service="openclaw",
                account="miafour",
                entry_kind="api_key",
                custom={"owner": 123},
            )
            catalog = SchemaRegistryDocument(
                schemas={
                    "builtin.secret.api_key": SchemaDescriptor(
                        schema_id="builtin.secret.api_key",
                        schema_version=1,
                        entry_type="secret",
                        entry_kind="api_key",
                        fields={"owner": {"type": "string"}},
                    )
                }
            )
            with (
                mock.patch.object(Path, "home", return_value=Path(tmp)),
                mock.patch("secrets_kit.cli.commands.doctor.check_security_cli", return_value=True),
                mock.patch(
                    "secrets_kit.cli.commands.doctor.registry_path",
                    return_value=mock.MagicMock(
                        is_file=mock.MagicMock(return_value=True),
                        __str__=mock.MagicMock(return_value=f"{tmp}/registry.json"),
                    ),
                ),
                mock.patch("secrets_kit.cli.commands.doctor.doctor_roundtrip", return_value=None),
                mock.patch(
                    "secrets_kit.cli.commands.doctor.load_schema_registry", return_value=catalog
                ),
                mock.patch(
                    "secrets_kit.cli.commands.doctor.list_secret_metadata", return_value=[meta]
                ),
                mock.patch("secrets_kit.cli.commands.doctor.read_metadata", return_value={"metadata": meta}),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                code = cmd_doctor(args=argparse.Namespace())

            self.assertEqual(code, 1)
            payload = json.loads(out.getvalue())
            self.assertTrue(payload["security_cli"])
            self.assertTrue(payload["registry"])
            self.assertTrue(payload["keychain_roundtrip"])
            self.assertEqual(payload["invalid_field_types"][0]["field"], "custom.owner")
            self.assertIn("metadata catalog validation failed", err.getvalue())
            self.assertTrue(payload["defaults"])

    def test_lock_dry_run_shows_backend_command(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.lock.check_security_cli", return_value=True),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = cmd_lock(
                args=argparse.Namespace(
                    keychain="/tmp/login.keychain-db", dry_run=True, yes=False
                )
            )

        self.assertEqual(code, 0)
        self.assertIn("security lock-keychain", out.getvalue())

    def test_lock_runs_backend(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.lock.check_security_cli", return_value=True),
            mock.patch(
                "secrets_kit.cli.commands.lock.lock_keychain", return_value="/tmp/login.keychain-db"
            ),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = cmd_lock(
                args=argparse.Namespace(keychain="/tmp/login.keychain-db", dry_run=False, yes=True)
            )

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
                        "backend": "keychain",
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
            self.assertEqual(args.backend, "keychain")

    def test_apply_defaults_rejects_invalid_backend_in_defaults_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config_dir = home / ".config" / "seckit"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "defaults.json").write_text(
                json.dumps({"service": "s", "account": "a", "backend": "i" + "cloud"}),
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

    def test_apply_defaults_rejects_invalid_explicit_backend(self) -> None:
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
            backend="i" + "cloud",
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
            backend="keychain",
            keychain=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(Path, "home", return_value=Path(tmp)),
                mock.patch("getpass.getuser", return_value="miafour"),
            ):
                _apply_defaults(args=args)
        self.assertEqual(args.account, "miafour")

    def test_read_password_uses_custom_prompt(self) -> None:
        with mock.patch("getpass.getpass", return_value="backup-pass") as getpass_mock:
            value = _read_password(
                value=None, use_stdin=False, prompt="new password to encrypt the backup file: "
            )
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
        fake_meta = mock.Mock(
            entry_type="secret",
            entry_kind="api_key",
            to_keychain_comment=mock.Mock(return_value="{}"),
        )
        with (
            mock.patch("secrets_kit.cli.commands.set.build_metadata", return_value=fake_meta),
            mock.patch("secrets_kit.cli.commands.set.write_secret") as set_secret_mock,
            redirect_stdout(io.StringIO()),
        ):
            code = cmd_set(args=args)
        self.assertEqual(code, 0)
        set_secret_mock.assert_called_once()
        self.assertEqual(set_secret_mock.call_args.kwargs["keychain_path"], "/tmp/test.keychain-db")

    def test_get_passes_keychain_path(self) -> None:
        from secrets_kit.models import EntryMetadata

        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="sync-test",
            account="local",
            keychain="/tmp/test.keychain-db",
        )
        out = io.StringIO()
        fake_meta = EntryMetadata(
            name="OPENAI_API_KEY", service="sync-test", account="local", source="manual"
        )
        with (
            mock.patch(
                "secrets_kit.cli.commands.get.read_secret_entry",
                return_value=("secret", fake_meta),
            ) as read_entry_mock,
            redirect_stdout(out),
        ):
            code = cmd_get(args=args)
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), "secret")
        self.assertEqual(read_entry_mock.call_args.kwargs["keychain_path"], "/tmp/test.keychain-db")

    def test_delete_passes_keychain_path(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            yes=True,
            service="sync-test",
            account="local",
            keychain="/tmp/test.keychain-db",
        )
        with (
            mock.patch("secrets_kit.cli.commands.delete.delete_secret_entry") as delete_secret_mock,
            redirect_stdout(io.StringIO()),
        ):
            code = cmd_delete(args=args)
        self.assertEqual(code, 0)
        self.assertEqual(
            delete_secret_mock.call_args.kwargs["keychain_path"], "/tmp/test.keychain-db"
        )

    def test_doctor_passes_keychain_path(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.doctor.check_security_cli", return_value=True),
            mock.patch(
                "secrets_kit.cli.commands.doctor.registry_path",
                return_value=mock.MagicMock(
                    is_file=mock.MagicMock(return_value=True),
                    __str__=mock.MagicMock(return_value="/tmp/registry.json"),
                ),
            ),
            mock.patch(
                "secrets_kit.cli.commands.doctor.ensure_defaults_storage",
                return_value="/tmp/defaults.json",
            ),
            mock.patch("secrets_kit.cli.commands.doctor.doctor_roundtrip") as doctor_roundtrip_mock,
            mock.patch("secrets_kit.cli.commands.doctor.load_schema_registry"),
            mock.patch("secrets_kit.cli.commands.doctor.list_secret_metadata", return_value=[]),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
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
            backend="keychain",
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

        with (
            mock.patch(
                "secrets_kit.cli.selection.read_metadata",
                side_effect=[
                    {"metadata": openai_meta},
                    {"metadata": telegram_meta},
                ],
            ),
            mock.patch(
                "secrets_kit.cli.selection.build_env_map",
                return_value={"OPENAI_API_KEY": "sk-openai", "TELEGRAM_BOT_TOKEN": "bot-token"},
            ),
            mock.patch("secrets_kit.cli.commands.run._exec_child", return_value=0) as exec_mock,
        ):
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
            backend="keychain",
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
        with (
            mock.patch(
                "secrets_kit.cli.commands.run._select_entries", return_value=[meta]
            ) as select_mock,
            mock.patch("secrets_kit.backends.dispatch.read_secret_value", return_value="sk-openai"),
            mock.patch("secrets_kit.cli.commands.run._exec_child", return_value=0) as exec_mock,
        ):
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
            backend="keychain",
        )
        out = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.service._select_entries", return_value=[meta]),
            mock.patch(
                "secrets_kit.cli.commands.service.secret_exists_for_backend", return_value=True
            ),
            mock.patch("secrets_kit.cli.commands.service.write_secret") as write_secret_mock,
            redirect_stdout(out),
        ):
            code = cmd_service_copy(args=args)
        self.assertEqual(code, 0)
        self.assertFalse(write_secret_mock.called)
        self.assertEqual(json.loads(out.getvalue()), {"created": 0, "skipped": 1, "updated": 0})

    def test_import_env_upsert_allows_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text("OPENAI_API_KEY=sk-new\n", encoding="utf-8")
            args = argparse.Namespace(
                dotenv=str(dotenv),
                from_env=None,
                names=None,
                account="miafour",
                service="Hermes",
                keychain=None,
                backend="keychain",
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
            with (
                mock.patch(
                    "secrets_kit.cli.commands.import_cmd._apply_candidates",
                    return_value={"created": 0, "updated": 1, "skipped": 0, "unchanged": 0},
                ) as apply_mock,
                redirect_stdout(out),
            ):
                code = cmd_import_env(args=args)
        self.assertEqual(code, 0)
        self.assertTrue(apply_mock.call_args.kwargs["allow_overwrite"])

    def test_import_env_names_enforces_exact_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text(
                "OPENROUTER_API_KEY=allowed-one\n"
                "ELEVENLABS_API_KEY=allowed-two\n"
                "UNRELATED_PRIVATE_VALUE=must-not-import\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(
                dotenv=str(dotenv),
                from_env=None,
                names="OPENROUTER_API_KEY,ELEVENLABS_API_KEY",
                account="miafour",
                service="Hermes",
                keychain=None,
                backend="keychain",
                type="secret",
                kind="auto",
                tags=None,
                dry_run=True,
                allow_overwrite=False,
                upsert=False,
                allow_empty=False,
                yes=True,
            )
            out = io.StringIO()
            with (
                mock.patch(
                    "secrets_kit.cli.commands.import_cmd._apply_candidates",
                    return_value={"created": 0, "updated": 0, "skipped": 0, "unchanged": 0},
                ) as apply_mock,
                redirect_stdout(out),
            ):
                code = cmd_import_env(args=args)
        self.assertEqual(code, 0)
        candidates = apply_mock.call_args.kwargs["candidates"]
        self.assertEqual(
            {candidate.metadata.name for candidate in candidates.values()},
            {"OPENROUTER_API_KEY", "ELEVENLABS_API_KEY"},
        )
        self.assertNotIn("must-not-import", out.getvalue())

    def test_import_env_names_fails_closed_when_requested_name_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dotenv = Path(tmp) / ".env"
            dotenv.write_text("OPENROUTER_API_KEY=available\n", encoding="utf-8")
            args = argparse.Namespace(
                dotenv=str(dotenv),
                from_env=None,
                names="OPENROUTER_API_KEY,MISSING_API_KEY",
                account="miafour",
                service="Hermes",
                keychain=None,
                backend="keychain",
                type="secret",
                kind="auto",
                tags=None,
                dry_run=False,
                allow_overwrite=False,
                upsert=False,
                allow_empty=False,
                yes=True,
            )
            with mock.patch("secrets_kit.cli.commands.import_cmd._apply_candidates") as apply_mock:
                code = cmd_import_env(args=args)
        self.assertEqual(code, 1)
        apply_mock.assert_not_called()

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
            backend="keychain",
            child_command=["--"],
        )
        with redirect_stderr(err):
            code = cmd_run(args=args)
        self.assertEqual(code, 2)
        self.assertIn("run requires a target command", err.getvalue())

    def test_run_reports_which_secret_failed_to_read(self) -> None:
        from secrets_kit.backends.keychain import BackendError
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
            backend="keychain",
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
        with (
            mock.patch(
                "secrets_kit.cli.selection.read_metadata", return_value={"metadata": apple_meta}
            ),
            mock.patch(
                "secrets_kit.cli.selection.build_env_map",
                side_effect=BackendError(
                    "failed to read secret for run: service=openclaw account=miafour "
                    "name=APPLE_APP_PASSWORD. Use --names/--tag to narrow the injected set if this command "
                    "does not need every entry in the scope. Underlying error: security find-generic-password failed"
                ),
            ),
            redirect_stderr(err),
        ):
            code = cmd_run(args=args)

        self.assertEqual(code, 1)
        self.assertIn("failed to read secret for run", err.getvalue())
        self.assertIn("name=APPLE_APP_PASSWORD", err.getvalue())
        self.assertIn("--names/--tag", err.getvalue())

    def test_read_metadata_returns_minimal_when_keychain_metadata_read_fails(self) -> None:
        from secrets_kit.backends.keychain import BackendError
        from secrets_kit.registry.resolve import read_metadata

        with (
            mock.patch("secrets_kit.registry.resolve.secret_exists", return_value=True),
            mock.patch(
                "secrets_kit.registry.resolve.get_secret_metadata",
                side_effect=BackendError("metadata denied"),
            ),
        ):
            resolved = read_metadata(
                service="hermes",
                account="miafour",
                name="APPLE_APP_PASSWORD",
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved["metadata_source"], "keychain-minimal")
        self.assertEqual(resolved["metadata"].source, "keychain-unmanaged")
        self.assertEqual(resolved["keychain_fields"], {})

    def test_read_metadata_returns_minimal_when_keychain_metadata_incomplete(self) -> None:
        from secrets_kit.registry.resolve import read_metadata

        with (
            mock.patch("secrets_kit.registry.resolve.secret_exists", return_value=True),
            mock.patch(
                "secrets_kit.registry.resolve.get_secret_metadata",
                return_value={"comment": ""},
            ),
        ):
            resolved = read_metadata(
                service="hermes",
                account="miafour",
                name="APPLE_APP_PASSWORD",
            )

        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved["metadata_source"], "keychain-minimal")

    def test_read_metadata_ignores_registry_only_secret(self) -> None:
        from secrets_kit.registry.resolve import read_metadata

        with mock.patch("secrets_kit.registry.resolve.secret_exists", return_value=False):
            resolved = read_metadata(
                service="hermes",
                account="miafour",
                name="APPLE_APP_PASSWORD",
            )

        self.assertIsNone(resolved)

    def test_list_json_uses_backend_metadata(self) -> None:
        from secrets_kit.models import EntryMetadata

        backend_entry = EntryMetadata(
            name="APPLE_APP_PASSWORD",
            service="hermes",
            account="miafour",
            source="keychain",
        )
        args = argparse.Namespace(
            service="hermes",
            account="miafour",
            type=None,
            kind=None,
            tag=None,
            stale=None,
            format="json",
            keychain=None,
            backend="keychain",
        )
        out = io.StringIO()
        with (
            mock.patch(
                "secrets_kit.cli.commands.list.list_secret_metadata",
                return_value=[backend_entry],
            ),
            redirect_stdout(out),
        ):
            code = cmd_list(args=args)

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload[0]["metadata_source"], "keychain")
        self.assertNotIn("stale_registry_entry", payload[0])
        self.assertNotIn("registry_fallback_used", payload[0])

    def test_migrate_metadata_reports_registry_inventory_removed(self) -> None:
        from secrets_kit.cli import cmd_migrate_metadata

        args = argparse.Namespace(
            service="sync-test",
            account="local",
            dry_run=True,
            force=False,
            keychain="/tmp/test.keychain-db",
            backend="keychain",
        )
        err = io.StringIO()
        with redirect_stderr(err):
            code = cmd_migrate_metadata(args=args)
        self.assertEqual(code, 1)
        self.assertIn("registry inventory migration is no longer supported", err.getvalue())

    def test_info_default_prints_status_text(self) -> None:
        fake_data = {
            "version": __version__,
            "platform": "darwin",
            "python": "3.12.0",
            "backend": "keychain",
            "defaults_path": "/x/defaults.json",
            "registry_path": "/x/registry.json",
            "defaults": {"backend": "keychain"},
            "backend_availability": {"keychain": True, "sqlite": True},
            "keychain": {"supported": True, "available": True, "accessible": True},
            "sqlite": {"included": False, "reason": "inactive"},
        }
        out = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.info.build_info_dict", return_value=fake_data),
            redirect_stdout(out),
        ):
            code = cmd_info(args=argparse.Namespace(info_json=False))
        self.assertEqual(code, 0)
        self.assertIn(f"version: {__version__}", out.getvalue())
        self.assertIn("keychain:", out.getvalue())

    def test_info_json_contains_core_keys(self) -> None:
        fake = {
            "version": "9.9.9",
            "platform": "darwin",
            "python": "3.12.0",
            "defaults_path": "/x/defaults.json",
            "defaults": {"backend": "keychain"},
            "backend_availability": {"keychain": True, "sqlite": True},
            "keychain": {"supported": True},
            "sqlite": {"path": "/tmp/x.sqlite", "exists": False},
        }
        out = io.StringIO()
        with (
            mock.patch("secrets_kit.cli.commands.info.build_info_dict", return_value=fake),
            redirect_stdout(out),
        ):
            code = cmd_info(args=argparse.Namespace(info_json=True))
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed, fake)
        for key in (
            "version",
            "backend_availability",
            "defaults",
            "platform",
            "python",
            "keychain",
            "sqlite",
        ):
            self.assertIn(key, parsed)

    def test_info_keychain_unsupported_off_macos(self) -> None:
        from secrets_kit.cli.commands.info import _keychain_status_dict

        with mock.patch("secrets_kit.cli.commands.info._is_macos", return_value=False):
            kc = _keychain_status_dict()
        self.assertFalse(kc["supported"])

    def test_info_parse_flags(self) -> None:
        parser = build_parser()
        a = parser.parse_args(["info"])
        self.assertFalse(a.info_json)
        b = parser.parse_args(["info", "--json"])
        self.assertTrue(b.info_json)


if __name__ == "__main__":
    unittest.main()
