from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.keychain import SecurityCliStore
from secrets_kit.backends.sqlite import (
    SQLITE_PATH_ENV,
    SQLITE_PLAINTEXT_DEBUG_ENV,
    SQLITE_UNSAFE_WARNING,
    SqliteSecretStore,
    SQLiteValidationError,
    create_transaction,
    insert_transaction,
    open_sqlite_backend,
    set_sqlite_secret,
)
from secrets_kit.backends.sqlite import gate as sqlite_gate_module
from secrets_kit.cli import (
    build_parser,
    cmd_doctor,
    cmd_export,
    cmd_get,
    cmd_import_env,
    cmd_run,
    cmd_set,
)
from secrets_kit.models import EntryMetadata, now_utc_iso


class SQLiteCliTest(unittest.TestCase):
    def setUp(self) -> None:
        sqlite_gate_module._SQLITE_DEVELOPER_MODE_WARNING_EMITTED = False

    def test_parser_accepts_sqlite_backend_and_dev_mode_flag(self) -> None:
        parser = build_parser()
        for command in ("set", "get", "list", "delete", "explain", "export", "run", "doctor"):
            with self.subTest(command=command):
                argv = [command, "--backend", "sqlite", "--sqlite-dev-mode"]
                if command in {"set", "get", "delete", "explain"}:
                    argv.extend(["--name", "OPENAI_API_KEY"])
                if command == "set":
                    argv.extend(["--value", "secret"])
                if command == "run":
                    argv.extend(["--all", "--", sys.executable, "-c", "print('ok')"])
                args = parser.parse_args(argv)
                self.assertEqual(args.backend, "sqlite")
                self.assertTrue(args.sqlite_dev_mode)
        import_args = parser.parse_args(
            ["import", "env", "--backend", "sqlite", "--sqlite-dev-mode", "--dotenv", "x.env"]
        )
        self.assertEqual(import_args.backend, "sqlite")
        self.assertTrue(import_args.sqlite_dev_mode)

    def test_sqlite_set_requires_explicit_dev_mode(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
            sqlite_dev_mode=False,
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stderr(err),
        ):
            code = cmd_set(args=args)

        self.assertEqual(code, 2)
        self.assertIn("requires --sqlite-dev-mode", err.getvalue())

    def test_sqlite_set_get_roundtrip_and_warning(self) -> None:
        set_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
            sqlite_dev_mode=True,
        )
        get_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="svc",
            account="acct",
            keychain=None,
            backend="sqlite",
            sqlite_dev_mode=True,
        )
        out = io.StringIO()
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            self.assertEqual(cmd_set(args=set_args), 0)
            self.assertEqual(cmd_get(args=get_args), 0)

        self.assertIn("secret\n", out.getvalue())
        self.assertIn(SQLITE_UNSAFE_WARNING, err.getvalue())
        self.assertEqual(err.getvalue().count(SQLITE_UNSAFE_WARNING), 1)

    def test_sqlite_env_ack_allows_operation(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
            sqlite_dev_mode=False,
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ,
                {
                    SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite"),
                    "SECKIT_SQLITE_DEVELOPER_MODE": "1",
                },
                clear=False,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(err),
        ):
            code = cmd_set(args=args)

        self.assertEqual(code, 0)
        self.assertIn(SQLITE_UNSAFE_WARNING, err.getvalue())

    def test_sqlite_plaintext_debug_env_allows_operation(self) -> None:
        store = SqliteSecretStore()
        meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="svc",
            account="acct",
            entry_kind="api_key",
            tags=["prod", "token"],
            rotation_days=30,
            rotation_warn_days=7,
            domains=["example.com"],
            custom={"owner": "ops"},
            source="unit-test",
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {
                    SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite"),
                    SQLITE_PLAINTEXT_DEBUG_ENV: "1",
                },
                clear=False,
            ),
            redirect_stderr(err),
        ):
            self.assertIsInstance(store, SecretStore)
            self.assertIsInstance(SecurityCliStore(), SecretStore)
            store.set(
                service="svc", account="acct", name="OPENAI_API_KEY", value="secret", metadata=meta
            )
            self.assertTrue(store.exists(service="svc", account="acct", name="OPENAI_API_KEY"))
            self.assertEqual(
                store.get(service="svc", account="acct", name="OPENAI_API_KEY"), "secret"
            )
            stored_meta = store.metadata(service="svc", account="acct", name="OPENAI_API_KEY")
            listed = store.list(service="svc", account="acct")
            store.doctor_roundtrip(service="svc", account="acct")

        self.assertEqual(stored_meta.entry_type, "secret")
        self.assertEqual(stored_meta.entry_kind, "api_key")
        self.assertEqual(stored_meta.tags, ["prod", "token"])
        self.assertEqual(stored_meta.rotation_days, 30)
        self.assertEqual(stored_meta.rotation_warn_days, 7)
        self.assertEqual(stored_meta.domains, ["example.com"])
        self.assertEqual(stored_meta.custom, {"owner": "ops"})
        self.assertEqual(stored_meta.source, "unit-test")
        self.assertEqual([item.name for item in listed], ["OPENAI_API_KEY"])
        self.assertIn(SQLITE_UNSAFE_WARNING, err.getvalue())

    def test_sqlite_store_delete_hides_active_projection(self) -> None:
        store = SqliteSecretStore(sqlite_dev_mode=True)
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stderr(io.StringIO()),
        ):
            store.set(
                service="svc", account="acct", name="OPENAI_API_KEY", value="secret", metadata=meta
            )
            store.delete(service="svc", account="acct", name="OPENAI_API_KEY")
            self.assertFalse(store.exists(service="svc", account="acct", name="OPENAI_API_KEY"))
            self.assertEqual(store.list(service="svc", account="acct"), [])

    def test_failed_projection_apply_rolls_back_transaction_insert(self) -> None:
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.secrets_api.apply_transaction",
                side_effect=SQLiteValidationError("boom"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaisesRegex(Exception, "boom"):
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="OPENAI_API_KEY",
                    value="secret",
                    metadata=meta,
                    sqlite_dev_mode=True,
                )
            conn = open_sqlite_backend()
            try:
                count = conn.execute("SELECT count(*) AS n FROM transactions").fetchone()["n"]
            finally:
                conn.close()
        self.assertEqual(count, 0)

    def test_get_does_not_rebuild_missing_projection(self) -> None:
        get_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="svc",
            account="acct",
            keychain=None,
            backend="sqlite",
            sqlite_dev_mode=True,
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stderr(err),
        ):
            conn = open_sqlite_backend()
            try:
                tx = create_transaction(
                    transaction_id="txn-recorded-only",
                    transaction_type="secret.set",
                    origin_node_id="node",
                    created_at=now_utc_iso(),
                    payload={
                        "secret_id": "secret:missing-projection",
                        "owner_id": "owner:missing",
                        "service_group_id": "service-group:missing",
                        "entry_type": "secret",
                        "entry_kind": "api_key",
                        "locator_hash_b64": "bG9jYXRvcg==",
                        "encrypted_name_b64": "T1BFTkFJX0FQSV9LRVk=",
                        "encrypted_payload_b64": "c2VjcmV0",
                        "content_hash_b64": "Y29udGVudA==",
                    },
                )
                insert_transaction(conn=conn, transaction=tx)
            finally:
                conn.close()
            code = cmd_get(args=get_args)

        self.assertEqual(code, 1)
        self.assertIn("entry not found", err.getvalue())

    def test_subprocess_sqlite_smoke_roundtrip_list_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            env["HOME"] = tmp
            env[SQLITE_PATH_ENV] = str(Path(tmp) / "seckit.sqlite")

            def run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-m", "secrets_kit.cli", *argv],
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            set_proc = run_cli(
                "set",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
                "--name",
                "OPENAI_API_KEY",
                "--value",
                "secret",
            )
            self.assertEqual(set_proc.returncode, 0, set_proc.stderr)
            self.assertIn(SQLITE_UNSAFE_WARNING, set_proc.stderr)

            get_proc = run_cli(
                "get",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
                "--name",
                "OPENAI_API_KEY",
                "--raw",
            )
            self.assertEqual(get_proc.returncode, 0, get_proc.stderr)
            self.assertEqual(get_proc.stdout, "secret\n")

            list_proc = run_cli(
                "list",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
            )
            self.assertEqual(list_proc.returncode, 0, list_proc.stderr)
            self.assertIn("OPENAI_API_KEY", list_proc.stdout)

            delete_proc = run_cli(
                "delete",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
                "--name",
                "OPENAI_API_KEY",
                "--yes",
            )
            self.assertEqual(delete_proc.returncode, 0, delete_proc.stderr)
            self.assertIn(SQLITE_UNSAFE_WARNING, delete_proc.stderr)

            get_deleted = run_cli(
                "get",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
                "--name",
                "OPENAI_API_KEY",
                "--raw",
            )
            self.assertNotEqual(get_deleted.returncode, 0)
            self.assertIn("entry not found", get_deleted.stderr)

            list_deleted = run_cli(
                "list",
                "--service",
                "svc",
                "--account",
                "acct",
                "--backend",
                "sqlite",
                "--sqlite-dev-mode",
            )
            self.assertEqual(list_deleted.returncode, 0, list_deleted.stderr)
            self.assertIn("no entries", list_deleted.stdout)

    def test_sqlite_direct_transfer_matches_keychain_cli_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            src_db = Path(tmp) / "source.sqlite"
            dst_db = Path(tmp) / "dest.sqlite"
            source_env = {SQLITE_PATH_ENV: str(src_db)}
            dest_env = {SQLITE_PATH_ENV: str(dst_db)}

            set_args = argparse.Namespace(
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                stdin=False,
                allow_empty=False,
                type="secret",
                kind="generic",
                tags=None,
                comment="source alpha",
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
                keychain=None,
                backend="sqlite",
                sqlite_dev_mode=True,
            )
            export_args = argparse.Namespace(
                service="sync-test",
                account="local",
                keychain=None,
                backend="sqlite",
                format="shell",
                out=None,
                password=None,
                password_stdin=False,
                names=None,
                tag=None,
                type=None,
                kind=None,
                all=True,
                sqlite_dev_mode=True,
            )
            import_args = argparse.Namespace(
                dotenv="",
                from_env=None,
                account="local",
                service="sync-test",
                keychain=None,
                backend="sqlite",
                type="secret",
                kind="auto",
                tags=None,
                dry_run=False,
                allow_overwrite=True,
                upsert=False,
                allow_empty=False,
                yes=True,
                sqlite_dev_mode=True,
            )
            get_args = argparse.Namespace(
                name="SECKIT_TEST_ALPHA",
                raw=True,
                service="sync-test",
                account="local",
                keychain=None,
                backend="sqlite",
                sqlite_dev_mode=True,
            )

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, source_env, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_set(args=set_args), 0)

            shell_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, source_env, clear=False),
                redirect_stdout(shell_out),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_export(args=export_args), 0)

            dotenv = Path(tmp) / "import.env"
            dotenv.write_text(shell_out.getvalue() + "\n", encoding="utf-8")
            import_args.dotenv = str(dotenv)

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_import_env(args=import_args), 0)

            out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(out),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_get(args=get_args), 0)
            self.assertEqual(out.getvalue().strip(), "alpha-1")

            run_args = argparse.Namespace(
                service="sync-test",
                account="local",
                names="SECKIT_TEST_ALPHA",
                tag=None,
                type=None,
                kind=None,
                all=False,
                keychain=None,
                backend="sqlite",
                sqlite_dev_mode=True,
                child_command=[
                    "--",
                    sys.executable,
                    "-c",
                    "import os; print(os.environ['SECKIT_TEST_ALPHA'])",
                ],
            )
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                mock.patch(
                    "secrets_kit.cli.commands.run._exec_child", return_value=0
                ) as exec_child_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_run(args=run_args), 0)
            self.assertEqual(
                exec_child_mock.call_args.kwargs["env"]["SECKIT_TEST_ALPHA"], "alpha-1"
            )

            doctor_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(doctor_out),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    cmd_doctor(
                        args=argparse.Namespace(
                            keychain=None,
                            backend="sqlite",
                            sqlite_dev_mode=True,
                        )
                    ),
                    0,
                )
            self.assertIn('"sqlite_roundtrip": true', doctor_out.getvalue())


if __name__ == "__main__":
    unittest.main()
