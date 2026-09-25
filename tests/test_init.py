"""Tests for seckit init commands."""

from __future__ import annotations

import argparse
import io
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV
from secrets_kit.backends.sqlite.local_hierarchy import local_peer_group_id_for_node
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
    load_sqlite_node_identity_summary,
)
from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.init_cmd import cmd_init, cmd_init_operator, cmd_init_sqlite
from secrets_kit.cli.operator_defaults import initial_operator_defaults, resolve_operator_account
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.registry import (
    defaults_path,
    load_catalog,
    load_defaults,
    registry_path,
    save_defaults,
)
from secrets_kit.schemas.identifiers import schema_id_for_name

GENERIC_SCHEMA_ID = schema_id_for_name(name="builtin.secret.generic")


class InitCommandTest(unittest.TestCase):
    def test_normal_init_help_does_not_offer_security_mode_selection(self) -> None:
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit):
            build_parser().parse_args(["init", "--help"])
        self.assertNotIn("--storage-mode", output.getvalue())
        self.assertNotIn("--unsafe-plaintext-storage", output.getvalue())

    def test_plaintext_initialization_requires_explicit_unsafe_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(home=tmp, storage_mode="plaintext", yes=True)
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(cmd_init(args=args), 1)
            self.assertIn("--unsafe-plaintext-storage", errors.getvalue())
            self.assertFalse((Path(tmp) / ".config/seckit").exists())

    def _sqlite_init_args(self, *, home: Path) -> argparse.Namespace:
        return argparse.Namespace(
            yes=True,
            home=str(home),
            init_target=None,
            backend="sqlite",
        )

    def _assert_bootstrapped_sqlite(self, *, home: Path) -> None:
        db_path = home / ".config" / "seckit" / "seckit.sqlite"
        key_path = home / ".config" / "seckit" / "sqlite-storage.key"
        identity_path = home / ".config" / "seckit" / "node-identity.key"
        self.assertTrue(db_path.is_file())
        self.assertTrue(key_path.is_file())
        self.assertTrue(identity_path.is_file())
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            self.assertGreater(conn.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertGreater(
                conn.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()[
                    0
                ],
                0,
            )
            identity = load_sqlite_node_identity_summary(conn=conn, home=home)
            self.assertIsNotNone(identity)
            projection = load_local_node_projection(conn=conn)
            self.assertIsNotNone(projection)
            assert projection is not None
            self.assertEqual(projection.node_id, identity.node_id)
            self.assertEqual(
                projection.peer_group_id,
                local_peer_group_id_for_node(node_id=identity.node_id),
            )
        finally:
            conn.close()

    def test_resolve_operator_account_prefers_home_over_root_env(self) -> None:
        env = {
            "USER": "root",
            "LOGNAME": "root",
            "HOME": "/Users/seckit",
        }
        with mock.patch.dict("os.environ", env, clear=False):
            self.assertEqual(resolve_operator_account(), "seckit")

    def test_initial_operator_defaults_shape(self) -> None:
        with mock.patch("sys.platform", "darwin"):
            payload = initial_operator_defaults(account="tester")
        self.assertEqual(payload["backend"], "sqlite")
        self.assertEqual(payload["type"], "secret")
        self.assertEqual(payload["kind"], "api_key")
        self.assertEqual(payload["account"], "tester")
        self.assertEqual(payload["default_rotation_days"], 90)

    def test_initial_operator_defaults_accept_backend_override(self) -> None:
        payload = initial_operator_defaults(account="tester", backend="keychain")
        self.assertEqual(payload["backend"], "keychain")

    def test_init_parser_accepts_backend_but_rejects_runtime_dev_alias(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["init", "--backend", "sqlite", "--yes"])
        self.assertEqual(args.backend, "sqlite")
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["init", "--dev"])

    def test_init_operator_writes_defaults_and_catalog_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            args = argparse.Namespace(yes=True, home=str(home), init_target=None, backend="keychain")
            with (
                mock.patch("sys.platform", "darwin"),
                redirect_stdout(io.StringIO()),
            ):
                code = cmd_init_operator(args=args)
            self.assertEqual(code, 0)
            defaults = load_defaults(home=home)
            self.assertEqual(defaults["backend"], "keychain")
            self.assertIn(GENERIC_SCHEMA_ID, load_catalog(home=home).schemas)
            self.assertTrue(defaults_path(home=home).exists())
            self.assertTrue(registry_path(home=home).exists())

    def test_init_operator_sqlite_backend_creates_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            db_path = Path(tmp) / "seckit.sqlite"
            args = argparse.Namespace(
                yes=True,
                home=str(home),
                init_target=None,
                backend="sqlite",
            )
            with (
                mock.patch.dict(
                    "os.environ",
                    {"SECKIT_SQLITE_PATH": str(db_path)},
                    clear=False,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = cmd_init_operator(args=args)
            self.assertEqual(code, 0)
            self.assertTrue(db_path.exists())
            self.assertTrue((Path(tmp) / "node-identity.key").exists())
            defaults = load_defaults(home=home)
            self.assertEqual(defaults["backend"], "sqlite")
            self.assertTrue(registry_path(home=home).exists())

    def test_init_operator_sqlite_backend_bootstraps_fresh_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "fresh-home"
            args = self._sqlite_init_args(home=home)
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                code = cmd_init_operator(args=args)

            self.assertEqual(code, 0)
            self._assert_bootstrapped_sqlite(home=home)

    def test_init_operator_sqlite_backend_bootstraps_fresh_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "config-home"
            (home / ".config" / "seckit").mkdir(parents=True)
            args = self._sqlite_init_args(home=home)
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                code = cmd_init_operator(args=args)

            self.assertEqual(code, 0)
            self._assert_bootstrapped_sqlite(home=home)

    def test_init_operator_sqlite_backend_recreates_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "missing-db-home"
            args = self._sqlite_init_args(home=home)
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                self.assertEqual(cmd_init_operator(args=args), 0)
                (home / ".config" / "seckit" / "seckit.sqlite").unlink()
                self.assertEqual(cmd_init_operator(args=args), 0)

            self._assert_bootstrapped_sqlite(home=home)

    def test_repeated_init_operator_sqlite_backend_leaves_usable_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "repeat-home"
            args = self._sqlite_init_args(home=home)
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                self.assertEqual(cmd_init_operator(args=args), 0)
                self.assertEqual(cmd_init_operator(args=args), 0)

            self._assert_bootstrapped_sqlite(home=home)

    def test_init_operator_home_contains_all_operator_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "operator-home"
            args = argparse.Namespace(
                yes=True,
                home=str(home),
                init_target=None,
                backend="sqlite",
            )
            with (
                mock.patch.dict("os.environ", {"HOME": str(Path(tmp) / "process-home")}),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                import os

                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                code = cmd_init_operator(args=args)

            self.assertEqual(code, 0)
            self.assertTrue(defaults_path(home=home).is_file())
            self.assertTrue(registry_path(home=home).is_file())
            self.assertTrue((home / ".config" / "seckit" / "seckit.sqlite").is_file())

    def test_init_operator_requires_confirmation_without_yes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            save_defaults(payload={"backend": "keychain"}, home=home)
            args = argparse.Namespace(yes=False, home=str(home), init_target=None)
            with (
                mock.patch("secrets_kit.cli.commands.init_cmd._confirm", return_value=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                code = cmd_init_operator(args=args)
            self.assertEqual(code, 1)

    def test_init_sqlite_recreates_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "seckit.sqlite"
            key_path = Path(tmp) / "sqlite-storage.key"
            with mock.patch.dict(
                "os.environ",
                {
                    "SECKIT_SQLITE_PATH": str(db_path),
                    "SECKIT_SQLITE_STORAGE_KEY_PATH": str(key_path),
                },
                clear=False,
            ):
                db_path.write_text("stale", encoding="utf-8")
                args = argparse.Namespace(yes=True, init_target="sqlite")
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = cmd_init_sqlite(args=args)
            self.assertEqual(code, 0)
            self.assertTrue(db_path.exists())
            self.assertTrue(key_path.exists())
            self.assertTrue((Path(tmp) / "node-identity.key").exists())
            self.assertGreater(db_path.stat().st_size, 0)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                with mock.patch.dict(
                    os.environ,
                    {"SECKIT_SQLITE_PATH": str(db_path)},
                    clear=False,
                ):
                    identity = load_sqlite_node_identity_summary(conn=conn)
                self.assertIsNotNone(identity)
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM secrets WHERE name = '__taxonomy_registry__'"
                    ).fetchone()[0],
                    0,
                )
                self.assertGreater(
                    conn.execute("SELECT count(*) FROM entry_types").fetchone()[0], 0
                )
                self.assertGreater(
                    conn.execute("SELECT count(*) FROM entry_kinds").fetchone()[0], 0
                )
            finally:
                conn.close()

    def test_repeated_operator_init_preserves_sqlite_node_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "identity-home"
            args = self._sqlite_init_args(home=home)
            with (
                mock.patch.dict(os.environ, {}, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                os.environ.pop(SQLITE_PATH_ENV, None)
                os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
                os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
                self.assertEqual(cmd_init_operator(args=args), 0)
                conn = sqlite3.connect(home / ".config" / "seckit" / "seckit.sqlite")
                conn.row_factory = sqlite3.Row
                try:
                    first = load_sqlite_node_identity_summary(conn=conn, home=home)
                finally:
                    conn.close()
                self.assertEqual(cmd_init_operator(args=args), 0)
                conn = sqlite3.connect(home / ".config" / "seckit" / "seckit.sqlite")
                conn.row_factory = sqlite3.Row
                try:
                    second = load_sqlite_node_identity_summary(conn=conn, home=home)
                finally:
                    conn.close()

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            if first is None or second is None:
                self.fail("node identity should be present")
            self.assertEqual(first.node_id, second.node_id)
            self.assertEqual(
                first.signing_public_key_fingerprint,
                second.signing_public_key_fingerprint,
            )
            self.assertEqual(
                first.encryption_public_key_fingerprint,
                second.encryption_public_key_fingerprint,
            )

    def test_destructive_sqlite_init_replaces_node_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "seckit.sqlite"
            key_path = Path(tmp) / "sqlite-storage.key"
            identity_path = Path(tmp) / "node-identity.key"
            env = {
                "SECKIT_SQLITE_PATH": str(db_path),
                "SECKIT_SQLITE_STORAGE_KEY_PATH": str(key_path),
            }
            args = argparse.Namespace(yes=True, init_target="sqlite")
            with mock.patch.dict("os.environ", env, clear=False):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(cmd_init_sqlite(args=args), 0)
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                try:
                    first = load_sqlite_node_identity_summary(conn=conn)
                finally:
                    conn.close()

                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(cmd_init_sqlite(args=args), 0)
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                try:
                    second = load_sqlite_node_identity_summary(conn=conn)
                finally:
                    conn.close()

            self.assertTrue(identity_path.is_file())
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            if first is None or second is None:
                self.fail("node identity should be present")
            self.assertNotEqual(first.node_id, second.node_id)
            self.assertNotEqual(
                first.signing_public_key_fingerprint,
                second.signing_public_key_fingerprint,
            )

    def test_bare_init_cli_defaults_to_encrypted_sqlite_and_supports_set_get(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "cli-home"
            env = dict(os.environ)
            env["HOME"] = str(home)
            env.pop(SQLITE_PATH_ENV, None)
            env.pop(SQLITE_STORAGE_KEY_ENV, None)

            init_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "init",
                ],
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(init_result.returncode, 0, init_result.stderr)
            self._assert_bootstrapped_sqlite(home=home)
            self.assertEqual(load_defaults(home=home)["backend"], "sqlite")
            self.assertEqual(load_defaults(home=home)["sqlite_storage_mode"], "encrypted")
            self.assertIn("sqlite", init_result.stdout)
            self.assertIn("encrypted", init_result.stdout)

            set_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "set",
                    "--service",
                    "rb07",
                    "--account",
                    "local",
                    "--name",
                    "RB07_SECRET",
                    "--value",
                    "rb07-value",
                ],
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(set_result.returncode, 0, set_result.stderr)

            get_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "get",
                    "--service",
                    "rb07",
                    "--account",
                    "local",
                    "--name",
                    "RB07_SECRET",
                    "--raw",
                ],
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(get_result.returncode, 0, get_result.stderr)
            self.assertEqual(get_result.stdout.strip(), "rb07-value")

    def test_init_is_allowed_to_create_registry_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self.assertFalse(registry_path(home=home).exists())
            args = argparse.Namespace(
                yes=True,
                home=str(home),
                init_target=None,
                backend="sqlite",
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cmd_init_operator(args=args)
            self.assertEqual(code, 0)
            self.assertIn(GENERIC_SCHEMA_ID, load_catalog(home=home).schemas)

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
