"""
tests.security.test_sqlite_operator_store_permissions

Security regressions for SQLite operator-store permissions.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV, SQLiteBackendError, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import SQLITE_NODE_IDENTITY_KEY_ENV
from secrets_kit.backends.sqlite.operator_store_security import validate_sqlite_operator_store
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.registry import defaults_path, registry_dir, registry_path


class SQLiteOperatorStorePermissionSecurityTest(unittest.TestCase):
    """Security regressions for local SQLite operator-store permissions."""

    def _init_store(self, *, home: Path) -> None:
        args = argparse.Namespace(
            yes=True,
            home=str(home),
            init_target=None,
            backend="sqlite",
        )
        with (
            mock.patch.dict(os.environ, {}, clear=False),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            os.environ.pop(SQLITE_PATH_ENV, None)
            os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
            os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
            self.assertEqual(cmd_init_operator(args=args), 0)

    def _paths(self, *, home: Path) -> dict[str, Path]:
        return {
            "directory": registry_dir(home=home),
            "defaults": defaults_path(home=home),
            "registry": registry_path(home=home),
            "database": registry_dir(home=home) / "seckit.sqlite",
            "storage_key": registry_dir(home=home) / "sqlite-storage.key",
            "node_identity": registry_dir(home=home) / "node-identity.key",
        }

    def _assert_permission_failure(self, *, home: Path, expected_path: Path) -> None:
        with self.assertRaises(SQLiteBackendError) as ctx:
            validate_sqlite_operator_store(home=home)
        message = str(ctx.exception)
        self.assertIn(str(expected_path), message)
        self.assertIn("expected=", message)
        self.assertIn("actual=", message)
        self.assertIn("suggested_fix=", message)
        self.assertIn("chmod", message)
        self.assertIn("chown", message)

    def _replace_with_symlink(self, *, path: Path) -> None:
        target = path.with_name(f"{path.name}.real")
        path.rename(target)
        os.symlink(target, path)

    def test_correct_permissions_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            validate_sqlite_operator_store(home=home)
            conn = open_sqlite_backend(home=home)
            conn.close()

    def test_directory_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["directory"]
            path.chmod(0o755)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_sqlite_database_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["database"]
            path.chmod(0o644)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_sqlite_storage_key_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["storage_key"]
            path.chmod(0o644)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_sqlite_node_identity_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["node_identity"]
            path.chmod(0o644)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_defaults_json_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["defaults"]
            path.chmod(0o644)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_registry_json_too_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["registry"]
            path.chmod(0o644)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_wrong_owner_is_rejected_where_testable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            with self.assertRaises(SQLiteBackendError) as ctx:
                validate_sqlite_operator_store(home=home, current_uid=os.getuid() + 1)
            self.assertIn("expected owner uid", str(ctx.exception))
            self.assertIn("suggested_fix=", str(ctx.exception))

    def test_missing_operator_store_files_are_rejected(self) -> None:
        for label in ("defaults", "registry", "database", "storage_key", "node_identity"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp) / "home"
                self._init_store(home=home)
                path = self._paths(home=home)[label]
                path.unlink()

                self._assert_permission_failure(home=home, expected_path=path)

    def test_missing_operator_store_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"

            self._assert_permission_failure(
                home=home,
                expected_path=registry_dir(home=home),
            )

    def test_newly_initialized_operator_store_passes_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            for label, path in self._paths(home=home).items():
                mode = stat.S_IMODE(path.stat().st_mode)
                expected = 0o700 if label == "directory" else 0o600
                self.assertEqual(mode, expected)
            validate_sqlite_operator_store(home=home)

    def test_symlinked_operator_store_artifacts_are_rejected(self) -> None:
        for label in ("defaults", "registry", "database", "storage_key", "node_identity"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp) / "home"
                self._init_store(home=home)
                path = self._paths(home=home)[label]
                self._replace_with_symlink(path=path)

                self._assert_permission_failure(home=home, expected_path=path)

    def test_symlinked_operator_store_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["directory"]
            target = path.with_name("seckit.real")
            shutil.move(str(path), str(target))
            os.symlink(target, path)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_unexpected_filesystem_object_type_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["defaults"]
            path.unlink()
            os.mkfifo(path)

            self._assert_permission_failure(home=home, expected_path=path)

    def test_malformed_node_identity_material_is_rejected_at_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            path = self._paths(home=home)["node_identity"]
            path.write_text("{not-json\n", encoding="utf-8")
            path.chmod(0o600)

            with self.assertRaises(SQLiteBackendError) as ctx:
                open_sqlite_backend(home=home)

            self.assertIn("invalid SQLite node identity material", str(ctx.exception))

    def test_mismatched_node_identity_projection_is_rejected_at_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            conn = sqlite3.connect(self._paths(home=home)["database"])
            try:
                conn.execute("UPDATE nodes SET signing_public_key = ?", (b"x" * 32,))
                conn.commit()
            finally:
                conn.close()

            with self.assertRaises(SQLiteBackendError) as ctx:
                open_sqlite_backend(home=home)

            self.assertIn("projection does not match", str(ctx.exception))

    def test_swapped_node_identity_between_homes_is_rejected_at_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home_a = Path(tmp) / "home-a"
            home_b = Path(tmp) / "home-b"
            self._init_store(home=home_a)
            self._init_store(home=home_b)
            path_a = self._paths(home=home_a)["node_identity"]
            path_b = self._paths(home=home_b)["node_identity"]
            path_a.write_bytes(path_b.read_bytes())
            path_a.chmod(0o600)

            with self.assertRaises(SQLiteBackendError) as ctx:
                open_sqlite_backend(home=home_a)

            self.assertIn("projection does not match", str(ctx.exception))

    def test_provisioning_followed_by_validation_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            validate_sqlite_operator_store(home=home)
            conn = open_sqlite_backend(home=home)
            conn.close()

    def test_repeated_validation_does_not_modify_filesystem_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            paths = self._paths(home=home)

            before = {
                label: _stat_snapshot(path=path)
                for label, path in paths.items()
            }
            validate_sqlite_operator_store(home=home)
            validate_sqlite_operator_store(home=home)
            after = {
                label: _stat_snapshot(path=path)
                for label, path in paths.items()
            }

            self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()


def _stat_snapshot(*, path: Path) -> tuple[int, int, int, int]:
    metadata = path.lstat()
    return (
        stat.S_IMODE(metadata.st_mode),
        int(metadata.st_ino),
        int(metadata.st_mtime_ns),
        int(metadata.st_size),
    )
