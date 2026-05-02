from __future__ import annotations

import argparse
import io
import os
import subprocess
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from secrets_kit.cli import cmd_export, cmd_get, cmd_import_env, cmd_set
from secrets_kit.keychain_backend import delete_keychain, keychain_path, lock_keychain, make_temp_keychain


def _locked_keychain_tests_enabled() -> bool:
    return os.environ.get("SECKIT_RUN_LOCKED_KEYCHAIN_TESTS") == "1"


@unittest.skipUnless(sys.platform == "darwin", "macOS-only integration test")
class DisposableKeychainFlowTest(unittest.TestCase):
    def test_direct_transfer_between_two_keychains(self) -> None:
        src = make_temp_keychain(password="src-pass")
        dst = make_temp_keychain(password="dst-pass")
        try:
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                with mock.patch("pathlib.Path.home", return_value=home):
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
                        keychain=src["path"],
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)

                    export_args = argparse.Namespace(
                        service="sync-test",
                        account="local",
                        keychain=src["path"],
                        format="shell",
                        out=None,
                        password=None,
                        password_stdin=False,
                        names=None,
                        tag=None,
                        type=None,
                        kind=None,
                        all=True,
                    )
                    shell_out = io.StringIO()
                    with redirect_stdout(shell_out):
                        self.assertEqual(cmd_export(args=export_args), 0)

                    dotenv = home / "import.env"
                    dotenv.write_text(shell_out.getvalue() + "\n", encoding="utf-8")

                    import_args = argparse.Namespace(
                        dotenv=str(dotenv),
                        from_env=None,
                        account="local",
                        service="sync-test",
                        keychain=dst["path"],
                        type="secret",
                        kind="auto",
                        tags=None,
                        dry_run=False,
                        allow_overwrite=True,
                        allow_empty=False,
                        yes=True,
                    )
                    self.assertEqual(cmd_import_env(args=import_args), 0)

                    get_args = argparse.Namespace(
                        name="SECKIT_TEST_ALPHA",
                        raw=True,
                        service="sync-test",
                        account="local",
                        keychain=dst["path"],
                    )
                    out = io.StringIO()
                    with redirect_stdout(out):
                        self.assertEqual(cmd_get(args=get_args), 0)
                    self.assertEqual(out.getvalue().strip(), "alpha-1")
        finally:
            for fixture in (src, dst):
                try:
                    delete_keychain(path=fixture["path"])
                finally:
                    shutil.rmtree(fixture["directory"], ignore_errors=True)

    @unittest.skipUnless(_locked_keychain_tests_enabled(), "set SECKIT_RUN_LOCKED_KEYCHAIN_TESTS=1 to run locked-keychain prompt tests")
    def test_locked_destination_fails_import(self) -> None:
        src = make_temp_keychain(password="src-pass")
        dst = make_temp_keychain(password="dst-pass")
        try:
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                with mock.patch("pathlib.Path.home", return_value=home):
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
                        keychain=src["path"],
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)

                    export_args = argparse.Namespace(
                        service="sync-test",
                        account="local",
                        keychain=src["path"],
                        format="shell",
                        out=None,
                        password=None,
                        password_stdin=False,
                        names=None,
                        tag=None,
                        type=None,
                        kind=None,
                        all=True,
                    )
                    shell_out = io.StringIO()
                    with redirect_stdout(shell_out):
                        self.assertEqual(cmd_export(args=export_args), 0)

                    dotenv = home / "import.env"
                    dotenv.write_text(shell_out.getvalue() + "\n", encoding="utf-8")
                    lock_keychain(path=dst["path"])

                    import_args = argparse.Namespace(
                        dotenv=str(dotenv),
                        from_env=None,
                        account="local",
                        service="sync-test",
                        keychain=dst["path"],
                        type="secret",
                        kind="auto",
                        tags=None,
                        dry_run=False,
                        allow_overwrite=True,
                        allow_empty=False,
                        yes=True,
                    )
                    self.assertEqual(cmd_import_env(args=import_args), 1)
        finally:
            for fixture in (src, dst):
                try:
                    delete_keychain(path=fixture["path"])
                finally:
                    shutil.rmtree(fixture["directory"], ignore_errors=True)

    def test_run_injects_disposable_keychain_secret_into_child_process(self) -> None:
        fixture = make_temp_keychain(password="run-pass")
        try:
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name="SECKIT_TEST_ENV",
                        value="expected",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="run env injection",
                        service="run-test",
                        account="local",
                        source_url="",
                        source_label="",
                        rotation_days=None,
                        rotation_warn_days=None,
                        expires_at="",
                        domain=None,
                        domains=None,
                        meta=None,
                        keychain=fixture["path"],
                        backend="local",
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)

                out_file = home / "child-env.txt"
                child_code = (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).write_text(os.environ.get('SECKIT_TEST_ENV', ''), encoding='utf-8')"
                )
                env = os.environ.copy()
                env["HOME"] = str(home)
                env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
                proc = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "secrets_kit.cli",
                        "run",
                        "--service",
                        "run-test",
                        "--account",
                        "local",
                        "--keychain",
                        fixture["path"],
                        "--",
                        sys.executable,
                        "-c",
                        child_code,
                        str(out_file),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(out_file.read_text(encoding="utf-8"), "expected")
        finally:
            try:
                delete_keychain(path=fixture["path"])
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
