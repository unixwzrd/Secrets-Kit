from __future__ import annotations

import argparse
import importlib.util
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.secrets import cmd_set
from secrets_kit.backends.security import delete_keychain, delete_secret, harden_keychain, keychain_path, make_temp_keychain, secret_exists
from secrets_kit.backends.sqlite.unlock import clear_sqlite_unlock_cache

from platform_guards import SKIP_MACOS_ONLY
from macos_integration import (
    _SKIP_INTERACTIVE,
    launchd_login_keychain_enabled,
    launchd_service_keychain_enabled,
    launchd_sqlite_enabled,
    launchd_tests_enabled,
)


def _launchd_program_arguments_for_seckit_run(
    *,
    run_cli_argv: list[str],
    keychain_path: str | None = None,
    keychain_unlock_password: str | None = None,
) -> list[str]:
    """launchd runs a fresh process; unlock temp keychains before ``seckit run`` (``-p ''`` = no password)."""
    if keychain_path is not None and keychain_unlock_password is not None:
        kc = shlex.quote(keychain_path)
        pw = shlex.quote(keychain_unlock_password)
        cmd = " ".join(shlex.quote(part) for part in run_cli_argv)
        script = f'/usr/bin/security unlock-keychain -p {pw} {kc} && exec {cmd}'
        return ["/bin/bash", "-c", script]
    return run_cli_argv


class LaunchdSmokeScriptInterfaceTest(unittest.TestCase):
    def test_smoke_script_help_lists_supported_modes(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            ["bash", "test-scripts/seckit_launchd_smoke.sh", "--help"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("login-agent", proc.stdout)
        self.assertIn("service-agent", proc.stdout)
        self.assertIn("service-daemon", proc.stdout)
        self.assertIn("--backend", proc.stdout)
        self.assertIn("seckit_launchd_agent_simulator.py", proc.stdout)


@unittest.skipUnless(sys.platform == "darwin", SKIP_MACOS_ONLY)
@unittest.skipUnless(launchd_tests_enabled(), _SKIP_INTERACTIVE)
class LaunchdRunFlowTest(unittest.TestCase):
    def test_launch_agent_can_receive_seckit_run_environment(self) -> None:
        fixture = make_temp_keychain(password="")
        label = f"ai.unixwzrd.seckit.launchd-test.{os.getpid()}"
        service_target = f"gui/{os.getuid()}/{label}"
        try:
            harden_keychain(path=fixture["path"], timeout_seconds=3600)
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                output_file = home / "launchd-env.txt"
                stdout_file = home / "launchd.stdout"
                stderr_file = home / "launchd.stderr"
                plist_file = home / f"{label}.plist"
                repo_root = Path(__file__).resolve().parents[1]

                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name="SECKIT_TEST_ENV",
                        value="expected",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd run env injection",
                        service="launchd-test",
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

                child_code = (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).write_text(os.environ.get('SECKIT_TEST_ENV', ''), encoding='utf-8')"
                )
                run_argv = [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "run",
                    "--service",
                    "launchd-test",
                    "--account",
                    "local",
                    "--keychain",
                    fixture["path"],
                    "--",
                    sys.executable,
                    "-c",
                    child_code,
                    str(output_file),
                ]
                plist = {
                    "Label": label,
                    "ProgramArguments": _launchd_program_arguments_for_seckit_run(
                        run_cli_argv=run_argv,
                        keychain_path=fixture["path"],
                        keychain_unlock_password="",
                    ),
                    "EnvironmentVariables": {
                        "HOME": str(home),
                        "PYTHONPATH": str(repo_root / "src"),
                    },
                    "WorkingDirectory": str(repo_root),
                    "RunAtLoad": False,
                    "StandardOutPath": str(stdout_file),
                    "StandardErrorPath": str(stderr_file),
                }
                with plist_file.open("wb") as handle:
                    plistlib.dump(plist, handle)

                bootstrapped = False
                try:
                    subprocess.run(
                        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_file)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    bootstrapped = True
                    subprocess.run(
                        ["launchctl", "kickstart", "-k", service_target],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if output_file.exists():
                            break
                        time.sleep(0.2)
                    stdout = stdout_file.read_text(encoding="utf-8") if stdout_file.exists() else ""
                    stderr = stderr_file.read_text(encoding="utf-8") if stderr_file.exists() else ""
                    self.assertTrue(output_file.exists(), f"launchd output was not created\nstdout={stdout}\nstderr={stderr}")
                    self.assertEqual(output_file.read_text(encoding="utf-8"), "expected")
                finally:
                    if bootstrapped:
                        subprocess.run(
                            ["launchctl", "bootout", service_target],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
        finally:
            try:
                delete_keychain(path=fixture["path"])
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)

    def test_launch_agent_backend_secure_explicit_uses_temp_keychain(self) -> None:
        """Same as the default temp-keychain test but passes ``--backend secure`` (security CLI path)."""
        fixture = make_temp_keychain(password="")
        label = f"ai.unixwzrd.seckit.launchd-secure-explicit.{os.getpid()}"
        service_target = f"gui/{os.getuid()}/{label}"
        try:
            harden_keychain(path=fixture["path"], timeout_seconds=3600)
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                output_file = home / "launchd-secure-env.txt"
                stdout_file = home / "launchd-secure.stdout"
                stderr_file = home / "launchd-secure.stderr"
                plist_file = home / f"{label}.plist"
                repo_root = Path(__file__).resolve().parents[1]

                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name="SECKIT_TEST_ENV",
                        value="expected-secure",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd secure explicit backend",
                        service="launchd-secure-test",
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
                        backend="secure",
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)

                child_code = (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).write_text(os.environ.get('SECKIT_TEST_ENV', ''), encoding='utf-8')"
                )
                run_argv = [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "run",
                    "--backend",
                    "secure",
                    "--service",
                    "launchd-secure-test",
                    "--account",
                    "local",
                    "--keychain",
                    fixture["path"],
                    "--",
                    sys.executable,
                    "-c",
                    child_code,
                    str(output_file),
                ]
                plist = {
                    "Label": label,
                    "ProgramArguments": _launchd_program_arguments_for_seckit_run(
                        run_cli_argv=run_argv,
                        keychain_path=fixture["path"],
                        keychain_unlock_password="",
                    ),
                    "EnvironmentVariables": {
                        "HOME": str(home),
                        "PYTHONPATH": str(repo_root / "src"),
                    },
                    "WorkingDirectory": str(repo_root),
                    "RunAtLoad": False,
                    "StandardOutPath": str(stdout_file),
                    "StandardErrorPath": str(stderr_file),
                }
                with plist_file.open("wb") as handle:
                    plistlib.dump(plist, handle)

                bootstrapped = False
                try:
                    subprocess.run(
                        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_file)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    bootstrapped = True
                    subprocess.run(
                        ["launchctl", "kickstart", "-k", service_target],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if output_file.exists():
                            break
                        time.sleep(0.2)
                    stdout = stdout_file.read_text(encoding="utf-8") if stdout_file.exists() else ""
                    stderr = stderr_file.read_text(encoding="utf-8") if stderr_file.exists() else ""
                    self.assertTrue(
                        output_file.exists(),
                        f"launchd output was not created\nstdout={stdout}\nstderr={stderr}",
                    )
                    self.assertEqual(output_file.read_text(encoding="utf-8"), "expected-secure")
                finally:
                    if bootstrapped:
                        subprocess.run(
                            ["launchctl", "bootout", service_target],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
        finally:
            try:
                delete_keychain(path=fixture["path"])
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)

    @unittest.skipUnless(
        importlib.util.find_spec("nacl") is not None,
        "SQLite launchd test requires PyNaCl",
    )
    @unittest.skipUnless(launchd_sqlite_enabled(), _SKIP_INTERACTIVE)
    def test_launch_agent_sqlite_backend_injects_env(self) -> None:
        """launchd + ``--backend sqlite`` with a disposable HOME, DB, and dummy passphrase (opt-in)."""
        label = f"ai.unixwzrd.seckit.launchd-sqlite.{os.getpid()}"
        service_target = f"gui/{os.getuid()}/{label}"
        with tempfile.TemporaryDirectory() as home_dir:
            home = Path(home_dir)
            db_file = home / "launchd-sqlite.db"
            passphrase = "launchd-sqlite-dummy-passphrase!!"
            output_file = home / "launchd-sqlite-env.txt"
            stdout_file = home / "launchd-sqlite.stdout"
            stderr_file = home / "launchd-sqlite.stderr"
            plist_file = home / f"{label}.plist"
            repo_root = Path(__file__).resolve().parents[1]

            prev_pass = os.environ.get("SECKIT_SQLITE_PASSPHRASE")
            prev_unlock = os.environ.get("SECKIT_SQLITE_UNLOCK")
            clear_sqlite_unlock_cache()
            try:
                os.environ["SECKIT_SQLITE_PASSPHRASE"] = passphrase
                os.environ["SECKIT_SQLITE_UNLOCK"] = "passphrase"
                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name="SECKIT_TEST_ENV",
                        value="expected-sqlite",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd sqlite env injection",
                        service="launchd-sqlite-test",
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
                        db=str(db_file),
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)
            finally:
                clear_sqlite_unlock_cache()
                if prev_pass is None:
                    os.environ.pop("SECKIT_SQLITE_PASSPHRASE", None)
                else:
                    os.environ["SECKIT_SQLITE_PASSPHRASE"] = prev_pass
                if prev_unlock is None:
                    os.environ.pop("SECKIT_SQLITE_UNLOCK", None)
                else:
                    os.environ["SECKIT_SQLITE_UNLOCK"] = prev_unlock

            child_code = (
                "import os, pathlib, sys; "
                "pathlib.Path(sys.argv[1]).write_text(os.environ.get('SECKIT_TEST_ENV', ''), encoding='utf-8')"
            )
            plist = {
                "Label": label,
                "ProgramArguments": [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "run",
                    "--backend",
                    "sqlite",
                    "--db",
                    str(db_file),
                    "--service",
                    "launchd-sqlite-test",
                    "--account",
                    "local",
                    "--",
                    sys.executable,
                    "-c",
                    child_code,
                    str(output_file),
                ],
                "EnvironmentVariables": {
                    "HOME": str(home),
                    "PYTHONPATH": str(repo_root / "src"),
                    "SECKIT_SQLITE_PASSPHRASE": passphrase,
                    "SECKIT_SQLITE_UNLOCK": "passphrase",
                },
                "WorkingDirectory": str(repo_root),
                "RunAtLoad": False,
                "StandardOutPath": str(stdout_file),
                "StandardErrorPath": str(stderr_file),
            }
            with plist_file.open("wb") as handle:
                plistlib.dump(plist, handle)

            bootstrapped = False
            try:
                subprocess.run(
                    ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_file)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                bootstrapped = True
                subprocess.run(
                    ["launchctl", "kickstart", "-k", service_target],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if output_file.exists():
                        break
                    time.sleep(0.2)
                stdout = stdout_file.read_text(encoding="utf-8") if stdout_file.exists() else ""
                stderr = stderr_file.read_text(encoding="utf-8") if stderr_file.exists() else ""
                self.assertTrue(
                    output_file.exists(),
                    f"launchd sqlite output was not created\nstdout={stdout}\nstderr={stderr}",
                )
                self.assertEqual(output_file.read_text(encoding="utf-8"), "expected-sqlite")
            finally:
                if bootstrapped:
                    subprocess.run(
                        ["launchctl", "bootout", service_target],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

    @unittest.skipUnless(launchd_login_keychain_enabled(), _SKIP_INTERACTIVE)
    def test_launch_agent_can_receive_login_keychain_secret_without_keychain_password(self) -> None:
        """Requires writing to the real login keychain; needs an interactive GUI session.

        Over plain SSH, ``security`` often returns **User interaction is not allowed** for
        ``SecKeychainItemCreateFromContent``. Run this test from Terminal.app on the machine
        while logged in at the console (or ensure Keychain allows the operation for your session).
        """
        label = f"ai.unixwzrd.seckit.launchd-login-test.{os.getpid()}"
        service_target = f"gui/{os.getuid()}/{label}"
        service = "launchd-login-test"
        account = os.environ.get("USER") or "local"
        name = "SECKIT_TEST_ENV"
        login_keychain = keychain_path()
        try:
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                output_file = home / "launchd-login-env.txt"
                stdout_file = home / "launchd-login.stdout"
                stderr_file = home / "launchd-login.stderr"
                plist_file = home / f"{label}.plist"
                repo_root = Path(__file__).resolve().parents[1]

                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name=name,
                        value="expected-login",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd login keychain env injection",
                        service=service,
                        account=account,
                        source_url="",
                        source_label="",
                        rotation_days=None,
                        rotation_warn_days=None,
                        expires_at="",
                        domain=None,
                        domains=None,
                        meta=None,
                        keychain=None,
                        backend="local",
                    )
                    self.assertEqual(cmd_set(args=set_args), 0)

                child_code = (
                    "import os, pathlib, sys; "
                    "pathlib.Path(sys.argv[1]).write_text(os.environ.get('SECKIT_TEST_ENV', ''), encoding='utf-8')"
                )
                plist = {
                    "Label": label,
                    "ProgramArguments": [
                        sys.executable,
                        "-m",
                        "secrets_kit.cli",
                        "run",
                        "--service",
                        service,
                        "--account",
                        account,
                        "--keychain",
                        login_keychain,
                        "--",
                        sys.executable,
                        "-c",
                        child_code,
                        str(output_file),
                    ],
                    "EnvironmentVariables": {
                        "HOME": str(home),
                        "PYTHONPATH": str(repo_root / "src"),
                    },
                    "WorkingDirectory": str(repo_root),
                    "RunAtLoad": False,
                    "StandardOutPath": str(stdout_file),
                    "StandardErrorPath": str(stderr_file),
                }
                with plist_file.open("wb") as handle:
                    plistlib.dump(plist, handle)

                bootstrapped = False
                try:
                    subprocess.run(
                        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_file)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    bootstrapped = True
                    subprocess.run(
                        ["launchctl", "kickstart", "-k", service_target],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if output_file.exists():
                            break
                        time.sleep(0.2)
                    stdout = stdout_file.read_text(encoding="utf-8") if stdout_file.exists() else ""
                    stderr = stderr_file.read_text(encoding="utf-8") if stderr_file.exists() else ""
                    self.assertTrue(output_file.exists(), f"launchd login-keychain output was not created\nstdout={stdout}\nstderr={stderr}")
                    self.assertEqual(output_file.read_text(encoding="utf-8"), "expected-login")
                finally:
                    if bootstrapped:
                        subprocess.run(
                            ["launchctl", "bootout", service_target],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
        finally:
            if secret_exists(service=service, account=account, name=name, path=login_keychain, backend="local"):
                delete_secret(service=service, account=account, name=name, path=login_keychain, backend="local")

    @unittest.skipUnless(
        launchd_service_keychain_enabled(),
        "set SECKIT_RUN_LAUNCHD_SERVICE_KEYCHAIN_TESTS=1 for dedicated service-keychain smoke (optional; temp-keychain launchd tests cover injection)",
    )
    def test_smoke_script_service_agent_mode(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            ["bash", "test-scripts/seckit_launchd_smoke.sh", "--mode", "service-agent"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('"mode": "service-agent"', proc.stdout)
        self.assertIn("launchd smoke test passed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
