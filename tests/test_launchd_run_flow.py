from __future__ import annotations

import argparse
import importlib.util
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from macos_integration import (
    _SKIP_INTERACTIVE,
    launchd_login_keychain_enabled,
    launchd_sqlite_enabled,
    launchd_tests_enabled,
)
from platform_guards import SKIP_MACOS_ONLY
from secrets_kit.backends.security import (
    delete_keychain,
    delete_secret,
    harden_keychain,
    keychain_path,
    make_temp_keychain,
    secret_exists,
)
from secrets_kit.backends.sqlite.unlock import clear_sqlite_unlock_cache
from secrets_kit.cli.commands.secrets import cmd_set


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


def _write_child_script(*, path: Path, env_names: list[str], output_path: Path) -> None:
    """Write a minimal temporary child script for launchd injection tests.

    The script reads the requested environment variables and writes them
    as a JSON object to ``output_path``.
    """
    code = (
        "import json, os, sys\n"
        f"output_file = {str(output_path)!r}\n"
        f"env_names = {env_names!r}\n"
        "payload = {name: os.environ.get(name, '') for name in env_names}\n"
        "with open(output_file, 'w', encoding='utf-8') as f:\n"
        "    json.dump(payload, f)\n"
        "    f.write('\\n')\n"
    )
    path.write_text(code, encoding="utf-8")


def _run_launchd_injection_test(
    *,
    label: str,
    home: Path,
    repo_root: Path,
    program_arguments: list[str],
    env_vars: dict[str, str],
    output_path: Path,
    timeout: float = 20.0,
) -> dict[str, str]:
    """Backend-agnostic launchd environment-injection validation.

    Builds a LaunchAgent plist from the supplied ``program_arguments``,
    bootstraps it into the GUI domain, kickstarts the job, and polls for
    the output file.  Always performs cleanup via ``finally:``.

    The caller is responsible for creating any temporary child scripts
    and constructing the complete ``program_arguments`` (including
    ``seckit run … -- <child>``) so that wrapping helpers such as
    ``_launchd_program_arguments_for_seckit_run`` receive the full
    command.

    Returns a dict with keys:
    - ``output_json``: child output (str)
    - ``stdout``: child stdout (str)
    - ``stderr``: child stderr (str)
    - ``service_target``: launchd target string
    - ``plist_path``: path to the generated plist
    - ``output_path``: path to the child output file
    """
    service_target = f"gui/{os.getuid()}/{label}"
    stdout_path = home / f"{label}.stdout"
    stderr_path = home / f"{label}.stderr"
    plist_path = home / f"{label}.plist"

    plist = {
        "Label": label,
        "ProgramArguments": list(program_arguments),
        "EnvironmentVariables": {
            "HOME": str(home),
            "PYTHONPATH": str(repo_root / "src"),
            **env_vars,
        },
        "WorkingDirectory": str(repo_root),
        "RunAtLoad": False,
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
    }
    with plist_path.open("wb") as handle:
        plistlib.dump(plist, handle)

    bootstrapped = False
    try:
        bootstrap_result = subprocess.run(
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if bootstrap_result.returncode != 0:
            launchctl_print = subprocess.run(
                ["launchctl", "print", service_target],
                capture_output=True,
                text=True,
                check=False,
            )
            raise AssertionError(
                f"launchctl bootstrap failed for {service_target}\n"
                f"plist: {plist_path}\n"
                f"stdout: {bootstrap_result.stdout}\n"
                f"stderr: {bootstrap_result.stderr}\n"
                f"launchctl print: {launchctl_print.stdout}{launchctl_print.stderr}"
            )
        bootstrapped = True

        kickstart_result = subprocess.run(
            ["launchctl", "kickstart", "-k", service_target],
            capture_output=True,
            text=True,
            check=False,
        )
        if kickstart_result.returncode != 0:
            raise AssertionError(
                f"launchctl kickstart failed for {service_target}\n"
                f"stdout: {kickstart_result.stdout}\n"
                f"stderr: {kickstart_result.stderr}"
            )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if output_path.exists():
                break
            time.sleep(0.2)

        stdout = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
        stderr = stderr_path.read_text(encoding="utf-8") if stderr_path.exists() else ""

        if not output_path.exists():
            launchctl_print = subprocess.run(
                ["launchctl", "print", service_target],
                capture_output=True,
                text=True,
                check=False,
            )
            raise AssertionError(
                f"launchd output was not created for {service_target}\n"
                f"plist: {plist_path}\n"
                f"stdout: {stdout}\n"
                f"stderr: {stderr}\n"
                f"launchctl print: {launchctl_print.stdout}{launchctl_print.stderr}"
            )

        output_json = output_path.read_text(encoding="utf-8")
        return {
            "output_json": output_json,
            "stdout": stdout,
            "stderr": stderr,
            "service_target": service_target,
            "plist_path": str(plist_path),
            "output_path": str(output_path),
        }
    finally:
        if bootstrapped:
            subprocess.run(
                ["launchctl", "bootout", service_target],
                capture_output=True,
                text=True,
                check=False,
            )
        for p in (plist_path, output_path, stdout_path, stderr_path):
            if p.exists():
                p.unlink(missing_ok=True)


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

    def test_launch_agent_service_agent_temp_keychain(self) -> None:
        """Python-native launchd validation using a disposable keychain backend.

        Replaces the shell-script ``service-agent`` smoke path with a
        backend-agnostic helper that performs the same validation in pure
        Python.
        """
        fixture = make_temp_keychain(password="")
        label = f"ai.unixwzrd.seckit.launchd-svc.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        try:
            harden_keychain(path=fixture["path"], timeout_seconds=3600)
            with tempfile.TemporaryDirectory() as home_dir:
                home = Path(home_dir)
                repo_root = Path(__file__).resolve().parents[1]

                with mock.patch("pathlib.Path.home", return_value=home):
                    set_args = argparse.Namespace(
                        name="SECKIT_TEST_ENV",
                        value="expected-service-agent",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd service-agent env injection",
                        service="launchd-svc-test",
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

                child_script = home / f"{label}.child.py"
                output_path = home / f"{label}.output.json"
                _write_child_script(
                    path=child_script,
                    env_names=["SECKIT_TEST_ENV"],
                    output_path=output_path,
                )
                run_argv = [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli",
                    "run",
                    "--service",
                    "launchd-svc-test",
                    "--account",
                    "local",
                    "--keychain",
                    fixture["path"],
                    "--",
                    sys.executable,
                    str(child_script),
                    str(output_path),
                ]
                program_arguments = _launchd_program_arguments_for_seckit_run(
                    run_cli_argv=run_argv,
                    keychain_path=fixture["path"],
                    keychain_unlock_password="",
                )

                result = _run_launchd_injection_test(
                    label=label,
                    home=home,
                    repo_root=repo_root,
                    program_arguments=program_arguments,
                    env_vars={},
                    output_path=output_path,
                )
                payload = json.loads(result["output_json"])
                self.assertEqual(payload.get("SECKIT_TEST_ENV"), "expected-service-agent")
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
    def test_launch_agent_service_agent_sqlite_backend(self) -> None:
        """Python-native launchd validation using the SQLite backend.

        Same injection logic as the keychain variant; only the secret
        source changes.
        """
        label = f"ai.unixwzrd.seckit.launchd-sqlite-svc.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        with tempfile.TemporaryDirectory() as home_dir:
            home = Path(home_dir)
            db_file = home / "launchd-sqlite-svc.db"
            passphrase = "launchd-sqlite-svc-dummy-passphrase!!"
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
                        value="expected-sqlite-service",
                        stdin=False,
                        allow_empty=False,
                        type="secret",
                        kind="generic",
                        tags=None,
                        comment="launchd sqlite service-agent env injection",
                        service="launchd-sqlite-svc-test",
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

            child_script = home / f"{label}.child.py"
            output_path = home / f"{label}.output.json"
            _write_child_script(
                path=child_script,
                env_names=["SECKIT_TEST_ENV"],
                output_path=output_path,
            )
            run_argv = [
                sys.executable,
                "-m",
                "secrets_kit.cli",
                "run",
                "--backend",
                "sqlite",
                "--db",
                str(db_file),
                "--service",
                "launchd-sqlite-svc-test",
                "--account",
                "local",
                "--",
                sys.executable,
                str(child_script),
                str(output_path),
            ]
            result = _run_launchd_injection_test(
                label=label,
                home=home,
                repo_root=repo_root,
                program_arguments=run_argv,
                env_vars={
                    "SECKIT_SQLITE_PASSPHRASE": passphrase,
                    "SECKIT_SQLITE_UNLOCK": "passphrase",
                },
                output_path=output_path,
            )
            payload = json.loads(result["output_json"])
            self.assertEqual(payload.get("SECKIT_TEST_ENV"), "expected-sqlite-service")


if __name__ == "__main__":
    unittest.main()
