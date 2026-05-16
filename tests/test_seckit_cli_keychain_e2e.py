"""End-to-end ``seckit`` binary against a temp keychain (macOS)."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.keychain.security_cli import check_security_cli, delete_keychain, make_temp_keychain

from macos_integration import _SKIP_INTERACTIVE, keychain_integration_enabled
from platform_guards import SKIP_MACOS_ONLY


def _seckit_argv() -> list[str]:
    override = os.environ.get("SECKIT_BIN", "").strip()
    if override:
        return [override]
    which = shutil.which("seckit")
    if which:
        return [which]
    return []


@unittest.skipUnless(sys.platform == "darwin", SKIP_MACOS_ONLY)
@unittest.skipUnless(check_security_cli(), "security CLI not available")
@unittest.skipUnless(bool(_seckit_argv()), "seckit not on PATH (pip install -e . or set SECKIT_BIN)")
@unittest.skipUnless(keychain_integration_enabled(), _SKIP_INTERACTIVE)
class SeckitCliKeychainE2eTest(unittest.TestCase):
    def test_cli_set_get_delete_temp_keychain(self) -> None:
        seckit = _seckit_argv()
        fixture = make_temp_keychain(password="")
        kc = fixture["path"]
        secret = f"cli-e2e-{secrets.token_hex(8)}"
        try:
            with tempfile.TemporaryDirectory() as home_parent:
                home = Path(home_parent) / "h"
                home.mkdir()
                env = {
                    **os.environ,
                    "HOME": str(home),
                    "PYTHONPATH": os.pathsep.join(
                        [str(Path(__file__).resolve().parents[1] / "src"), os.environ.get("PYTHONPATH", "")]
                    ).strip(os.pathsep),
                }
                base = seckit + [
                    "set",
                    "--name",
                    "CLI_E2E_K",
                    "--value",
                    secret,
                    "--service",
                    "cli-e2e",
                    "--account",
                    "local",
                    "--keychain",
                    kc,
                    "--backend",
                    "secure",
                ]
                r1 = subprocess.run(base, env=env, capture_output=True, text=True, check=False)
                self.assertEqual(r1.returncode, 0, msg=r1.stderr + r1.stdout)
                r2 = subprocess.run(
                    seckit
                    + [
                        "get",
                        "--raw",
                        "--name",
                        "CLI_E2E_K",
                        "--service",
                        "cli-e2e",
                        "--account",
                        "local",
                        "--keychain",
                        kc,
                        "--backend",
                        "secure",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r2.returncode, 0, msg=r2.stderr)
                self.assertEqual(r2.stdout.strip(), secret)
                self.assertNotIn(secret, r2.stderr)
                r3 = subprocess.run(
                    seckit
                    + [
                        "delete",
                        "--yes",
                        "--name",
                        "CLI_E2E_K",
                        "--service",
                        "cli-e2e",
                        "--account",
                        "local",
                        "--keychain",
                        kc,
                        "--backend",
                        "secure",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r3.returncode, 0, msg=r3.stderr)
        finally:
            try:
                delete_keychain(path=kc)
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
