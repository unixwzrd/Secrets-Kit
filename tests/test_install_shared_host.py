"""Exercise the source installer's shared launcher without a root install."""

from __future__ import annotations

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


class SharedLauncherTest(unittest.TestCase):
    def test_system_mode_does_not_fall_back_to_user_owned_uv(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        body = source.split("find_uv_bin() {", 1)[1].split("\nbootstrap_uv_via_install_script()", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            uv = home / ".local/bin/uv"
            uv.parent.mkdir(parents=True)
            uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            uv.chmod(0o755)
            script = (
                "ensure_operator_path() { :; }\n"
                "SYSTEM_MODE=1\n"
                f"SECKIT_LAUNCHER_BIN_DIR={shlex.quote(str(Path(tmp) / 'bin'))}\n"
                "find_uv_bin() {" + body + "\nfind_uv_bin\n"
            )
            result = subprocess.run(
                ["bash", "-c", script], env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_launcher_selects_active_generation_and_rejects_unactivated(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        body = source.split("write_system_launcher() {", 1)[1].split("\nemit_json() {", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "shared"
            runtime = prefix / "runtime"
            candidate = runtime / "runtime-candidate"
            candidate_bin = candidate / "bin"
            candidate_bin.mkdir(parents=True)
            (prefix / "bin").mkdir()
            for name in ("seckit", "seckit-mcp"):
                command = candidate_bin / name
                command.write_text("#!/bin/sh\nprintf 'candidate:%s\\n' \"$1\"\n", encoding="utf-8")
                command.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                "install_die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                f"SECKIT_RUNTIME_DIR={shlex.quote(str(runtime))}\n"
                f"SECKIT_LAUNCHER_PATH={shlex.quote(str(prefix / 'bin/seckit'))}\n"
                f"SECKIT_MCP_LAUNCHER_PATH={shlex.quote(str(prefix / 'bin/seckit-mcp'))}\n"
                "write_system_launcher() {" + body + "\nwrite_system_launcher\n"
            )
            generated = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            launcher = prefix / "bin/seckit"
            inactive = subprocess.run([str(launcher), "--version"], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(inactive.returncode, 0)
            (runtime / "current").symlink_to(candidate)
            for name in ("seckit", "seckit-mcp"):
                active = subprocess.run([str(prefix / "bin" / name), "--version"], capture_output=True, text=True, timeout=10)
                self.assertEqual(active.returncode, 0, active.stderr)
                self.assertEqual(active.stdout.strip(), "candidate:--version")


if __name__ == "__main__":
    unittest.main()
