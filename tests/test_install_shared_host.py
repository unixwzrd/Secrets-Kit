"""Exercise the source installer's shared launcher without a root install."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SharedLauncherTest(unittest.TestCase):
    def test_user_launcher_isolates_python_and_native_loader_environment(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        body = source.split("write_launcher() {", 1)[1].split("\ndetect_shell_profile() {", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            runtime = home / ".local/share/seckit/runtime"
            candidate_bin = runtime / "candidate/bin"
            candidate_bin.mkdir(parents=True)
            (runtime / "current").symlink_to("candidate")
            launcher_bin = home / ".local/bin"
            launcher_bin.mkdir(parents=True)
            for name in ("seckit", "seckit-mcp"):
                (candidate_bin / name).symlink_to(sys.executable)
            script = (
                "set -euo pipefail\n"
                "atomic_write_file_from() { cp \"$2\" \"$1\"; }\n"
                f"SECKIT_LAUNCHER_PATH={shlex.quote(str(launcher_bin / 'seckit'))}\n"
                f"SECKIT_MCP_LAUNCHER_PATH={shlex.quote(str(launcher_bin / 'seckit-mcp'))}\n"
                "write_launcher() {" + body + "\nwrite_launcher\n"
            )
            generated = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            polluted = dict(os.environ, HOME=str(home), PYTHONHOME="/tmp/hermes-missing-python",
                            PYTHONPATH="/tmp/hermes-pythonpath", CONDA_PREFIX="/tmp/hermes-conda",
                            VIRTUAL_ENV="/tmp/hermes-venv", OPENSSL_CONF="/tmp/hermes-openssl",
                            OPENSSL_MODULES="/tmp/hermes-modules", LD_LIBRARY_PATH="/tmp/hermes-loader",
                            DYLD_LIBRARY_PATH="/tmp/hermes-dyld")
            probe = "import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(('PYTHON','CONDA_','DYLD_','LD_')) or k in ('VIRTUAL_ENV','OPENSSL_CONF','OPENSSL_MODULES')}))"
            for name in ("seckit", "seckit-mcp"):
                result = subprocess.run([str(launcher_bin / name), "-c", probe], env=polluted,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), '{"PYTHONDONTWRITEBYTECODE": "1"}')

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
                command.write_text(
                    "#!/bin/sh\n"
                    "[ -z \"${PYTHONHOME-}\" ] && [ -z \"${PYTHONPATH-}\" ] && "
                    "[ -z \"${OPENSSL_CONF-}\" ] || exit 9\n"
                    "printf 'candidate:%s\\n' \"$1\"\n",
                    encoding="utf-8",
                )
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
                active = subprocess.run(
                    [str(prefix / "bin" / name), "--version"],
                    env=dict(os.environ, PYTHONHOME="/tmp/hermes-python", PYTHONPATH="/tmp/hermes-path",
                             OPENSSL_CONF="/tmp/hermes-openssl"),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(active.returncode, 0, active.stderr)
                self.assertEqual(active.stdout.strip(), "candidate:--version")


if __name__ == "__main__":
    unittest.main()
