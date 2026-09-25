"""Installer transport regressions: private headers and failed partial downloads."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class InstallerDownloadTests(unittest.TestCase):
    """Execute the actual shell helpers with isolated downloader processes."""

    def run_download(self, tool: str, *, file: bool, fail: bool = False, probe: bool = False) -> tuple[subprocess.CompletedProcess[str], dict, bytes]:
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        helpers = source.split("download_text() {", 1)[1].split("\njson_python() {", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / tool
            executable.write_text(
                f"#!{sys.executable}\n"
                "import json,os,pathlib,sys\n"
                "args=sys.argv[1:]\n"
                "config=next((a.split('=',1)[1] for a in args if a.startswith('--config=')),None)\n"
                "headers=pathlib.Path(config).read_text() if config else (os.fdopen(3).read() if pathlib.Path(sys.argv[0]).name=='python3' else sys.stdin.read())\n"
                "mode=pathlib.Path(config).stat().st_mode & 0o777 if config else None\n"
                "pathlib.Path(os.environ['PROBE_RECORD']).write_text(json.dumps({'argv':args,'stdin':headers,'mode':mode,'config':config}))\n"
                "target=next((args[args.index(flag)+1] for flag in ('-o','-qO') if flag in args),os.environ.get('SECKIT_DEST'))\n"
                "if target:pathlib.Path(target).write_bytes(b'partial' if os.environ['PROBE_FAIL']=='1' else b'payload')\n"
                "else:sys.stdout.write('payload')\n"
                "sys.exit(22 if os.environ['PROBE_FAIL']=='1' else 0)\n"
            )
            executable.chmod(0o700)
            target = root / "artifact.whl"
            target.write_bytes(b"existing")
            record = root / "record.json"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""),
                       PROBE_RECORD=str(record), PROBE_FAIL="1" if fail else "0",
                       SECKIT_NETWORK_RETRIES="0", SECKIT_CONNECT_TIMEOUT="1", SECKIT_TRANSFER_TIMEOUT="1")
            function = "url_exists" if probe else ("download_file" if file else "download_text")
            arguments = "https://example.invalid/release "
            if file:
                arguments += shlex.quote(str(target)) + " "
            arguments += shlex.quote("Accept: application/octet-stream\nAuthorization: Bearer synthetic-header-probe")
            # The conditional deliberately disables implicit shell errexit.
            script = ("set -euo pipefail\nresolve_downloader() { printf '%s' " + tool + "; }\n"
                      + "download_text() {" + helpers + "\n"
                      + f"if {function} {arguments}; then exit 0; else exit $?; fi\n")
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=10)
            captured = json.loads(record.read_text())
            if captured["config"]:
                self.assertFalse(Path(captured["config"]).exists(), "credential file retained")
                self.assertEqual(captured["mode"], 0o600)
            return result, captured, target.read_bytes()

    def test_headers_never_use_process_arguments(self) -> None:
        for tool in ("curl", "wget", "python3"):
            for file in (False, True):
                with self.subTest(tool=tool, file=file):
                    result, record, content = self.run_download(tool, file=file)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn("synthetic-header-probe", " ".join(record["argv"]))
                    self.assertIn("Authorization: Bearer synthetic-header-probe", record["stdin"])
                    self.assertEqual(content, b"payload" if file else b"existing")

    def test_partial_failed_download_never_replaces_destination(self) -> None:
        for tool in ("curl", "wget", "python3"):
            with self.subTest(tool=tool):
                result, _, content = self.run_download(tool, file=True, fail=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(content, b"existing")

    def test_failed_text_download_propagates_failure(self) -> None:
        for tool in ("curl", "wget", "python3"):
            with self.subTest(tool=tool):
                result, _, _ = self.run_download(tool, file=False, fail=True)
                self.assertNotEqual(result.returncode, 0)

    def test_authenticated_probe_never_exposes_header_in_arguments(self) -> None:
        for tool in ("curl", "wget", "python3"):
            for fail in (False, True):
                with self.subTest(tool=tool, fail=fail):
                    result, record, _ = self.run_download(tool, file=False, fail=fail, probe=True)
                    self.assertEqual(result.returncode == 0, not fail)
                    self.assertNotIn("synthetic-header-probe", " ".join(record["argv"]))
                    self.assertIn("Authorization: Bearer synthetic-header-probe", record["stdin"])


if __name__ == "__main__":
    unittest.main()
