"""Subprocess integration: ``seckit daemon serve`` + ``daemon ping`` over a real UDS.

``test_seckitd_phase5a`` already validates ``serve_forever`` in-process (thread).
This module validates the **operator entrypoint** (``python -m secrets_kit.cli.main``)
and argv parsing for ``daemon serve`` / ``daemon ping``.

Requires Unix domain sockets and permission to bind the temp socket path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


def _repo_src_root() -> Path:
    return Path(__file__).resolve().parents[1] / "src"


@unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "requires Unix domain sockets")
class SeckitDaemonSubprocessIntegrationTest(unittest.TestCase):
    def test_daemon_serve_subprocess_then_ping_exits_zero(self) -> None:
        src = _repo_src_root()
        with tempfile.TemporaryDirectory() as td:
            sock = Path(td) / "subproctest.sock"
            env = {
                **os.environ,
                "PYTHONPATH": str(src),
            }
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "secrets_kit.cli.main",
                    "daemon",
                    "serve",
                    "--socket",
                    str(sock),
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.time() + 15.0
                while time.time() < deadline:
                    if sock.exists():
                        break
                    if proc.poll() is not None:
                        self.fail(f"daemon serve exited early (code {proc.returncode})")
                    time.sleep(0.05)
                self.assertTrue(sock.exists(), "Unix socket was not created")

                ping = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "secrets_kit.cli.main",
                        "daemon",
                        "ping",
                        "--socket",
                        str(sock),
                        "--timeout",
                        "5",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(ping.returncode, 0, ping.stderr + ping.stdout)
                doc = json.loads(ping.stdout)
                self.assertTrue(doc.get("ok"))
                self.assertTrue(doc.get("data", {}).get("pong"))
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
