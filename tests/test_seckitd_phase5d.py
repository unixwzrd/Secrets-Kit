"""Phase 5D: seckitd loopback runtime + sync_status IPC integration."""

from __future__ import annotations

import base64
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from secrets_kit.seckitd.client import ipc_call
from secrets_kit.seckitd.server import serve_forever


@unittest.skipUnless(hasattr(__import__("socket"), "AF_UNIX"), "requires Unix domain sockets")
class SeckitdPhase5DLoopbackTests(unittest.TestCase):
    def test_loopback_delivers_and_sync_status(self) -> None:
        os.environ["SECKITD_RUNTIME_LOOPBACK"] = "1"
        try:
            with tempfile.TemporaryDirectory() as td:
                sock = Path(td) / "d.sock"
                stop = threading.Event()

                def _run() -> None:
                    serve_forever(socket_path=sock, stop_flag=stop)

                th = threading.Thread(target=_run, daemon=True)
                th.start()
                try:
                    deadline = time.time() + 5.0
                    while time.time() < deadline and not sock.exists():
                        time.sleep(0.05)
                    self.assertTrue(sock.exists())
                    sync = ipc_call(socket_path=sock, request={"op": "sync_status"}, timeout_s=5.0)
                    self.assertTrue(sync.get("ok"))
                    self.assertTrue(sync["data"]["runtime_loopback_enabled"])
                    payload = b"payload-bytes"
                    sub = ipc_call(
                        socket_path=sock,
                        request={
                            "op": "submit_outbound",
                            "payload_b64": base64.standard_b64encode(payload).decode("ascii"),
                            "route_key": "alpha",
                        },
                        timeout_s=5.0,
                    )
                    self.assertTrue(sub.get("ok"))
                    st2 = {}
                    for _ in range(200):
                        st2 = ipc_call(socket_path=sock, request={"op": "sync_status"}, timeout_s=2.0)
                        if (
                            st2.get("ok")
                            and st2["data"].get("loopback")
                            and st2["data"]["loopback"].get("bytes_sent", 0) > 0
                        ):
                            break
                        time.sleep(0.02)
                    self.assertTrue(st2.get("ok"))
                    self.assertGreater(st2["data"]["loopback"]["bytes_sent"], 0)
                finally:
                    stop.set()
                    th.join(timeout=10.0)
        finally:
            del os.environ["SECKITD_RUNTIME_LOOPBACK"]


if __name__ == "__main__":
    unittest.main()
