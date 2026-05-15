"""Phase 5B: ``seckitd`` peer credentials and IPC subprocess tail redaction."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secrets_kit.seckitd.bridge import SubprocessResult
from secrets_kit.seckitd.unix_transport import configure_unix_ipc_socket
from secrets_kit.seckitd.ipc_redact import (
    redact_homedir_paths,
    relay_subprocess_tails_for_ipc,
    truncate_utf8_tail,
    verbose_ipc_enabled,
)
from secrets_kit.seckitd.peer_cred import PeerCredentialError, get_unix_peer_uid, verify_unix_peer_euid
from secrets_kit.seckitd.protocol import DaemonState, handle_request


class IpcRedactTests(unittest.TestCase):
    def test_truncate_utf8_tail(self) -> None:
        s = "é" * 30
        out = truncate_utf8_tail(s, max_bytes=10)
        self.assertLessEqual(len(out.encode("utf-8")), 10)
        self.assertGreater(len(out), 0)

    def test_success_non_verbose_empty_tails(self) -> None:
        so, se = relay_subprocess_tails_for_ipc(
            ok=True,
            stdout='{"ok": true}\n',
            stderr="",
            verbose_ipc=False,
        )
        self.assertEqual(so, "")
        self.assertEqual(se, "")

    def test_success_verbose_includes_redacted_tails(self) -> None:
        with patch.dict(os.environ, {"HOME": "/Users/tester"}):
            raw_out = 'line\n"/Users/tester/secret/path"\n'
            so, se = relay_subprocess_tails_for_ipc(
                ok=True,
                stdout=raw_out,
                stderr="err",
                verbose_ipc=True,
            )
        self.assertIn("<HOME>", so)
        self.assertIn("err", se)

    def test_failure_non_verbose_stderr_only(self) -> None:
        so, se = relay_subprocess_tails_for_ipc(
            ok=False,
            stdout="OUT",
            stderr="ERROR: Peer sync: problem /home/x/data\n",
            verbose_ipc=False,
        )
        self.assertEqual(so, "")
        self.assertIn("<HOME>", se)
        self.assertNotIn("OUT", se)

    def test_redact_homedir_paths(self) -> None:
        with patch.dict(os.environ, {"HOME": "/Users/ghost"}):
            t = redact_homedir_paths("see /Users/ghost/x and /Users/other/y")
        self.assertIn("<HOME>/x", t)
        self.assertIn("<HOME>/y", t)

    def test_verbose_ipc_enabled_env(self) -> None:
        with patch.dict(os.environ, {"SECKITD_VERBOSE_IPC": "1"}):
            self.assertTrue(verbose_ipc_enabled())
        with patch.dict(os.environ, {"SECKITD_VERBOSE_IPC": ""}):
            self.assertFalse(verbose_ipc_enabled())


class PeerCredTests(unittest.TestCase):
    class _Conn:
        pass

    def test_verify_accepts_matching_uid(self) -> None:
        verify_unix_peer_euid(
            self._Conn(),
            expected_euid=1000,
            _peer_uid_fn=lambda _c: 1000,
        )

    def test_verify_rejects_mismatch(self) -> None:
        with self.assertRaises(PeerCredentialError):
            verify_unix_peer_euid(
                self._Conn(),
                expected_euid=1000,
                _peer_uid_fn=lambda _c: 1001,
            )

    def test_insecure_skip_allows_mismatch(self) -> None:
        with patch.dict(os.environ, {"SECKITD_INSECURE_SKIP_PEER_CRED": "1"}):
            verify_unix_peer_euid(
                self._Conn(),
                expected_euid=1000,
                _peer_uid_fn=lambda _c: 9999,
            )

    def test_configure_unix_ipc_socket_on_af_unix(self) -> None:
        """Open ``AF_UNIX``, set platform ``setsockopt``, bind — local CLI ↔ daemon transport only."""
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("Unix domain sockets not available")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                configure_unix_ipc_socket(sock)
            except OSError as exc:
                self.fail(f"setsockopt failed for Unix domain socket: {exc}")

            if sys.platform == "darwin" and hasattr(socket, "SO_NOSIGPIPE"):
                self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE), 1)

            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "ipc.sock"
                sock.bind(str(path))
                sock.listen(1)
        finally:
            sock.close()


class ProtocolRelayIpcTests(unittest.TestCase):
    def test_relay_ok_omits_subprocess_tails_without_verbose(self) -> None:
        wrap = {
            "source_peer": "host-a",
            "destination_peer": "host-b",
            "timestamp": "2026-05-05T12:00:00Z",
            "payload_type": "peer_bundle",
            "payload": "opaque",
        }
        secret_echo = '{"inner":"super-secret-bundle-bytes"}'
        with patch("secrets_kit.seckitd.protocol.verbose_ipc_enabled", return_value=False):
            with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin") as run_mock:
                run_mock.return_value = SubprocessResult(0, '{"merged": true}', "")
                st = DaemonState()
                resp = handle_request(
                    state=st,
                    request={
                        "op": "relay_inbound",
                        "signer": "alice",
                        "wrapper": wrap,
                        "payload_text": secret_echo,
                    },
                )
        self.assertTrue(resp.get("ok"), msg=resp)
        data = resp["data"]
        self.assertEqual(data["stdout_tail"], "")
        self.assertEqual(data["stderr_tail"], "")
        dumped = json.dumps(resp)
        self.assertNotIn("super-secret", dumped)


if __name__ == "__main__":
    unittest.main()
