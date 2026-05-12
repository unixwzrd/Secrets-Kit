"""Relay inbound operational boundaries: daemon stays a dumb forwarder (mocked import)."""

from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch

from secrets_kit.seckitd.bridge import SubprocessResult
from secrets_kit.seckitd.protocol import DaemonState, handle_request


def _valid_wrapper() -> dict:
    return {
        "source_peer": "host-a",
        "destination_peer": "host-b",
        "timestamp": "2026-05-05T12:00:00Z",
        "payload_type": "peer_bundle",
        "payload": "opaque-envelope-not-used-for-validation",
    }


class RelayOperationalBoundariesTest(unittest.TestCase):
    def test_relay_structured_response_on_import_nonzero_exit(self) -> None:
        payload = '{"inner":[]}'
        with patch("secrets_kit.seckitd.protocol.verbose_ipc_enabled", return_value=False):
            with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin") as run_mock:
                run_mock.return_value = SubprocessResult(2, "", "sync failed\n")
                resp = handle_request(
                    state=DaemonState(),
                    request={
                        "op": "relay_inbound",
                        "signer": "alice",
                        "wrapper": _valid_wrapper(),
                        "payload_text": payload,
                    },
                )
        self.assertTrue(resp.get("ok"), msg=resp)
        data = resp["data"]
        self.assertEqual(data.get("seckit_exit_code"), 2)
        self.assertFalse(data.get("seckit_ok"))
        allowed_keys = {"seckit_exit_code", "seckit_ok", "stdout_tail", "stderr_tail"}
        self.assertEqual(set(data.keys()), allowed_keys)
        self.assertNotIn("merge", json.dumps(resp))

    def test_relay_success_path_invokes_forward_only(self) -> None:
        payload = "bundle-bytes"
        with patch("secrets_kit.seckitd.protocol.verbose_ipc_enabled", return_value=False):
            with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin") as run_mock:
                run_mock.return_value = SubprocessResult(0, "{}", "")
                resp = handle_request(
                    state=DaemonState(),
                    request={
                        "op": "relay_inbound",
                        "signer": "bob",
                        "wrapper": _valid_wrapper(),
                        "payload_text": payload,
                    },
                    seckit_argv=["/usr/bin/python3", "-m", "x"],
                )
        self.assertTrue(resp.get("ok"), msg=resp)
        self.assertTrue(resp["data"].get("seckit_ok"))
        run_mock.assert_called_once()
        kw = run_mock.call_args.kwargs
        self.assertEqual(kw["bundle_text"], payload)
        self.assertEqual(kw["signer_alias"], "bob")
        self.assertEqual(kw["seckit_argv"], ["/usr/bin/python3", "-m", "x"])

    def test_relay_slow_import_still_structured_ok(self) -> None:
        def _slow(*_a: object, **_k: object) -> SubprocessResult:
            time.sleep(0.03)
            return SubprocessResult(0, "{}", "")

        with patch("secrets_kit.seckitd.protocol.verbose_ipc_enabled", return_value=False):
            with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin", side_effect=_slow):
                resp = handle_request(
                    state=DaemonState(),
                    request={
                        "op": "relay_inbound",
                        "signer": "alice",
                        "wrapper": _valid_wrapper(),
                        "payload_text": "{}",
                    },
                )
        self.assertTrue(resp.get("ok"), msg=resp)
        self.assertTrue(resp["data"].get("seckit_ok"))

    def test_relay_partial_stdout_success_still_structured(self) -> None:
        """Daemon forwards opaque bytes; truncated/non-JSON stdout does not add merge fields."""
        with patch("secrets_kit.seckitd.protocol.verbose_ipc_enabled", return_value=False):
            with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin") as run_mock:
                run_mock.return_value = SubprocessResult(0, '{"partial":true}\n(truncated', "")
                resp = handle_request(
                    state=DaemonState(),
                    request={
                        "op": "relay_inbound",
                        "signer": "alice",
                        "wrapper": _valid_wrapper(),
                        "payload_text": "x",
                    },
                )
        self.assertTrue(resp.get("ok"), msg=resp)
        self.assertTrue(resp["data"].get("seckit_ok"))
        self.assertNotIn("merge", json.dumps(resp))

    def test_relay_side_effect_propagates(self) -> None:
        """Child orchestration errors are not swallowed into merge-shaped IPC."""
        with patch("secrets_kit.seckitd.protocol.run_sync_import_stdin", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                handle_request(
                    state=DaemonState(),
                    request={
                        "op": "relay_inbound",
                        "signer": "alice",
                        "wrapper": _valid_wrapper(),
                        "payload_text": "{}",
                    },
                )


if __name__ == "__main__":
    unittest.main()
