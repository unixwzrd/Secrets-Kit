"""Pure unit tests for Phase 5D runtime session / retry FSM (no daemon I/O)."""

from __future__ import annotations

import base64
import itertools
import unittest

from secrets_kit.seckitd.loopback_transport import LoopbackTransport
from secrets_kit.seckitd.runtime_session import (
    ErrorClass,
    OutboundRuntimeCoordinator,
    RetryPolicy,
    SessionState,
    classify_transport_error,
)


class ClassifyErrorTests(unittest.TestCase):
    def test_transient_types(self) -> None:
        self.assertEqual(classify_transport_error(ConnectionError("x")), ErrorClass.TRANSIENT)
        self.assertEqual(classify_transport_error(BrokenPipeError()), ErrorClass.TRANSIENT)
        self.assertEqual(classify_transport_error(TimeoutError()), ErrorClass.TRANSIENT)
        self.assertEqual(classify_transport_error(OSError(5, "x")), ErrorClass.TRANSIENT)

    def test_terminal_default(self) -> None:
        self.assertEqual(classify_transport_error(ValueError("x")), ErrorClass.TERMINAL)


class CoordinatorLoopbackTests(unittest.TestCase):
    def test_enqueue_and_deliver_roundtrip(self) -> None:
        coord = OutboundRuntimeCoordinator(retry=RetryPolicy(max_connect_attempts=3, max_send_attempts_per_item=3))
        tr = LoopbackTransport()
        raw = b"hello-opaque"
        b64 = base64.standard_b64encode(raw).decode("ascii")
        coord.enqueue(payload_b64=b64, route_hint="r1", payload_type="t", client_ref=None)
        coord.tick(tr)
        coord.tick(tr)
        self.assertEqual(tr.bytes_sent, len(raw))
        self.assertEqual(tr.chunks, [raw])
        snap = coord.snapshot_status()
        self.assertEqual(snap["pending_total_non_authoritative"], 0)

    def test_injected_send_failure_eventually_delivers(self) -> None:
        coord = OutboundRuntimeCoordinator(
            retry=RetryPolicy(
                max_connect_attempts=4,
                max_send_attempts_per_item=8,
                initial_backoff_s=0.001,
                max_backoff_s=0.01,
            )
        )
        clock = itertools.count(0, step=0.1).__next__
        coord.monotonic_fn = clock
        tr = LoopbackTransport()
        tr.inject_send_failures = 1
        b64 = base64.standard_b64encode(b"x").decode("ascii")
        coord.enqueue(payload_b64=b64, route_hint="r1", payload_type=None, client_ref=None)
        coord.tick(tr)
        self.assertFalse(tr.connected)
        route = coord.routes["r1"]
        self.assertEqual(route.session_state, SessionState.BACKING_OFF)
        for _ in range(30):
            coord.tick(tr)
            if tr.bytes_sent > 0:
                break
        self.assertGreater(tr.bytes_sent, 0)

    def test_terminal_after_max_connect(self) -> None:
        coord = OutboundRuntimeCoordinator(
            retry=RetryPolicy(max_connect_attempts=2, max_send_attempts_per_item=3, initial_backoff_s=0.0)
        )
        tr = LoopbackTransport()
        tr.inject_connect_failures = 100
        coord.enqueue(
            payload_b64=base64.standard_b64encode(b"a").decode("ascii"),
            route_hint="z",
            payload_type=None,
            client_ref=None,
        )
        for _ in range(24):
            coord.tick(tr)
        self.assertEqual(coord.routes["z"].session_state, SessionState.TERMINAL_FAILURE)


if __name__ == "__main__":
    unittest.main()
