"""Static contract checks for documentary `runtime_ipc` types (no sockets, no network, no async)."""

from __future__ import annotations

import importlib
import inspect
import unittest
from typing import get_type_hints

import secrets_kit.runtime.ipc as ri


_FORBIDDEN_PUBLIC_NAME_MARKERS = (
    "rpc",
    "broker",
    "grpc",
    "mesh",
)

_FIELD_NEEDLES = ("secret", "password", "token", "plaintext")

_LEAK_NEEDLE = "PLAINTEXT_IPC_TEST_NEEDLE_8821"


class RuntimeIpcContractTest(unittest.TestCase):
    def test_public_names_avoid_broker_rpc_mesh_semantics(self) -> None:
        public = [n for n in dir(ri) if not n.startswith("_")]
        for name in public:
            low = name.lower()
            for bad in _FORBIDDEN_PUBLIC_NAME_MARKERS:
                with self.subTest(name=name, marker=bad):
                    self.assertNotIn(bad, low, msg=f"{name!r} should not imply {bad!r} semantics")

    def test_envelope_fields_avoid_plaintext_field_names(self) -> None:
        hints = get_type_hints(ri.RuntimeIpcEnvelope)
        for field_name in hints:
            low = field_name.lower()
            for needle in _FIELD_NEEDLES:
                with self.subTest(field=field_name):
                    self.assertNotIn(needle, low)

    def test_envelope_repr_does_not_dump_metadata_values(self) -> None:
        env = ri.RuntimeIpcEnvelope(
            request_id="r1",
            operation=ri.RuntimeIpcOperation.ping,
            metadata={"note": _LEAK_NEEDLE},
        )
        text = repr(env)
        self.assertNotIn(_LEAK_NEEDLE, text)

    def test_failure_repr_redacts_message_body(self) -> None:
        fail = ri.RuntimeIpcFailure(code=ri.RuntimeIpcErrorCode.unavailable, message=_LEAK_NEEDLE)
        text = repr(fail)
        self.assertNotIn(_LEAK_NEEDLE, text)

    def test_operation_and_error_enums_non_empty_documentary(self) -> None:
        self.assertGreaterEqual(len(ri.RuntimeIpcOperation), 1)
        self.assertGreaterEqual(len(ri.RuntimeIpcErrorCode), 1)

    def test_module_docstring_posts_non_goals(self) -> None:
        doc = (importlib.import_module("secrets_kit.runtime.ipc").__doc__ or "").lower()
        self.assertIn("not", doc)
        self.assertIn("daemon", doc)
        self.assertIn("wire", doc)

    def test_mediator_protocol_defines_send_recv(self) -> None:
        src = inspect.getsource(ri.RuntimeMediatorProtocol)
        self.assertIn("send_bytes", src)
        self.assertIn("recv_bytes", src)
