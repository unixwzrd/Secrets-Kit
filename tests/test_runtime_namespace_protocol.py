from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nacl.signing

from secrets_kit.protocol.envelope import (
    PayloadMetadata,
    Principal,
    ProtocolVersionError,
    build_message_envelope,
    reject_unsupported_major,
)
from secrets_kit.protocol.routing import RouteMetadata
from secrets_kit.protocol.signing import sign_envelope, verify_envelope
from secrets_kit.runtime.paths import RuntimePathError, runtime_layout
from secrets_kit.runtime.registry import EndpointRecord, reconstruct_registry, register_endpoint
from secrets_kit.transport.framing import frame_json, parse_json_object


class RuntimeNamespaceTests(unittest.TestCase):
    def test_instances_create_distinct_ephemeral_layouts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"SECKIT_RUNTIME_DIR": td}, clear=False):
                prod = runtime_layout(instance="prod")
                test = runtime_layout(instance="test")
                self.assertNotEqual(prod.root, test.root)
                self.assertTrue(str(prod.root).startswith(td))
                self.assertEqual(prod.sockets_dir.name, "sockets")
                self.assertEqual((prod.root.stat().st_mode & 0o777), 0o700)

    def test_runtime_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"
            target.mkdir()
            link = Path(td) / "link"
            link.symlink_to(target)
            with mock.patch.dict(os.environ, {"SECKIT_RUNTIME_DIR": str(link)}, clear=False):
                with self.assertRaises(RuntimePathError):
                    runtime_layout(instance="prod")

    def test_registry_reconstructs_from_live_artifacts_only(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("requires Unix domain sockets")
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"SECKIT_RUNTIME_DIR": td}, clear=False):
                layout = runtime_layout(instance="prod")
                live = EndpointRecord(
                    instance_id=layout.instance,
                    agent_id="agent-a",
                    endpoint_id="local",
                    socket_path=str(layout.agent_socket_path("agent-a")),
                    pid=os.getpid(),
                    uid=os.geteuid(),
                    protocol_version=1,
                )
                dead = EndpointRecord(
                    instance_id=layout.instance,
                    agent_id="agent-b",
                    endpoint_id="local",
                    socket_path=str(layout.agent_socket_path("agent-b")),
                    pid=99999999,
                    uid=os.geteuid(),
                    protocol_version=1,
                )
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.bind(live.socket_path)
                    sock.listen(1)
                    register_endpoint(layout, live)
                    register_endpoint(layout, dead)
                    rebuilt = reconstruct_registry(layout)
                finally:
                    sock.close()
        self.assertIn(live.key, rebuilt)
        self.assertNotIn(dead.key, rebuilt)


class ProtocolEnvelopeTests(unittest.TestCase):
    def test_unsupported_major_rejected_diagnostically(self) -> None:
        with self.assertRaisesRegex(ProtocolVersionError, "unsupported protocol major"):
            reject_unsupported_major("2.0")

    def test_frame_roundtrip_is_json_object(self) -> None:
        raw = frame_json({"protocol_version": "1.0", "op": "ping"})
        obj = parse_json_object(raw[4:])
        self.assertEqual(obj["protocol_version"], "1.0")

    def test_canonical_signature_independent_of_json_order(self) -> None:
        sk = nacl.signing.SigningKey.generate()
        env = build_message_envelope(
            sender=Principal(node_id="node-a", agent_id="a", instance_id="prod"),
            recipient=Principal(node_id="node-b", agent_id="b", instance_id="prod"),
            route=RouteMetadata(destination_peer="node-b", route_hint="lan"),
            payload=PayloadMetadata(codec="json", content_type="application/json", encryption="none"),
            payload_body='{"hello":"world"}',
        )
        signed = sign_envelope(env, signing_key=sk, key_id="test-key")
        shuffled = json.loads(json.dumps(signed.to_dict(), sort_keys=False))
        reparsed = type(signed).from_dict(shuffled)
        verify_envelope(reparsed, verify_key=sk.verify_key)

    def test_tampered_route_fails_signature(self) -> None:
        sk = nacl.signing.SigningKey.generate()
        signed = sign_envelope(
            build_message_envelope(
                sender=Principal(node_id="node-a"),
                recipient=Principal(node_id="node-b"),
                route=RouteMetadata(destination_peer="node-b"),
                payload_body="opaque",
            ),
            signing_key=sk,
            key_id="test-key",
        )
        raw = signed.to_dict()
        raw["route"]["destination_peer"] = "node-c"
        tampered = type(signed).from_dict(raw)
        with self.assertRaises(Exception):
            verify_envelope(tampered, verify_key=sk.verify_key)


if __name__ == "__main__":
    unittest.main()
