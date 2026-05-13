"""Phase 4: public enrollment and transport message wrapper (schemas + helpers)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from secrets_kit.identity.core import init_identity, load_identity
from secrets_kit.identity.enrollment import build_public_enrollment_payload
from secrets_kit.schemas.enrollment import validate_public_enrollment
from secrets_kit.schemas.envelope import validate_transport_message_wrapper
from secrets_kit.sync.envelope import (
    build_transport_message,
    forwarding_subset,
    relay_visible_routing_subset,
)


class Phase4EnrollmentEnvelopeTests(unittest.TestCase):
    def test_public_enrollment_round_trip_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "h"
            init_identity(home=home)
            ident = load_identity(home=home)
            raw = build_public_enrollment_payload(
                ident,
                peer_endpoints=["relay.example:443", "wss://edge.example/session"],
            )
            validated = validate_public_enrollment(raw)
            self.assertEqual(validated.format, "seckit.enrollment_public")
            self.assertEqual(validated.identity.host_id, ident.host_id)
            self.assertEqual(validated.peer_endpoints, ["relay.example:443", "wss://edge.example/session"])
            self.assertNotIn("entry_id", raw)
            self.assertIn("relay_endpoints", raw)

    def test_enrollment_rejects_unknown_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "h"
            init_identity(home=home)
            ident = load_identity(home=home)
            raw = build_public_enrollment_payload(ident)
            raw = dict(raw)
            raw["surprise"] = "nope"
            with self.assertRaises(ValidationError):
                validate_public_enrollment(raw)

    def test_enrollment_rejects_denylisted_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "h"
            init_identity(home=home)
            ident = load_identity(home=home)
            raw = build_public_enrollment_payload(ident)
            raw = dict(raw)
            raw["signing_seed"] = "abcd"
            with self.assertRaises(ValidationError) as ctx:
                validate_public_enrollment(raw)
            self.assertIn("forbidden enrollment key", str(ctx.exception).lower())

    def test_transport_wrapper_and_forwarding_subset_ignores_payload_type(self) -> None:
        base_kw = dict(
            source_peer="00000000-0000-0000-0000-00000000aa01",
            destination_peer="00000000-0000-0000-0000-00000000aa02",
            timestamp="2026-05-05T12:00:00Z",
            payload="opaque-bytes",
            message_id="mid-1",
            forward_token="hop-a",
        )
        m_chat = build_transport_message(payload_type="chat", **base_kw)
        m_sync = build_transport_message(payload_type="sync_bundle", **base_kw)
        validate_transport_message_wrapper(m_chat)
        validate_transport_message_wrapper(m_sync)
        vis_chat = forwarding_subset(m_chat)
        vis_sync = forwarding_subset(m_sync)
        self.assertEqual(vis_chat, vis_sync)
        self.assertNotIn("payload_type", vis_chat)
        self.assertEqual(relay_visible_routing_subset(m_chat), vis_chat)

    def test_transport_wrapper_ttl_optional_and_validated(self) -> None:
        msg = build_transport_message(
            source_peer="a",
            destination_peer="b",
            timestamp="t",
            payload_type="x",
            payload="p",
            ttl=3600,
        )
        v = validate_transport_message_wrapper(msg)
        self.assertEqual(v.ttl, 3600)
        bad = dict(msg)
        bad["ttl"] = 0
        with self.assertRaises(ValidationError):
            validate_transport_message_wrapper(bad)

    def test_forwarding_subset_requires_destination(self) -> None:
        with self.assertRaises(ValueError):
            forwarding_subset({"source_peer": "x"})

    def test_correlation_id_not_allowed_on_wrapper(self) -> None:
        msg = build_transport_message(
            source_peer="a",
            destination_peer="b",
            timestamp="t",
            payload_type="x",
            payload="p",
        )
        msg = dict(msg)
        msg["correlation_id"] = "no"
        with self.assertRaises(ValidationError):
            validate_transport_message_wrapper(msg)


if __name__ == "__main__":
    unittest.main()
