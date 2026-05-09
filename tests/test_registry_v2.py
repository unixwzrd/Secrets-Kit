"""Tests for registry v2 minimal index helpers."""

from __future__ import annotations

import unittest

from secrets_kit.registry.v2 import (
    REGISTRY_FORMAT_VERSION_V2,
    RegistryIndexEntryV2,
    name_hash_hex,
    new_entry_id,
    registry_entry_key,
    v2_registry_document_payload,
)


class RegistryV2Test(unittest.TestCase):
    def test_registry_entry_key(self) -> None:
        self.assertEqual(registry_entry_key(service="x", account="y", name="Z"), "x::y::Z")

    def test_name_hash_stable(self) -> None:
        h = name_hash_hex(service="s", account="a", name="N")
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))
        self.assertEqual(h, name_hash_hex(service="s", account="a", name="N"))
        self.assertNotEqual(
            name_hash_hex(service="s", account="a", name="N"),
            name_hash_hex(service="s", account="a", name="M"),
        )

    def test_new_entry_id_is_uuid(self) -> None:
        u = new_entry_id()
        self.assertEqual(len(u), 36)
        self.assertNotEqual(u, new_entry_id())

    def test_v2_document_round_trip_dict(self) -> None:
        row = RegistryIndexEntryV2(
            id="550e8400-e29b-41d4-a716-446655440000",
            backend="sqlite",
            service="dev-demo",
            account="test-user",
            name_hash=name_hash_hex(service="dev-demo", account="test-user", name="API_KEY"),
            updated_at="2026-05-07T00:00:00Z",
            deleted=False,
        )
        doc = v2_registry_document_payload(entries=[row])
        self.assertEqual(doc["version"], REGISTRY_FORMAT_VERSION_V2)
        self.assertEqual(len(doc["entries"]), 1)
        restored = RegistryIndexEntryV2.from_dict(doc["entries"][0])
        self.assertEqual(restored, row)


if __name__ == "__main__":
    unittest.main()
