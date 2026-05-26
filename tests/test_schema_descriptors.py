"""Tests for schema descriptor parsing, export, and merge rules."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.models import ValidationError
from secrets_kit.schemas.descriptor import SchemaDescriptor, bump_schema_version, parse_descriptor
from secrets_kit.schemas.export import export_descriptor_bytes, export_registry_bytes
from secrets_kit.schemas.merge import merge_seed_into_registry
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.seed import load_bundled_seed_descriptors


class SchemaDescriptorTest(unittest.TestCase):
    def test_parse_rejects_non_string_field_type(self) -> None:
        with self.assertRaises(ValidationError):
            parse_descriptor(
                payload={
                    "schema_id": "custom.test",
                    "schema_version": 1,
                    "entry_type": "secret",
                    "entry_kind": "generic",
                    "fields": {"count": {"type": "number"}},
                }
            )

    def test_bundled_seeds_load(self) -> None:
        seeds = load_bundled_seed_descriptors()
        self.assertIn("builtin.secret.generic", seeds)
        self.assertIn("builtin.secret.api_key", seeds)
        self.assertGreaterEqual(len(seeds), 4)

    def test_export_registry_is_deterministic(self) -> None:
        seeds = load_bundled_seed_descriptors()
        doc = SchemaRegistryDocument.empty()
        merged = merge_seed_into_registry(registry=doc, seeds=seeds, allow_replace=False)
        first = export_registry_bytes(document=merged.document.to_dict())
        second = export_registry_bytes(document=merged.document.to_dict())
        self.assertEqual(first, second)
        payload = json.loads(first.decode("utf-8"))
        self.assertEqual(list(payload["schemas"].keys()), sorted(payload["schemas"].keys()))

    def test_merge_field_collision_fails_without_replace(self) -> None:
        base = SchemaRegistryDocument.empty()
        base.schemas["builtin.secret.generic"] = SchemaDescriptor(
            schema_id="builtin.secret.generic",
            schema_version=1,
            entry_type="secret",
            entry_kind="generic",
            fields={"provider": {"type": "string"}},
        )
        seeds = {
            "builtin.secret.generic": SchemaDescriptor(
                schema_id="builtin.secret.generic",
                schema_version=1,
                entry_type="secret",
                entry_kind="generic",
                fields={"provider": {"type": "string", "legacy": "1"}},
            )
        }
        with self.assertRaises(ValidationError):
            merge_seed_into_registry(registry=base, seeds=seeds, allow_replace=False)

    def test_merge_add_only_field_union(self) -> None:
        base = SchemaRegistryDocument.empty()
        base.schemas["builtin.secret.generic"] = SchemaDescriptor(
            schema_id="builtin.secret.generic",
            schema_version=1,
            entry_type="secret",
            entry_kind="generic",
            fields={"provider": {"type": "string"}},
        )
        seeds = {
            "builtin.secret.generic": SchemaDescriptor(
                schema_id="builtin.secret.generic",
                schema_version=1,
                entry_type="secret",
                entry_kind="generic",
                fields={"endpoint": {"type": "string"}},
            )
        }
        result = merge_seed_into_registry(registry=base, seeds=seeds, allow_replace=False)
        fields = result.document.schemas["builtin.secret.generic"].fields
        self.assertIn("provider", fields)
        self.assertIn("endpoint", fields)
        self.assertEqual(result.document.schemas["builtin.secret.generic"].schema_version, 2)

    def test_bump_schema_version_increments(self) -> None:
        desc = SchemaDescriptor(
            schema_id="builtin.secret.generic",
            schema_version=2,
            entry_type="secret",
            entry_kind="generic",
        )
        bumped = bump_schema_version(desc)
        self.assertEqual(bumped.schema_version, 3)

    def test_export_descriptor_sorted_fields(self) -> None:
        desc = {
            "schema_id": "builtin.secret.api_key",
            "schema_version": 1,
            "entry_type": "secret",
            "entry_kind": "api_key",
            "fields": {"endpoint": {"type": "string"}, "provider": {"type": "string"}},
        }
        exported = export_descriptor_bytes(descriptor=desc)
        self.assertIn(b'"endpoint"', exported)
        self.assertLess(exported.index(b"endpoint"), exported.index(b"provider"))

    def test_install_seed_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_id": "custom.secret.widget",
                        "schema_version": 1,
                        "entry_type": "secret",
                        "entry_kind": "widget",
                        "fields": {"region": {"type": "string"}},
                    }
                ),
                encoding="utf-8",
            )
            loaded = parse_descriptor(payload=json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual(loaded.schema_id, "custom.secret.widget")
            self.assertEqual(loaded.fields["region"], {"type": "string"})


if __name__ == "__main__":
    unittest.main()
