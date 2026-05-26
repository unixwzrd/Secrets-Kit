"""Tests for layered EntryMetadata merge and custom validation."""

from __future__ import annotations

import unittest

from secrets_kit.metadata.merge import merge_entry_metadata
from secrets_kit.models import EntryMetadata, ValidationError
from secrets_kit.schemas.constants import SECKIT_UNDEFINED
from secrets_kit.schemas.descriptor import SchemaDescriptor
from secrets_kit.schemas.validate import is_custom_value_set, validate_custom


class MetadataMergeTest(unittest.TestCase):
    def _descriptor(self) -> SchemaDescriptor:
        return SchemaDescriptor(
            schema_id="builtin.secret.api_key",
            schema_version=1,
            entry_type="secret",
            entry_kind="api_key",
            fields={"provider": {"type": "string"}, "endpoint": {"type": "string"}},
        )

    def test_merge_defaults_descriptor_base_overlay(self) -> None:
        base = EntryMetadata(
            name="KEY",
            service="svc",
            account="acct",
            entry_type="secret",
            entry_kind="api_key",
            schema_id="builtin.secret.api_key",
            custom={"provider": "openai"},
            created_at="2026-01-01T00:00:00Z",
        )
        overlay = EntryMetadata(
            name="KEY",
            service="svc",
            account="acct",
            entry_type="secret",
            entry_kind="api_key",
            custom={"endpoint": "https://api.example"},
        )
        merged = merge_entry_metadata(
            operator_defaults={
                "type": "secret",
                "kind": "generic",
                "service": "default",
                "account": "default",
            },
            descriptor=self._descriptor(),
            base=base,
            overlay=overlay,
        )
        self.assertEqual(merged.custom["provider"], "openai")
        self.assertEqual(merged.custom["endpoint"], "https://api.example")
        self.assertEqual(merged.schema_id, "builtin.secret.api_key")

    def test_validate_rejects_unknown_custom_field(self) -> None:
        meta = EntryMetadata(
            name="KEY",
            service="svc",
            account="acct",
            entry_type="secret",
            entry_kind="api_key",
            custom={"unknown": "x"},
        )
        with self.assertRaises(ValidationError):
            validate_custom(metadata=meta, descriptor=self._descriptor())

    def test_undefined_sentinel_not_counted_as_set(self) -> None:
        self.assertFalse(is_custom_value_set(SECKIT_UNDEFINED))
        self.assertFalse(is_custom_value_set(""))
        self.assertTrue(is_custom_value_set("value"))


if __name__ == "__main__":
    unittest.main()
