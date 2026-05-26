"""Taxonomy registry document, seeds, and export."""

from __future__ import annotations

import unittest

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.export import export_taxonomy_registry_text
from secrets_kit.taxonomy.merge import merge_seed_into_registry
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument
from secrets_kit.taxonomy.seed import load_bundled_taxonomy_seeds


class TaxonomyRegistryTest(unittest.TestCase):
    def test_bundled_seeds_are_canonical(self) -> None:
        document = load_bundled_taxonomy_seeds()
        self.assertTrue(any(item.name == "secret" for item in document.entry_types))
        self.assertTrue(any(item.name == "api_key" for item in document.entry_kinds))

    def test_non_canonical_seed_name_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            TaxonomyRegistryDocument.from_dict(
                {"entry_kinds": [{"name": "API_Key", "builtin": True}]}
            )

    def test_export_is_deterministic(self) -> None:
        doc = load_bundled_taxonomy_seeds()
        first = export_taxonomy_registry_text(document=doc.to_dict())
        second = export_taxonomy_registry_text(document=doc.to_dict())
        self.assertEqual(first, second)

    def test_merge_adds_custom_kind(self) -> None:
        base = load_bundled_taxonomy_seeds()
        overlay = TaxonomyRegistryDocument.from_dict(
            {"entry_kinds": [{"name": "jwt", "builtin": False}]}
        )
        merged = merge_seed_into_registry(registry=base, seeds=overlay)
        names = {item.name for item in merged.document.entry_kinds}
        self.assertIn("jwt", names)

    def test_invalid_seed_charset(self) -> None:
        with self.assertRaises(ValidationError):
            TaxonomyRegistryDocument.from_dict(
                {"entry_kinds": [{"name": "bad kind", "builtin": False}]}
            )


if __name__ == "__main__":
    unittest.main()
