"""Taxonomy registry document, seeds, and export."""

from __future__ import annotations

import unittest

from secrets_kit.cli.taxonomy_prompt import resolve_name_for_cli
from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.export import export_taxonomy_registry_text
from secrets_kit.taxonomy.merge import merge_seed_into_registry
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument
from secrets_kit.taxonomy.resolve import resolve_vocabulary_for_write
from secrets_kit.taxonomy.seed import load_bundled_taxonomy_seeds
from secrets_kit.taxonomy.validate import policy_mode_active


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

    def test_policy_mode_depends_only_on_policy_flag(self) -> None:
        self.assertFalse(policy_mode_active())
        self.assertTrue(policy_mode_active(force_policy=True))

    def test_policy_mode_rejects_unknown_vocabulary(self) -> None:
        with self.assertRaises(ValidationError):
            resolve_vocabulary_for_write(
                registry=TaxonomyRegistryDocument.empty(),
                entry_type="secret",
                entry_kind="api_key",
                tags=[],
                policy_mode=True,
            )

    def test_force_raw_prompt_resolution_is_backend_independent(self) -> None:
        args = unittest.mock.Mock(force_raw_name=True, accept_normalized=False, yes=False)
        self.assertEqual(
            resolve_name_for_cli(label="entry_kind", raw="API-Key", args=args),
            "API-Key",
        )


if __name__ == "__main__":
    unittest.main()
