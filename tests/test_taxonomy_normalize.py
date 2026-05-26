"""Canonical taxonomy name normalization."""

from __future__ import annotations

import unittest

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.normalize import canonical_taxonomy_name
from secrets_kit.taxonomy.uuid import entry_kind_id_for_name


class TaxonomyNormalizeTest(unittest.TestCase):
    def test_variants_map_to_same_canonical_and_uuid(self) -> None:
        samples = ["API_Key", "api_key", " api_key ", "api-key"]
        canonical = [canonical_taxonomy_name(raw=item) for item in samples]
        self.assertTrue(all(item == "api_key" for item in canonical))
        uuids = {entry_kind_id_for_name(name=item) for item in samples}
        self.assertEqual(len(uuids), 1)

    def test_force_raw_diverges_uuid(self) -> None:
        canonical_id = entry_kind_id_for_name(name="api_key")
        raw_id = entry_kind_id_for_name(name="api-key", force_raw=True)
        self.assertNotEqual(canonical_id, raw_id)

    def test_empty_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            canonical_taxonomy_name(raw="   ")


if __name__ == "__main__":
    unittest.main()
