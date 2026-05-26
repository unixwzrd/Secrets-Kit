"""Import preserves custom vocabulary kinds (no static ENTRY_KIND_VALUES gate)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.importers import candidates_from_file


class ImportTaxonomyTest(unittest.TestCase):
    def test_file_import_accepts_custom_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "name": "CUSTOM_JWT",
                            "value": "x",
                            "type": "secret",
                            "kind": "oauth_refresh_token",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            items = candidates_from_file(file_path=path)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].metadata.entry_kind, "oauth_refresh_token")


if __name__ == "__main__":
    unittest.main()
