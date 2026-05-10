"""Static guards for CLI / sync import boundaries (Phase 2)."""

from __future__ import annotations

import unittest
from pathlib import Path


class ImportLayerGuardsTest(unittest.TestCase):
    def test_parser_does_not_import_cli_main(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        path = repo / "src" / "secrets_kit" / "cli" / "parser" / "base.py"
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("import secrets_kit.cli.main", text)
        self.assertNotIn("secrets_kit.cli.main as", text)

    def test_sync_merge_does_not_import_cli(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        path = repo / "src" / "secrets_kit" / "sync" / "merge.py"
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("secrets_kit.cli", text)

    def test_registry_resolve_does_not_import_cli(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        path = repo / "src" / "secrets_kit" / "registry" / "resolve.py"
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("secrets_kit.cli", text)


if __name__ == "__main__":
    unittest.main()
