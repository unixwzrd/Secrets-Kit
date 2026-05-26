from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "secrets_kit"


class ImportLayerGuardTest(unittest.TestCase):
    def test_sqlite_modules_do_not_import_keychain(self) -> None:
        for path in sorted((SRC / "backends" / "sqlite").glob("*.py")):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("secrets_kit.backends.keychain", source)

    def test_keychain_modules_do_not_import_sqlite(self) -> None:
        for path in sorted((SRC / "backends" / "keychain").glob("*.py")):
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("secrets_kit.backends.sqlite", source)


if __name__ == "__main__":
    unittest.main()
