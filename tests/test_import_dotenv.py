from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secrets_kit.importers import read_dotenv


class ImportDotenvTest(unittest.TestCase):
    def test_parse_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("A=1\nexport B='two'\n# C=3\n", encoding="utf-8")
            parsed = read_dotenv(dotenv_path=path)
            self.assertEqual(parsed["A"], "1")
            self.assertEqual(parsed["B"], "two")
            self.assertNotIn("C", parsed)


if __name__ == "__main__":
    unittest.main()
