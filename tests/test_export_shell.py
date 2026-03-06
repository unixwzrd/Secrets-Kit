from __future__ import annotations

import unittest

from secrets_kit.exporters import export_shell_lines


class ExportShellTest(unittest.TestCase):
    def test_export_quotes_values(self) -> None:
        out = export_shell_lines(env_map={"A": "hello world", "B": "x"})
        self.assertIn("export A='hello world'", out)
        self.assertIn("export B=x", out)


if __name__ == "__main__":
    unittest.main()
