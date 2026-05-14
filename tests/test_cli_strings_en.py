"""Smoke tests for static CLI string modules (human-facing text only; not JSON keys)."""

from __future__ import annotations

import unittest

from secrets_kit.cli.strings import en
from secrets_kit.cli.strings import es
from secrets_kit.cli.strings import it


class CliStaticStringModulesTest(unittest.TestCase):
    def test_en_strings_nonempty_and_main_epilog_stable(self) -> None:
        s = en.STRINGS
        for _k, v in s.items():
            self.assertIsInstance(v, str)
            self.assertGreater(len(v), 0, msg=_k)
        self.assertIn("MAIN_HELP_EPILOG", s)
        self.assertTrue(s["MAIN_HELP_EPILOG"].startswith("Typical paths ("))
        self.assertIn("defaults.json", s["MAIN_HELP_EPILOG"])
        self.assertIn("CONFIG_COMMAND_DESCRIPTION", s)
        self.assertIn("ROOT_DESCRIPTION", s)
        self.assertIn("DOCTOR_HELP", s)

    def test_stub_locale_modules_share_en_strings_until_translated(self) -> None:
        self.assertIs(es.STRINGS, en.STRINGS)
        self.assertIs(it.STRINGS, en.STRINGS)


if __name__ == "__main__":
    unittest.main()
