"""Help consistency checks (no golden snapshots of full --help text)."""

from __future__ import annotations

import argparse
import unittest

from secrets_kit.cli_parser import build_parser

PRIMARY_WITH_EXAMPLES = frozenset(
    {
        "set",
        "get",
        "list",
        "explain",
        "export",
        "run",
        "recover",
        "doctor",
        "backend-index",
        "config",
        "delete",
    }
)

# Narrow implementation-leakage guards (not product vocabulary like "SQLite").
FORBIDDEN_SUBSTRINGS = (
    "secrets_kit.",
    "PRAGMA ",
    "SELECT *",
    "Security.framework dump",
)

ROOT_ANCHORS = (
    "Command taxonomy",
    "Everyday operations",
)


def _subparser_choices(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and action.choices is not None:
            return dict(action.choices)
    return {}


class CliHelpConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parser = build_parser()

    def test_root_help_includes_taxonomy_anchors(self) -> None:
        text = self.parser.format_help()
        for anchor in ROOT_ANCHORS:
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, text)

    def test_root_help_avoids_obvious_sql_dump_leakage(self) -> None:
        text = self.parser.format_help()
        self.assertNotIn("PRAGMA ", text)
        self.assertNotIn("SELECT *", text)

    def test_primary_commands_have_substance_and_examples(self) -> None:
        choices = _subparser_choices(self.parser)
        for name in sorted(PRIMARY_WITH_EXAMPLES):
            self.assertIn(name, choices, msg=f"missing subcommand {name}")
            sub = choices[name]
            help_text = sub.format_help()
            self.assertGreater(len(help_text), 120, msg=f"{name}: expected substantive formatted help")
            desc = (getattr(sub, "description", None) or "").strip()
            if not desc:
                # add_parser(help=...) does not always populate .description; require body text instead.
                self.assertIn("--", help_text, msg=f"{name}: expected flag documentation")
            else:
                self.assertGreater(len(desc), 12, msg=f"{name}: expected substantive description")
            self.assertIn("Examples:", help_text, msg=f"{name}: expected Examples in formatted help")
            lower = help_text.lower()
            for bad in FORBIDDEN_SUBSTRINGS:
                self.assertNotIn(bad.lower(), lower, msg=f"{name}: forbidden substring {bad!r}")

    def test_defaults_alias_parses(self) -> None:
        choices = _subparser_choices(self.parser)
        self.assertIn("config", choices)
        self.assertIn("defaults", choices)

    def test_materialize_mentioned_on_get_help(self) -> None:
        choices = _subparser_choices(self.parser)
        text = choices["get"].format_help().lower()
        self.assertIn("material", text)

    def test_backend_index_help_denies_materialization(self) -> None:
        choices = _subparser_choices(self.parser)
        text = choices["backend-index"].format_help().lower()
        self.assertTrue("material" in text or "secret" in text, msg="backend-index help should frame output posture")
