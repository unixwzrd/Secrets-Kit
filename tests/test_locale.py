"""Validate bundled translations without changing machine-facing contracts."""

import argparse
import io
import os
import re
import string
import unittest
from contextlib import redirect_stdout
from unittest import mock

from secrets_kit.cli.parser import build_parser
from secrets_kit.locale import TABLES, active_locale, msg
from secrets_kit.locales.en_US import STRINGS


class LocaleTest(unittest.TestCase):
    def test_service_feedback_translates_without_changing_values(self) -> None:
        from secrets_kit.cli.commands.daemon import cmd_daemon_service_status

        state = {"manager": "systemd", "installed": True, "active": True,
                 "daemon_reachable": True, "definition": "/synthetic/service", "linger": False}
        for language in TABLES:
            output = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"SECKIT_LANGUAGE": language}, clear=True),
                mock.patch("secrets_kit.cli.commands.daemon.service_status", return_value=state),
                redirect_stdout(output),
            ):
                self.assertEqual(cmd_daemon_service_status(args=argparse.Namespace()), 0)
                for key, value in state.items():
                    rendered = str(value).lower() if isinstance(value, bool) else value
                    self.assertIn(msg(f"cli.daemon.service.{key}", value=rendered), output.getvalue())

    def test_selection_and_fallback(self) -> None:
        cases = {
            "fr_CA.UTF-8": "fr",
            "es-MX": "es",
            "de_DE@euro": "de",
            "en_GB": "en_US",
            "C": "en_US",
            "POSIX": "en_US",
            "unknown": "en_US",
        }
        for value, expected in cases.items():
            with (
                self.subTest(value=value),
                mock.patch.dict(os.environ, {"LANG": value}, clear=True),
            ):
                self.assertEqual(active_locale(), expected)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(active_locale(), "en_US")

    def test_precedence(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SECKIT_LANGUAGE": "fr", "LC_ALL": "es", "LC_MESSAGES": "de", "LANG": "en_US"},
            clear=True,
        ):
            self.assertEqual(active_locale(), "fr")
            del os.environ["SECKIT_LANGUAGE"]
            self.assertEqual(active_locale(), "es")
            del os.environ["LC_ALL"]
            self.assertEqual(active_locale(), "de")

    def test_catalog_keys_and_placeholders_match(self) -> None:
        formatter = string.Formatter()

        def fields(template: str) -> list[tuple[str, str, str]]:
            return sorted(
                (name, spec, conversion or "")
                for _, name, spec, conversion in formatter.parse(template)
                if name is not None
            )

        for language, table in TABLES.items():
            self.assertEqual(set(table), set(STRINGS), language)
            for key, english in STRINGS.items():
                self.assertEqual(fields(table[key]), fields(english), (language, key))
                self.assertTrue(table[key].strip(), (language, key))
                technical = r"--[\w-]+|[\w.-]+\.(?:json|sh|db)\b"
                self.assertEqual(
                    set(re.findall(technical, table[key])),
                    set(re.findall(technical, english)),
                    (language, key),
                )
            self.assertEqual(table["prompts.confirm_suffix"], "[y/N]")

    def test_missing_translation_falls_back_but_unknown_key_fails(self) -> None:
        with (
            mock.patch.dict(os.environ, {"SECKIT_LANGUAGE": "fr"}, clear=True),
            mock.patch.dict(TABLES, {"fr": {}}),
        ):
            self.assertEqual(msg("cli.common.aborted"), STRINGS["cli.common.aborted"])
            with self.assertRaises(KeyError):
                msg("nonexistent.key")

    def test_translations_preserve_substitution_values(self) -> None:
        value = "{unchanged} /tmp/example"
        for language in TABLES:
            with mock.patch.dict(os.environ, {"SECKIT_LANGUAGE": language}, clear=True):
                self.assertIn(value, msg("errors.file_not_found", filename=value))

    def test_commands_and_json_option_remain_identical(self) -> None:
        baseline = None
        for language in TABLES:
            with mock.patch.dict(os.environ, {"SECKIT_LANGUAGE": language}, clear=True):
                parser = build_parser()
                choices = next(
                    a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction)
                )
                names = set(choices)
                if baseline is None:
                    baseline = names
                self.assertEqual(names, baseline)
                self.assertTrue(parser.parse_args(["status", "--json"]).status_json)
                self.assertIn(msg("cli.parser.description"), parser.format_help())
                self.assertTrue(parser.format_help().startswith(msg("cli.help.usage")))
                self.assertIn(msg("cli.help.help"), parser.format_help())
                self.assertIn(msg("cli.help.options"), parser.format_help())
