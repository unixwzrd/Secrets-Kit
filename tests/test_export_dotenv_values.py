"""Focused value-bearing dotenv export and protected-output checks."""

from __future__ import annotations

import argparse
import importlib
import io
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.export import cmd_export
from secrets_kit.exporters import export_dotenv_values


class DotenvValuesExportTest(unittest.TestCase):
    def test_render_quotes_and_newlines_without_literal_newline_in_value(self) -> None:
        self.assertEqual(
            export_dotenv_values(env_map={"TOKEN": 'owner\'s "key"\nnext'}),
            'TOKEN="owner\'s \\"key\\"\\nnext"',
        )

    def test_quoted_values_round_trip_through_python_dotenv_when_available(self) -> None:
        try:
            dotenv_values = importlib.import_module("dotenv").dotenv_values
        except ImportError:
            self.skipTest("python-dotenv is not installed")
        values = {
            "APOSTROPHE": "owner's token",
            "BACKSLASH": r"path\name",
            "EQUALS": "a=b # not a comment",
            "MULTILINE": "first\nsecond",
            "QUOTES": 'say "hello"',
            "TRAILING_BACKSLASH": 'quote " and backslash \\',
            "UNICODE": "café",
        }
        rendered = export_dotenv_values(env_map=values)
        self.assertEqual(dict(dotenv_values(stream=io.StringIO(rendered))), values)

    def test_unrepresentable_values_fail_without_disclosing_them(self) -> None:
        for value in (
            "literal ${OTHER}",
            "control\x01byte",
            "bad\x00byte",
            "\ud800",
            '"starts-quoted\\',
            "has # comment\\",
            "has\nnewline\\",
        ):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "^dotenv_value_unsupported$"):
                    export_dotenv_values(env_map={"TOKEN": value})
        with self.assertRaisesRegex(ValueError, "^dotenv_value_unsupported$"):
            export_dotenv_values(env_map={"BAD\nKEY": "value"})

    def test_cli_requires_protected_new_file_and_never_prints_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / ".env"
            args = argparse.Namespace(format="dotenv-values", out=str(output))
            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                mock.patch(
                    "secrets_kit.cli.commands.export._select_entries", return_value=[object()]
                ),
                mock.patch(
                    "secrets_kit.cli.commands.export._build_env_map",
                    return_value={"TOKEN": "synthetic-value"},
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(cmd_export(args=args), 0)
                self.assertEqual(cmd_export(args=args), 1)
                args.out = None
                self.assertEqual(cmd_export(args=args), 1)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(output.read_text(), 'TOKEN="synthetic-value"\n')
            self.assertNotIn("synthetic-value", stdout.getvalue() + stderr.getvalue())

    def test_cli_rejects_interpolation_before_creating_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / ".env"
            args = argparse.Namespace(format="dotenv-values", out=str(output))
            with (
                mock.patch(
                    "secrets_kit.cli.commands.export._select_entries", return_value=[object()]
                ),
                mock.patch(
                    "secrets_kit.cli.commands.export._build_env_map",
                    return_value={"TOKEN": "${OTHER}"},
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_export(args=args), 1)
            self.assertFalse(output.exists())

    def test_cli_rejects_partial_requested_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / ".env"
            args = argparse.Namespace(
                format="dotenv-values", out=str(output), names="FOUND,MISSING"
            )
            selected = argparse.Namespace(name="FOUND")
            with (
                mock.patch(
                    "secrets_kit.cli.commands.export._select_entries", return_value=[selected]
                ),
                mock.patch("secrets_kit.cli.commands.export._build_env_map") as build_map,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cmd_export(args=args), 1)
                build_map.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
