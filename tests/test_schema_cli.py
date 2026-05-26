"""Schema registry CLI parser and handler smoke tests."""

from __future__ import annotations

import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from secrets_kit.cli.commands.schema import cmd_schema_list, cmd_schema_show
from secrets_kit.cli.parser import build_parser
from secrets_kit.schemas.descriptor import SchemaDescriptor
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


def _sample_schema_registry() -> SchemaRegistryDocument:
    doc = SchemaRegistryDocument.empty()
    doc.schemas["builtin.secret.api_key"] = SchemaDescriptor(
        schema_id="builtin.secret.api_key",
        schema_version=1,
        entry_type="secret",
        entry_kind="api_key",
        fields={"provider": {"type": "string"}},
    )
    return doc


class SchemaParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_parse_list_flags(self) -> None:
        args = self.parser.parse_args(["schema", "list", "--all", "--json"])
        self.assertEqual(args.schema_command, "list")
        self.assertTrue(args.all)
        self.assertTrue(args.json)

    def test_parse_show_schema_id(self) -> None:
        args = self.parser.parse_args(["schema", "show", "builtin.secret.api_key"])
        self.assertEqual(args.schema_id, "builtin.secret.api_key")

    def test_parse_export_options(self) -> None:
        args = self.parser.parse_args(
            ["schema", "export", "-o", "out.json", "--schema-id", "builtin.secret.generic"]
        )
        self.assertEqual(args.output, "out.json")
        self.assertEqual(args.schema_id, "builtin.secret.generic")

    def test_parse_install_paths(self) -> None:
        args = self.parser.parse_args(
            ["schema", "install", "seed.json", "--replace", "-y", "--sqlite-dev-mode"]
        )
        self.assertEqual(args.paths, ["seed.json"])
        self.assertTrue(args.replace)
        self.assertTrue(args.yes)
        self.assertTrue(args.sqlite_dev_mode)

    def test_parse_field_remove(self) -> None:
        args = self.parser.parse_args(
            [
                "schema",
                "field",
                "remove",
                "builtin.secret.api_key",
                "provider",
                "--force",
            ]
        )
        self.assertEqual(args.field_command, "remove")
        self.assertEqual(args.schema_id, "builtin.secret.api_key")
        self.assertEqual(args.field_name, "provider")

    def test_parse_deprecate(self) -> None:
        args = self.parser.parse_args(
            [
                "schema",
                "deprecate",
                "builtin.secret.legacy",
                "--replacement",
                "builtin.secret.api_key",
                "--reason",
                "superseded",
            ]
        )
        self.assertEqual(args.schema_command, "deprecate")
        self.assertEqual(args.replacement, "builtin.secret.api_key")
        self.assertEqual(args.reason, "superseded")

    def test_parse_remove(self) -> None:
        args = self.parser.parse_args(
            ["schema", "remove", "builtin.secret.legacy", "--force", "-y"]
        )
        self.assertEqual(args.schema_command, "remove")
        self.assertTrue(args.force)
        self.assertTrue(args.yes)


@mock.patch("secrets_kit.cli.commands.schema._backend", return_value="keychain")
@mock.patch("secrets_kit.cli.commands.schema.load_schema_registry")
class SchemaCommandTest(unittest.TestCase):
    def test_list_json(self, mock_load: mock.MagicMock, _mock_backend: mock.MagicMock) -> None:
        mock_load.return_value = _sample_schema_registry()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_schema_list(
                args=argparse.Namespace(
                    all=False,
                    json=True,
                    backend=None,
                    sqlite_dev_mode=False,
                )
            )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["schema_id"], "builtin.secret.api_key")

    def test_show_descriptor(self, mock_load: mock.MagicMock, _mock_backend: mock.MagicMock) -> None:
        mock_load.return_value = _sample_schema_registry()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_schema_show(
                args=argparse.Namespace(
                    schema_id="builtin.secret.api_key",
                    json=False,
                    backend=None,
                    sqlite_dev_mode=False,
                )
            )
        self.assertEqual(code, 0)
        self.assertIn("builtin.secret.api_key", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
