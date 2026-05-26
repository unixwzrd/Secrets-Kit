"""Taxonomy CLI: parser flags, list filters, and command handlers."""

from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.taxonomy import (
    _list_sections_from_args,
    cmd_taxonomy_export,
    cmd_taxonomy_install,
    cmd_taxonomy_list,
    cmd_taxonomy_show,
    taxonomy_list_rows,
)
from secrets_kit.cli.parser import build_parser
from secrets_kit.taxonomy.registry_doc import TaxonomyEntry, TaxonomyRegistryDocument


def _sample_registry() -> TaxonomyRegistryDocument:
    return TaxonomyRegistryDocument(
        entry_types=[
            TaxonomyEntry(id="t1", name="secret", builtin=True, operator_comment="policy bucket"),
            TaxonomyEntry(id="t2", name="pii", builtin=True, operator_comment=""),
        ],
        entry_kinds=[
            TaxonomyEntry(id="k1", name="api_key", builtin=True, operator_comment="API credentials"),
            TaxonomyEntry(id="k2", name="password", builtin=True, operator_comment=""),
        ],
        tags=[TaxonomyEntry(id="g1", name="prod", builtin=False, operator_comment="production")],
    )


def _list_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "types": False,
        "kinds": False,
        "tags": False,
        "json": False,
        "backend": None,
        "sqlite_dev_mode": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class TaxonomyListRowsTest(unittest.TestCase):
    def test_list_rows_include_comments_and_ids(self) -> None:
        rows = taxonomy_list_rows(registry=_sample_registry())
        self.assertEqual(len(rows), 5)
        by_name = {str(row["name"]): row for row in rows}
        self.assertEqual(by_name["secret"]["operator_comment"], "policy bucket")
        self.assertEqual(by_name["api_key"]["id"], "k1")

    def test_list_rows_all_sections_when_defaults(self) -> None:
        rows = taxonomy_list_rows(registry=_sample_registry())
        lists = {str(row["list"]) for row in rows}
        self.assertEqual(lists, {"entry_kind", "entry_type", "tag"})

    def test_list_rows_types_only(self) -> None:
        rows = taxonomy_list_rows(
            registry=_sample_registry(),
            include_types=True,
            include_kinds=False,
            include_tags=False,
        )
        self.assertEqual([str(row["name"]) for row in rows], ["pii", "secret"])

    def test_list_rows_kinds_only(self) -> None:
        rows = taxonomy_list_rows(
            registry=_sample_registry(),
            include_types=False,
            include_kinds=True,
            include_tags=False,
        )
        self.assertEqual([str(row["list"]) for row in rows], ["entry_kind", "entry_kind"])
        self.assertEqual([str(row["name"]) for row in rows], ["api_key", "password"])

    def test_list_rows_tags_only(self) -> None:
        rows = taxonomy_list_rows(
            registry=_sample_registry(),
            include_types=False,
            include_kinds=False,
            include_tags=True,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["list"], "tag")
        self.assertEqual(rows[0]["name"], "prod")

    def test_list_rows_types_and_tags_union(self) -> None:
        rows = taxonomy_list_rows(
            registry=_sample_registry(),
            include_types=True,
            include_kinds=False,
            include_tags=True,
        )
        lists = {str(row["list"]) for row in rows}
        self.assertEqual(lists, {"entry_type", "tag"})
        self.assertEqual(len(rows), 3)


class TaxonomyListSectionsFromArgsTest(unittest.TestCase):
    def test_default_includes_all_sections(self) -> None:
        args = argparse.Namespace(types=False, kinds=False, tags=False)
        self.assertEqual(_list_sections_from_args(args=args), (True, True, True))

    def test_types_only_flag(self) -> None:
        args = argparse.Namespace(types=True, kinds=False, tags=False)
        self.assertEqual(_list_sections_from_args(args=args), (True, False, False))

    def test_kinds_only_flag(self) -> None:
        args = argparse.Namespace(types=False, kinds=True, tags=False)
        self.assertEqual(_list_sections_from_args(args=args), (False, True, False))

    def test_tags_only_flag(self) -> None:
        args = argparse.Namespace(types=False, kinds=False, tags=True)
        self.assertEqual(_list_sections_from_args(args=args), (False, False, True))

    def test_combined_flags(self) -> None:
        args = argparse.Namespace(types=True, kinds=True, tags=False)
        self.assertEqual(_list_sections_from_args(args=args), (True, True, False))


class TaxonomyParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_parse_list_no_filters(self) -> None:
        args = self.parser.parse_args(["taxonomy", "list"])
        self.assertEqual(args.command, "taxonomy")
        self.assertEqual(args.taxonomy_command, "list")
        self.assertFalse(args.types)
        self.assertFalse(args.kinds)
        self.assertFalse(args.tags)
        self.assertFalse(args.json)

    def test_parse_list_types_kinds_json(self) -> None:
        args = self.parser.parse_args(["taxonomy", "list", "--types", "--kinds", "--json"])
        self.assertTrue(args.types)
        self.assertTrue(args.kinds)
        self.assertFalse(args.tags)
        self.assertTrue(args.json)

    def test_parse_list_tags_and_sqlite_dev_mode(self) -> None:
        args = self.parser.parse_args(["taxonomy", "list", "--tags", "--sqlite-dev-mode"])
        self.assertTrue(args.tags)
        self.assertTrue(args.sqlite_dev_mode)

    def test_parse_show_entry_kind(self) -> None:
        args = self.parser.parse_args(["taxonomy", "show", "entry_kind", "api_key"])
        self.assertEqual(args.list_name, "entry_kind")
        self.assertEqual(args.name, "api_key")

    def test_parse_export_output_path(self) -> None:
        args = self.parser.parse_args(["taxonomy", "export", "-o", "/tmp/taxonomy.json"])
        self.assertEqual(args.output, "/tmp/taxonomy.json")

    def test_parse_install_paths_and_normalization_flags(self) -> None:
        args = self.parser.parse_args(
            [
                "taxonomy",
                "install",
                "a.json",
                "b.json",
                "--accept-normalized",
                "--force-raw-name",
            ]
        )
        self.assertEqual(args.paths, ["a.json", "b.json"])
        self.assertTrue(args.accept_normalized)
        self.assertTrue(args.force_raw_name)


class _TaxonomyCommandTestCase(unittest.TestCase):
    """Patch backend resolution so command tests stay hermetic."""

    _load_target: str = ""
    _merge_target: str = ""

    def setUp(self) -> None:
        self._backend_patch = mock.patch(
            "secrets_kit.cli.commands.taxonomy._backend",
            return_value="keychain",
        )
        self._backend_patch.start()
        if self._load_target:
            self._load_patch = mock.patch(self._load_target)
            self.mock_load = self._load_patch.start()
            self.mock_load.return_value = _sample_registry()
        if self._merge_target:
            self._merge_patch = mock.patch(self._merge_target)
            self.mock_merge = self._merge_patch.start()
            self.mock_merge.return_value = _sample_registry()

    def tearDown(self) -> None:
        if self._load_target:
            self._load_patch.stop()
        if self._merge_target:
            self._merge_patch.stop()
        self._backend_patch.stop()


class TaxonomyListCommandTest(_TaxonomyCommandTestCase):
    _load_target = "secrets_kit.cli.commands.taxonomy.load_taxonomy_registry"

    def test_list_json_includes_all_fields(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(json=True))
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload), 5)
        api_key = next(row for row in payload if row["name"] == "api_key")
        self.assertEqual(api_key["list"], "entry_kind")
        self.assertEqual(api_key["operator_comment"], "API credentials")
        self.assertIn("id", api_key)
        self.assertIn("builtin", api_key)

    def test_list_table_includes_comment_column(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(kinds=True))
        self.assertEqual(code, 0)
        text = stdout.getvalue()
        self.assertIn("comment", text)
        self.assertIn("API credentials", text)
        self.assertNotIn("entry_type", text)

    def test_list_types_only_via_command(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(types=True))
        self.assertEqual(code, 0)
        self.assertIn("secret", stdout.getvalue())
        self.assertNotIn("api_key", stdout.getvalue())

    def test_list_tags_only_via_command(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(tags=True))
        self.assertEqual(code, 0)
        self.assertIn("prod", stdout.getvalue())
        self.assertNotIn("password", stdout.getvalue())

    def test_list_types_and_tags_via_command(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(types=True, tags=True))
        self.assertEqual(code, 0)
        text = stdout.getvalue()
        self.assertIn("secret", text)
        self.assertIn("prod", text)
        self.assertNotIn("api_key", text)

    def test_list_empty_filter_message(self) -> None:
        self.mock_load.return_value = TaxonomyRegistryDocument(
            entry_types=[], entry_kinds=[], tags=[]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_list(args=_list_args(types=True))
        self.assertEqual(code, 0)
        self.assertIn("no vocabulary entries", stdout.getvalue())


class TaxonomyShowCommandTest(_TaxonomyCommandTestCase):
    _load_target = "secrets_kit.cli.commands.taxonomy.load_taxonomy_registry"

    def test_show_entry_kind(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_show(
                args=argparse.Namespace(
                    list_name="entry_kind",
                    name="api_key",
                    backend=None,
                    sqlite_dev_mode=False,
                )
            )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["name"], "api_key")
        self.assertEqual(payload["operator_comment"], "API credentials")

    def test_show_missing_entry_returns_error(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cmd_taxonomy_show(
                args=argparse.Namespace(
                    list_name="entry_kind",
                    name="missing_kind",
                    backend=None,
                    sqlite_dev_mode=False,
                )
            )
        self.assertEqual(code, 1)
        self.assertIn("not found", stderr.getvalue())


class TaxonomyExportCommandTest(_TaxonomyCommandTestCase):
    _load_target = "secrets_kit.cli.commands.taxonomy.load_taxonomy_registry"

    def test_export_stdout(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_export(
                args=argparse.Namespace(output=None, backend=None, sqlite_dev_mode=False)
            )
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIn("entry_kinds", payload)

    def test_export_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "taxonomy.json"
            code = cmd_taxonomy_export(
                args=argparse.Namespace(
                    output=str(out_path), backend=None, sqlite_dev_mode=False
                )
            )
            self.assertEqual(code, 0)
            text = out_path.read_text(encoding="utf-8")
            self.assertIn("entry_types", text)


class TaxonomyInstallCommandTest(_TaxonomyCommandTestCase):
    _merge_target = "secrets_kit.cli.commands.taxonomy.merge_seed_files_into_taxonomy_store"

    def test_install_reports_path_count(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_taxonomy_install(
                args=argparse.Namespace(
                    paths=["one.json", "two.json"],
                    backend=None,
                    sqlite_dev_mode=False,
                )
            )
        self.assertEqual(code, 0)
        self.assertIn("2 file", stdout.getvalue())
        self.mock_merge.assert_called_once()
        call_kwargs = self.mock_merge.call_args.kwargs
        self.assertEqual(len(call_kwargs["paths"]), 2)


if __name__ == "__main__":
    unittest.main()
