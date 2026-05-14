"""Tests for package version resolution (metadata vs checkout fallback)."""

from __future__ import annotations

import unittest
from unittest import mock

import secrets_kit
from secrets_kit.cli.support.version_info import _cli_version
from secrets_kit.version_meta import UNKNOWN_VERSION, package_version_string


class PackageVersionTest(unittest.TestCase):
    def test___version___matches_cli_helper(self) -> None:
        self.assertEqual(secrets_kit.__version__, _cli_version())

    def test_package_version_string_uses_metadata_when_present(self) -> None:
        with mock.patch("importlib.metadata.version", return_value="9.8.7"):
            self.assertEqual(package_version_string(), "9.8.7")

    def test_package_version_string_unknown_when_not_installed(self) -> None:
        import importlib.metadata

        def _raise(_: str) -> str:
            raise importlib.metadata.PackageNotFoundError

        with mock.patch("importlib.metadata.version", side_effect=_raise):
            self.assertEqual(package_version_string(), UNKNOWN_VERSION)
