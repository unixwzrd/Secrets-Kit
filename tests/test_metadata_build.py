"""Tests for CLI metadata construction."""

from __future__ import annotations

import argparse
import unittest
from unittest import mock

from secrets_kit.cli.metadata_build import build_metadata
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


class MetadataBuildKeychainTest(unittest.TestCase):
    def test_build_metadata_passes_keychain_to_registries(self) -> None:
        args = argparse.Namespace(
            name="MY_KEY",
            type="secret",
            kind="generic",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain="/tmp/disposable.keychain-db",
            backend="keychain",
            sqlite_dev_mode=False,
            accept_normalized=True,
            schema_id=None,
        )
        schema_doc = SchemaRegistryDocument.empty()

        with (
            mock.patch("secrets_kit.cli.metadata_build.load_registry", return_value={}),
            mock.patch("secrets_kit.cli.metadata_build.read_metadata", return_value=None),
            mock.patch("secrets_kit.cli.metadata_build._load_defaults", return_value={}),
            mock.patch("secrets_kit.cli.metadata_build.sys.platform", "darwin"),
            mock.patch(
                "secrets_kit.cli.metadata_build.load_schema_registry",
                return_value=schema_doc,
            ) as mock_schema_load,
            mock.patch(
                "secrets_kit.cli.metadata_build.resolve_descriptor",
            ) as mock_resolve,
            mock.patch(
                "secrets_kit.cli.metadata_build.ensure_schema_allowed",
            ) as mock_ensure,
            mock.patch(
                "secrets_kit.cli.metadata_build.sync_vocabulary_on_write",
                return_value=mock.MagicMock(
                    entry_type="secret", entry_kind="generic", tags=[]
                ),
            ) as mock_vocab_sync,
            mock.patch("secrets_kit.cli.metadata_build.merge_entry_metadata") as mock_merge,
        ):
            fake_descriptor = mock.MagicMock(
                schema_id="builtin.secret.generic", schema_version=1
            )
            mock_resolve.return_value = fake_descriptor
            mock_ensure.return_value = fake_descriptor
            fake_meta = mock.MagicMock()
            mock_merge.return_value = fake_meta

            result = build_metadata(args=args, name="MY_KEY", source="manual")

        self.assertIs(result, fake_meta)
        mock_vocab_sync.assert_called_once()
        call = mock_vocab_sync.call_args.kwargs
        self.assertEqual(call["keychain_path"], "/tmp/disposable.keychain-db")
        mock_schema_load.assert_called_once_with(
            backend="keychain",
            keychain_path="/tmp/disposable.keychain-db",
            sqlite_dev_mode=False,
        )


if __name__ == "__main__":
    unittest.main()
