"""Phase 3 Pydantic mirror schemas: parity with authoritative emitters."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from secrets_kit.backends.base import BackendCapabilities, BackendSecurityPosture, IndexRow
from secrets_kit.identity.core import init_identity, load_identity
from secrets_kit.models.core import EntryMetadata
from secrets_kit.registry.core import registry_path
from secrets_kit.schemas.backend import BackendCapabilitiesDict, BackendSecurityPostureDict
from secrets_kit.schemas.identity_public import IdentityPublicExportDict
from secrets_kit.schemas.index import IndexRowDiagDict, IndexRowSafeDict
from secrets_kit.schemas.metadata import (
    EntryMetadataCanonicalDict,
    assert_metadata_canonical_dict,
    parse_full_registry_metadata_with_schema_check,
    validate_slim_registry_entry,
)
from secrets_kit.schemas.sync_bundle import InspectBundleSummaryDict
from secrets_kit.sync.bundle import build_bundle, inspect_bundle, parse_bundle_file

try:
    import nacl  # noqa: F401
except ImportError:  # pragma: no cover
    nacl = None  # type: ignore[assignment]


class SchemaMirrorTest(unittest.TestCase):
    def test_entry_metadata_canonical_roundtrip(self) -> None:
        meta = EntryMetadata(name="K", service="s", account="a", tags=["t1"])
        assert_metadata_canonical_dict(meta)
        raw = meta.to_dict()
        reparsed = EntryMetadata.from_dict(raw)
        self.assertEqual(reparsed.name, meta.name)

    def test_entry_metadata_legacy_type_kind_keys(self) -> None:
        payload = {
            "name": "X",
            "service": "s",
            "account": "a",
            "type": "secret",
            "kind": "token",
            "tags": [],
            "comment": "",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "source": "manual",
            "schema_version": 1,
            "source_url": "",
            "source_label": "",
            "rotation_days": None,
            "rotation_warn_days": None,
            "last_rotated_at": "",
            "expires_at": "",
            "domains": [],
            "custom": {},
            "entry_id": "",
        }
        meta = EntryMetadata.from_dict(payload)
        EntryMetadataCanonicalDict.model_validate(meta.to_dict())

    def test_index_row_safe_and_diag(self) -> None:
        row = IndexRow(
            entry_id="e1",
            locator_hash="h",
            locator_hint="hint",
            updated_at="2026-01-01T00:00:00Z",
            deleted=False,
            deleted_at="",
            generation=1,
            tombstone_generation=0,
            index_schema_version=1,
            payload_schema_version=1,
            backend_impl_version=1,
            payload_ref="pk1",
            corrupt=False,
            corrupt_reason="",
            last_validation_at="",
        )
        IndexRowSafeDict.model_validate(row.to_safe_dict())
        IndexRowDiagDict.model_validate(row.to_diag_dict())

    def test_backend_posture_capabilities_asdict(self) -> None:
        posture = BackendSecurityPosture(
            metadata_encrypted=True,
            safe_index_supported=True,
            requires_unlock_for_metadata=False,
            supports_secure_delete=True,
        )
        caps = BackendCapabilities(
            supports_safe_index=True,
            supports_unlock_enumeration=True,
            supports_atomic_rename=True,
            supports_tombstones=True,
            supports_backend_migrate=False,
            supports_transactional_set=True,
            supports_selective_resolve=True,
            set_atomicity="atomic",
        )
        BackendSecurityPostureDict.model_validate(asdict(posture))
        BackendCapabilitiesDict.model_validate(asdict(caps))

    def test_slim_registry_entry_validate(self) -> None:
        row = {
            "name": "N",
            "service": "s",
            "account": "a",
            "entry_id": "e",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
        }
        validate_slim_registry_entry(row)

    def test_parse_full_registry_with_schema_check(self) -> None:
        payload = {
            "name": "N",
            "service": "s",
            "account": "a",
            "tags": [],
            "comment": "",
            "entry_type": "secret",
            "entry_kind": "generic",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "source": "manual",
            "schema_version": 1,
            "source_url": "",
            "source_label": "",
            "last_rotated_at": "",
            "expires_at": "",
            "domains": [],
            "custom": {},
            "entry_id": "",
        }
        meta = parse_full_registry_metadata_with_schema_check(payload)
        self.assertEqual(meta.name, "N")

    @unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
    def test_inspect_bundle_summary_shape(self) -> None:
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        ha = base / "a"
        hb = base / "b"
        ha.mkdir()
        hb.mkdir()
        try:
            init_identity(home=ha)
            init_identity(home=hb)
            id_a = load_identity(home=ha)
            id_b = load_identity(home=hb)
            fp_b = id_b.signing_fingerprint_hex()
            entries = [
                {
                    "metadata": {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "created_at": "2026-01-01T00:00:00Z",
                        "domains": [],
                        "tags": [],
                        "updated_at": "2026-01-02T00:00:00Z",
                    },
                    "origin_host": id_a.host_id,
                    "value": "x",
                }
            ]
            bundle = build_bundle(
                identity=id_a,
                recipient_records=[(fp_b, id_b.box_public)],
                entries=entries,
            )
            payload = parse_bundle_file(json.dumps(bundle))
            summary = inspect_bundle(payload=payload)
            InspectBundleSummaryDict.model_validate(summary)
        finally:
            td.cleanup()

    def test_identity_public_export(self) -> None:
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        h = base / "h"
        h.mkdir()
        try:
            init_identity(home=h)
            ident = load_identity(home=h)
            pub = ident.export_public_payload()
            IdentityPublicExportDict.model_validate(pub)
        finally:
            td.cleanup()


class RegistrySchemaEnvTest(unittest.TestCase):
    def test_load_registry_with_validate_patch_v2(self) -> None:
        td = tempfile.TemporaryDirectory()
        home = Path(td.name)
        try:
            reg_dir = home / ".config" / "seckit"
            reg_dir.mkdir(parents=True)
            os.chmod(reg_dir, 0o700)
            body = {
                "version": 2,
                "$schema": "https://unixwzrd.ai/schemas/seckit/registry-slim-v2.json",
                "entries": [
                    {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "entry_id": "550e8400-e29b-41d4-a716-446655440000",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-02T00:00:00Z",
                    }
                ],
            }
            rpath = registry_path(home=home)
            rpath.write_text(json.dumps(body), encoding="utf-8")
            os.chmod(rpath, 0o600)
            from secrets_kit.registry import core as reg_core

            with mock.patch.object(reg_core, "_VALIDATE_REGISTRY_METADATA", True):
                entries = reg_core.load_registry(home=home)
            self.assertIn("s::a::K", entries)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
