"""Slim registry.json (v2) migration and serialization."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.models import EntryMetadata
from secrets_kit.registry import (
    REGISTRY_FILE_VERSION,
    LEGACY_REGISTRY_FILE_VERSION,
    ensure_registry_storage,
    load_registry,
    registry_path,
    upsert_metadata,
)


class RegistrySlimTest(unittest.TestCase):
    def test_v1_migrates_to_slim_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            rpath = ensure_registry_storage(home=home)
            fat = {
                "version": LEGACY_REGISTRY_FILE_VERSION,
                "entries": [
                    {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "entry_type": "secret",
                        "entry_kind": "api_key",
                        "tags": ["leak-me"],
                        "source": "dotenv:/secret/path/.env",
                        "source_url": "https://evil.example",
                        "comment": "nope",
                        "created_at": "2020-01-01T00:00:00Z",
                        "updated_at": "2020-02-02T00:00:00Z",
                        "schema_version": 1,
                    }
                ],
            }
            rpath.write_text(json.dumps(fat), encoding="utf-8")

            mapping = load_registry(home=home)
            self.assertIn("s::a::K", mapping)
            meta = mapping["s::a::K"]
            self.assertEqual(meta.name, "K")
            self.assertEqual(meta.tags, [])

            text = rpath.read_text(encoding="utf-8")
            self.assertNotIn("tags", text)
            self.assertNotIn("source_url", text)
            self.assertNotIn("leak-me", text)
            self.assertIn('"version": 2', text)

    def test_upsert_writes_only_allowed_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ensure_registry_storage(home=home)
            upsert_metadata(
                home=home,
                metadata=EntryMetadata(
                    name="X",
                    service="sx",
                    account="ax",
                    tags=["t1"],
                    source="manual",
                    entry_kind="api_key",  # type: ignore[arg-type]
                    source_url="https://x",
                ),
            )
            body = json.loads(registry_path(home=home).read_text(encoding="utf-8"))
            self.assertEqual(body["version"], REGISTRY_FILE_VERSION)
            row = body["entries"][0]
            self.assertLessEqual(
                set(row.keys()),
                {"name", "service", "account", "entry_id", "created_at", "updated_at", "sync_origin_host"},
            )
            self.assertGreaterEqual(set(row.keys()), {"name", "service", "account", "entry_id", "created_at", "updated_at"})
            self.assertEqual(row["name"], "X")


if __name__ == "__main__":
    unittest.main()
