from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.models import EntryMetadata
from secrets_kit.registry.storage import (
    REGISTRY_SCHEMA,
    REGISTRY_VERSION,
    RegistryError,
    delete_metadata,
    ensure_registry_storage,
    load_catalog,
    registry_backup_path,
    registry_path,
    save_catalog,
    upsert_metadata,
)
from secrets_kit.schemas.identifiers import schema_id_for_name

GENERIC_SCHEMA_ID = schema_id_for_name(name="builtin.secret.generic")

FORBIDDEN_INVENTORY_KEYS = {
    "account",
    "comment",
    "created_at",
    "custom",
    "domains",
    "entry_id",
    "name",
    "service",
    "source",
    "sync_origin_host",
    "tags",
    "updated_at",
}


def _payload(*, home: Path) -> dict:
    return json.loads(registry_path(home=home).read_text(encoding="utf-8"))


class RegistryStorageTest(unittest.TestCase):
    def test_new_registry_file_is_catalog_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ensure_registry_storage(home=home)
            payload = _payload(home=home)

        self.assertEqual(payload["version"], REGISTRY_VERSION)
        self.assertEqual(payload["$schema"], REGISTRY_SCHEMA)
        self.assertIn("schemas", payload)
        self.assertIn(GENERIC_SCHEMA_ID, payload["schemas"])
        self.assertNotIn("entries", payload)

    def test_load_catalog_returns_schema_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            catalog = load_catalog(home=home)

        self.assertIn(GENERIC_SCHEMA_ID, catalog.schemas)
        self.assertFalse(catalog.deprecated)

    def test_save_catalog_persists_catalog_only_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            catalog = load_catalog(home=home)
            save_catalog(document=catalog, home=home)
            payload = _payload(home=home)

        self.assertIn("schemas", payload)
        self.assertNotIn("entries", payload)
        self.assertFalse(FORBIDDEN_INVENTORY_KEYS & set(payload))

    def test_old_inventory_registry_is_backed_up_and_rewritten_catalog_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ensure_registry_storage(home=home)
            old_payload = {
                "version": 2,
                "entries": [
                    {
                        "name": "API_TOKEN",
                        "service": "svc",
                        "account": "acct",
                        "entry_id": "22222222-2222-4222-8222-222222222222",
                        "created_at": "2026-03-02T18:20:00Z",
                        "updated_at": "2026-03-02T19:05:00Z",
                        "sync_origin_host": "host-a",
                    }
                ],
            }
            registry_path(home=home).write_text(json.dumps(old_payload), encoding="utf-8")

            catalog = load_catalog(home=home)
            rewritten = _payload(home=home)
            backup = registry_backup_path(home=home)

            self.assertIn(GENERIC_SCHEMA_ID, catalog.schemas)
            self.assertTrue(backup.exists())
            self.assertEqual(json.loads(backup.read_text(encoding="utf-8")), old_payload)
            self.assertIn("schemas", rewritten)
            self.assertNotIn("entries", rewritten)
            self.assertNotIn("API_TOKEN", json.dumps(rewritten))
            self.assertNotIn("22222222-2222-4222-8222-222222222222", json.dumps(rewritten))
            self.assertNotIn("host-a", json.dumps(rewritten))

    def test_inventory_mutation_apis_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            meta = EntryMetadata(name="API_TOKEN", service="svc", account="acct")

            with self.assertRaisesRegex(RegistryError, "catalog only"):
                upsert_metadata(metadata=meta, home=home)
            with self.assertRaisesRegex(RegistryError, "no metadata inventory"):
                delete_metadata(service="svc", account="acct", name="API_TOKEN", home=home)


if __name__ == "__main__":
    unittest.main()
