"""SQLite metadata schema registry and system-object list filtering."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import (
    SQLITE_PATH_ENV,
    list_active_sqlite_metadata,
    set_sqlite_secret,
)
from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.models import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.registry import registry_path
from secrets_kit.schemas.identifiers import schema_id_for_name
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.registry_store import (
    load_schema_registry,
    merge_seed_files_into_store,
    save_schema_registry,
)
from secrets_kit.system_objects import SystemObjectKind, locator_for_kind

GENERIC_SCHEMA_ID = schema_id_for_name(name="builtin.secret.generic")


class SchemaRegistrySqliteTest(unittest.TestCase):
    def _env_patch(self, db_path: str):
        return mock.patch.dict(
            os.environ,
            {
                SQLITE_PATH_ENV: db_path,
            },
            clear=False,
        )

    def test_merge_seed_populates_registry_in_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path):
                merge_seed_files_into_store(backend="sqlite", allow_replace=False)
                registry = load_schema_registry(backend="sqlite", bootstrap_if_missing=True)
                self.assertIn(GENERIC_SCHEMA_ID, registry.schemas)

    def test_empty_schema_registry_requires_explicit_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path), mock.patch.object(Path, "home", return_value=Path(tmp)):
                save_schema_registry(
                    registry=SchemaRegistryDocument.empty(),
                    backend="sqlite",
                )
                before = registry_path().read_bytes()
                with self.assertRaises(ValidationError):
                    load_schema_registry(backend="sqlite")
                self.assertEqual(registry_path().read_bytes(), before)
                registry = load_schema_registry(backend="sqlite", bootstrap_if_missing=True)
                self.assertIn(GENERIC_SCHEMA_ID, registry.schemas)

    def test_schema_registry_hidden_from_operator_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path):
                conn = provision_sqlite_datastore(path=Path(db_path), storage_mode="encrypted")
                ensure_sqlite_node_identity(conn=conn)
                conn.close()
                merge_seed_files_into_store(backend="sqlite", allow_replace=False)
                meta = EntryMetadata(
                    name="OP_KEY",
                    service="svc",
                    account="acct",
                    entry_type="secret",
                    entry_kind="api_key",
                    schema_id="builtin.secret.api_key",
                    updated_at=now_utc_iso(),
                )
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="OP_KEY",
                    value="secret-value",
                    metadata=meta,
                )
                listed = list_active_sqlite_metadata()
                names = {item.name for item in listed}
                self.assertIn("OP_KEY", names)
                loc = locator_for_kind(kind=SystemObjectKind.SCHEMA_REGISTRY)
                self.assertNotIn(loc.name, names)


if __name__ == "__main__":
    unittest.main()
