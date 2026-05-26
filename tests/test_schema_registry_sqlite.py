"""SQLite metadata schema registry and system-object list filtering."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from secrets_kit.backends.sqlite import (
    SQLITE_PATH_ENV,
    list_active_sqlite_metadata,
    set_sqlite_secret,
)
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.registry_store import (
    load_schema_registry,
    merge_seed_files_into_store,
    save_schema_registry,
)
from secrets_kit.system_objects import SystemObjectKind, locator_for_kind


class SchemaRegistrySqliteTest(unittest.TestCase):
    def _env_patch(self, db_path: str):
        return mock.patch.dict(
            os.environ,
            {
                SQLITE_PATH_ENV: db_path,
                "SECKIT_SQLITE_DEVELOPER_MODE": "1",
            },
            clear=False,
        )

    def test_merge_seed_populates_registry_in_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path):
                merge_seed_files_into_store(
                    backend="sqlite", allow_replace=False, sqlite_dev_mode=True
                )
                registry = load_schema_registry(backend="sqlite", sqlite_dev_mode=True)
                self.assertIn("builtin.secret.generic", registry.schemas)

    def test_empty_schema_registry_rebootstraps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path):
                save_schema_registry(
                    registry=SchemaRegistryDocument.empty(),
                    backend="sqlite",
                    sqlite_dev_mode=True,
                )
                registry = load_schema_registry(backend="sqlite", sqlite_dev_mode=True)
                self.assertIn("builtin.secret.generic", registry.schemas)

    def test_schema_registry_hidden_from_operator_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "seckit.sqlite")
            with self._env_patch(db_path):
                merge_seed_files_into_store(
                    backend="sqlite", allow_replace=False, sqlite_dev_mode=True
                )
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
                    sqlite_dev_mode=True,
                )
                listed = list_active_sqlite_metadata(sqlite_dev_mode=True)
                names = {item.name for item in listed}
                self.assertIn("OP_KEY", names)
                loc = locator_for_kind(kind=SystemObjectKind.SCHEMA_REGISTRY)
                self.assertNotIn(loc.name, names)


if __name__ == "__main__":
    unittest.main()
