"""Host identity is an opt-in local scope, never peer or billing authority."""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import (
    bootstrap_replay_support_rows,
    bootstrap_schema,
    connect_sqlite,
    get_transaction,
    insert_transaction,
    rebuild_secret_projections,
)
from secrets_kit.backends.sqlite.secrets_api import set_sqlite_secret
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    initialize_sqlite_storage_mode,
)
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.host_context import (
    HOST_MEMBERSHIP_KEY,
    HostContext,
    host_context_path,
    join_host_context,
    load_host_context,
    local_host_scope,
)
from secrets_kit.identifiers import random_identifier
from secrets_kit.models import EntryMetadata


def _context(*, environment: str = "dev") -> HostContext:
    return HostContext(
        installation_id="b48b3aca-23a7-431f-8b9f-c01017b70354",
        environment=environment,
        organization_id=random_identifier(identifier_type="organization"),
        organization_name="Example Company",
        client_id=random_identifier(identifier_type="client"),
        client_name="Example Unit",
    )


class HostContextTest(unittest.TestCase):
    def test_two_user_stores_share_business_scope_but_not_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = _context()
            identities: list[tuple[str, str, str]] = []
            for name in ("first", "second"):
                home = Path(tmp) / name
                args = argparse.Namespace(yes=True, home=str(home), init_target=None, backend="sqlite")
                with redirect_stdout(StringIO()):
                    self.assertEqual(cmd_init_operator(args=args), 0)
                with mock.patch("secrets_kit.host_context.load_host_context", return_value=context):
                    membership = join_host_context(prefix=Path(tmp) / "shared", environment="dev", home=home)
                database = home / ".config/seckit/seckit.sqlite"
                with sqlite3.connect(database) as conn:
                    conn.row_factory = sqlite3.Row
                    node_id = conn.execute("SELECT node_id FROM node_private").fetchone()[0]
                    scope = local_host_scope(conn=conn)
                self.assertEqual(scope[:2], (context.organization_id, context.client_id))
                identities.append((str(node_id), str(membership["principal_owner_id"]), str(database)))
            self.assertEqual(len({item[0] for item in identities}), 2)
            self.assertEqual(len({item[1] for item in identities}), 2)
            self.assertEqual(len({item[2] for item in identities}), 2)

    def test_host_config_rejects_unprivileged_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / "shared"
            path = host_context_path(prefix)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(_context().as_dict()), encoding="utf-8")
            with self.assertRaises(PermissionError):
                load_host_context(prefix)

    def test_join_requires_existing_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            with mock.patch("secrets_kit.host_context.load_host_context", return_value=_context()):
                with self.assertRaisesRegex(ValueError, "initialize"):
                    join_host_context(prefix=Path(tmp) / "shared", environment="dev", home=home)

    def test_join_rejects_wrong_environment_without_changing_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            args = argparse.Namespace(yes=True, home=str(home), init_target=None, backend="sqlite")
            with redirect_stdout(StringIO()):
                self.assertEqual(cmd_init_operator(args=args), 0)
            database = home / ".config/seckit/seckit.sqlite"
            with sqlite3.connect(database) as conn:
                before = conn.execute("SELECT count(*) FROM datastore_metadata").fetchone()[0]
            with mock.patch("secrets_kit.host_context.load_host_context", return_value=_context(environment="qa")):
                with self.assertRaisesRegex(ValueError, "environment"):
                    join_host_context(prefix=Path(tmp) / "shared", environment="dev", home=home)
            with sqlite3.connect(database) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM datastore_metadata").fetchone()[0], before)

    def test_join_is_idempotent_and_preserves_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            args = argparse.Namespace(yes=True, home=str(home), init_target=None, backend="sqlite")
            with redirect_stdout(StringIO()):
                self.assertEqual(cmd_init_operator(args=args), 0)
            database = home / ".config" / "seckit" / "seckit.sqlite"
            with sqlite3.connect(database) as conn:
                node_before = conn.execute("SELECT node_id FROM node_private").fetchone()[0]
                transaction_count_before = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
            context = _context()
            with mock.patch("secrets_kit.host_context.load_host_context", return_value=context):
                membership = join_host_context(prefix=Path(tmp) / "shared", environment="dev", home=home)
                self.assertEqual(join_host_context(prefix=Path(tmp) / "shared", environment="dev", home=home), membership)
            with sqlite3.connect(database) as conn:
                conn.row_factory = sqlite3.Row
                self.assertEqual(
                    local_host_scope(conn=conn),
                    (context.organization_id, context.client_id, membership["principal_owner_id"]),
                )
                self.assertEqual(conn.execute("SELECT node_id FROM node_private").fetchone()[0], node_before)
                self.assertEqual(conn.execute("SELECT count(*) FROM transactions").fetchone()[0], transaction_count_before)
                self.assertEqual(conn.execute("SELECT count(*) FROM datastore_metadata WHERE metadata_key=?", (HOST_MEMBERSHIP_KEY,)).fetchone()[0], 1)
            self.assertEqual(membership["client_id"], context.client_id)
            self.assertTrue(membership["principal_owner_id"].startswith("own:"))

            with mock.patch("pathlib.Path.home", return_value=home):
                set_sqlite_secret(
                    service="test", account="example", name="synthetic",
                    value="not-a-real-secret",
                    metadata=EntryMetadata(name="synthetic", service="test", account="example", source="test"),
                )
            with sqlite3.connect(database) as conn:
                row = conn.execute(
                    "SELECT organization_id, client_id, owner_id FROM transactions WHERE transaction_type='secret.set'"
                ).fetchone()
                self.assertEqual(row, (context.organization_id, context.client_id, membership["principal_owner_id"]))
                transaction_ids = [item[0] for item in conn.execute("SELECT transaction_id FROM transactions")]
            source = connect_sqlite(path=database)
            try:
                history = [get_transaction(conn=source, transaction_id=identifier) for identifier in transaction_ids]
            finally:
                source.close()
            replay = connect_sqlite(path=Path(tmp) / "replay.sqlite")
            try:
                bootstrap_schema(conn=replay)
                initialize_sqlite_storage_mode(conn=replay, mode=SQLITE_STORAGE_MODE_ENCRYPTED)
                bootstrap_replay_support_rows(conn=replay, transactions=history)
                for item in history:
                    insert_transaction(conn=replay, transaction=item)
                with mock.patch("pathlib.Path.home", return_value=home):
                    rebuild_secret_projections(conn=replay)
                self.assertEqual(replay.execute("SELECT count(*) FROM secrets").fetchone()[0], 1)
            finally:
                replay.close()


if __name__ == "__main__":
    unittest.main()
