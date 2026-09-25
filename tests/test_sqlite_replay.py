"""
tests.test_sqlite_replay

Unit tests for SQLite replay and projection materialization.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite import (
    SQLiteValidationError,
    Transaction,
    bootstrap_replay_support_rows,
    bootstrap_schema,
    connect_sqlite,
    create_transaction,
    get_transaction,
    insert_transaction,
    rebuild_secret_projections,
)
from secrets_kit.backends.sqlite.local_hierarchy import local_peer_group_id_for_node
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_PLAINTEXT,
    initialize_sqlite_storage_mode,
)
from secrets_kit.backends.sqlite.taxonomy import entry_kind_id_for_name, entry_type_id_for_name
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "org-1")
CLIENT_ID = tid("client", "client-1")
OWNER_ID = tid("owner", "owner-1")
SERVICE_GROUP_ID = tid("service_group", "service-group-1")
PEER_GROUP_ID = tid("peer_group", "peer-group-1")
NODE_ID = tid("node", "node-1")
SECRET_ID = tid("secret", "secret-1")
STALE_SECRET_ID = tid("secret", "stale-secret")
SCHEMA_ID = tid("schema", "builtin.secret")
TXN_SET_1 = tid("transaction", "txn-set-1")
TXN_SET_2 = tid("transaction", "txn-set-2")
TXN_DELETE_1 = tid("transaction", "txn-delete-1")
TXN_SET_BAD = tid("transaction", "txn-set-bad")
TXN_BOOL_SCHEMA_VERSION = tid("transaction", "txn-set-bool-schema-version")
TXN_BAD_TAGS = tid("transaction", "txn-set-bad-tags")
TXN_UNKNOWN = tid("transaction", "txn-unknown")
ENV_ID = tid("envelope", "env-1")


def _b64(value: bytes) -> str:
    """
    Encode bytes for SQLite replay test payloads.

    Args:
        value:
            Bytes to encode.

    Returns:
        ASCII base64 text.

    Side Effects:
        None.
    """
    return base64.b64encode(value).decode("ascii")


class SQLiteReplayTest(unittest.TestCase):
    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        """
        Open a bootstrapped SQLite test connection.

        Args:
            tmpdir:
                Temporary directory path.

        Returns:
            Configured SQLite connection.

        Side Effects:
            Creates a SQLite database and bootstraps schema.
        """
        conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
        bootstrap_schema(conn=conn)
        initialize_sqlite_storage_mode(conn=conn, mode=SQLITE_STORAGE_MODE_PLAINTEXT)
        return conn

    def _insert_projection_parents(self, conn: sqlite3.Connection) -> None:
        """
        Insert parent rows required by the secrets projection FKs.

        Args:
            conn:
                SQLite connection.

        Returns:
            None.

        Side Effects:
            Inserts organization, client, owner, and service-group rows.
        """
        conn.execute(
            "INSERT INTO business_organizations (organization_id, name) VALUES (?, ?)",
            (ORG_ID, "org-1"),
        )
        conn.execute(
            "INSERT INTO business_clients (client_id, organization_id, name) VALUES (?, ?, ?)",
            (CLIENT_ID, ORG_ID, "client-1"),
        )
        conn.execute(
            "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)", (OWNER_ID, CLIENT_ID)
        )
        conn.execute(
            "INSERT INTO service_groups (service_group_id, owner_id) VALUES (?, ?)",
            (SERVICE_GROUP_ID, OWNER_ID),
        )
        conn.execute(
            "INSERT INTO peer_groups (peer_group_id, owner_id) VALUES (?, ?)",
            (PEER_GROUP_ID, OWNER_ID),
        )
        conn.execute(
            "INSERT INTO nodes (node_id, peer_group_id) VALUES (?, ?)",
            (NODE_ID, PEER_GROUP_ID),
        )
        conn.execute(
            "INSERT INTO entry_types (entry_type_id, name) VALUES (?, ?)",
            (entry_type_id_for_name(name="secret"), "secret"),
        )
        conn.execute(
            "INSERT INTO entry_kinds (entry_kind_id, name) VALUES (?, ?)",
            (entry_kind_id_for_name(name="api_key"), "api_key"),
        )

    def _set_payload(self, *, encrypted_payload: bytes = b"payload-1") -> dict[str, object]:
        """
        Build a minimal secret.set payload.

        Args:
            encrypted_payload:
                Placeholder encrypted payload bytes.

        Returns:
            Canonical JSON payload mapping.

        Side Effects:
            None.
        """
        return {
            "secret_id": SECRET_ID,
            "owner_id": OWNER_ID,
            "service_group_id": SERVICE_GROUP_ID,
            "entry_type": "secret",
            "entry_kind": "api_key",
            "schema_id": SCHEMA_ID,
            "schema_version": 1,
            "name": "NAME_1",
            "service": "svc-1",
            "account": "acct-1",
            "source": "unit-test",
            "comment": "projection comment",
            "source_url": "https://example.test/source",
            "source_label": "example",
            "rotation_days": 30,
            "rotation_warn_days": 7,
            "last_rotated_at": "2026-05-24T00:00:00Z",
            "expires_at": "2026-06-24T00:00:00Z",
            "tags": ["prod", "token"],
            "domains": ["example.com", "api.example.com"],
            "custom": {"owner": "ops", "priority": 1},
            "locator_hash_b64": _b64(b"locator-1"),
            "encrypted_name_b64": _b64(b"NAME_1"),
            "encrypted_payload_b64": _b64(encrypted_payload),
            "content_hash_b64": _b64(b"content-1"),
            "projection_created_at": "2026-05-25T00:00:00Z",
            "projection_updated_at": "2026-05-25T00:00:00Z",
        }

    def _delete_payload(self) -> dict[str, object]:
        """
        Build a minimal secret.delete tombstone payload.

        Returns:
            Canonical JSON payload mapping.

        Side Effects:
            None.
        """
        return {
            "secret_id": SECRET_ID,
            "owner_id": OWNER_ID,
            "service_group_id": SERVICE_GROUP_ID,
            "entry_type": "secret",
            "entry_kind": "api_key",
            "schema_id": SCHEMA_ID,
            "schema_version": 1,
            "name": "NAME_1",
            "service": "svc-1",
            "account": "acct-1",
            "source": "unit-test",
            "comment": "projection comment",
            "source_url": "https://example.test/source",
            "source_label": "example",
            "rotation_days": 30,
            "rotation_warn_days": 7,
            "last_rotated_at": "2026-05-24T00:00:00Z",
            "expires_at": "2026-06-24T00:00:00Z",
            "tags": ["prod", "token"],
            "domains": ["example.com", "api.example.com"],
            "custom": {"owner": "ops", "priority": 1},
            "locator_hash_b64": _b64(b"locator-1"),
            "encrypted_name_b64": _b64(b"NAME_1"),
            "content_hash_b64": _b64(b"content-delete"),
            "projection_updated_at": "2026-05-25T00:01:00Z",
        }

    def _insert_transaction(
        self,
        conn: sqlite3.Connection,
        *,
        transaction_id: str,
        transaction_type: str,
        payload: dict[str, object],
        created_at: str = "2026-05-25T00:00:00Z",
    ) -> None:
        """
        Insert a canonical replay test transaction.

        Args:
            conn:
                SQLite connection.
            transaction_id:
                Transaction identifier.
            transaction_type:
                Transaction type.
            payload:
                Transaction payload.
            created_at:
                Creation timestamp.

        Returns:
            None.

        Side Effects:
            Inserts one transaction row.
        """
        insert_transaction(
            conn=conn,
            transaction=create_transaction(
                transaction_id=transaction_id,
                transaction_type=transaction_type,
                origin_node_id=NODE_ID,
                created_at=created_at,
                payload=payload,
            ),
        )

    def _secret_row(self, conn: sqlite3.Connection) -> sqlite3.Row:
        """
        Return the test secret projection row.

        Args:
            conn:
                SQLite connection.

        Returns:
            SQLite row.

        Side Effects:
            Reads one projection row.
        """
        row = conn.execute("SELECT * FROM secrets WHERE secret_id = ?", (SECRET_ID,)).fetchone()
        self.assertIsNotNone(row)
        return row

    def _copied_transactions(
        self, conn: sqlite3.Connection, transaction_ids: list[str]
    ) -> list[Transaction]:
        """
        Return test transactions in copy order.

        Args:
            conn:
                SQLite connection.
            transaction_ids:
                Ordered transaction identifiers.

        Returns:
            Transaction objects from the source history.

        Side Effects:
            Reads transaction rows.
        """
        return [
            get_transaction(conn=conn, transaction_id=transaction_id)
            for transaction_id in transaction_ids
        ]

    def _assert_relational_metadata(self, conn: sqlite3.Connection, row: sqlite3.Row) -> None:
        self.assertEqual(row["name"], "NAME_1")
        self.assertEqual(row["service"], "svc-1")
        self.assertEqual(row["account"], "acct-1")
        self.assertEqual(row["source"], "unit-test")
        self.assertEqual(row["comment"], "projection comment")
        self.assertEqual(row["source_url"], "https://example.test/source")
        self.assertEqual(row["source_label"], "example")
        self.assertEqual(row["rotation_days"], 30)
        self.assertEqual(row["rotation_warn_days"], 7)
        self.assertEqual(row["last_rotated_at"], "2026-05-24T00:00:00Z")
        self.assertEqual(row["expires_at"], "2026-06-24T00:00:00Z")
        domains = [
            item["domain"]
            for item in conn.execute(
                "SELECT domain FROM secret_domains WHERE secret_id = ? ORDER BY domain",
                (SECRET_ID,),
            ).fetchall()
        ]
        self.assertEqual(domains, ["api.example.com", "example.com"])
        custom = {
            item["metadata_key"]: json.loads(item["metadata_value"])
            for item in conn.execute(
                """
                SELECT metadata_key, metadata_value
                FROM secret_custom_metadata
                WHERE secret_id = ?
                ORDER BY metadata_key
                """,
                (SECRET_ID,),
            ).fetchall()
        }
        self.assertEqual(custom, {"owner": "ops", "priority": 1})
        tags = [
            item["name"]
            for item in conn.execute(
                """
                SELECT st.name
                FROM secret_tag_assignments sta
                JOIN secret_tags st ON st.tag_id = sta.tag_id
                WHERE sta.secret_id = ?
                ORDER BY st.name
                """,
                (SECRET_ID,),
            ).fetchall()
        ]
        self.assertEqual(tags, ["prod", "token"])

    def test_secret_set_materializes_active_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["locator_hash"], b"locator-1")
                self.assertEqual(row["encrypted_name"], b"NAME_1")
                self.assertEqual(row["encrypted_payload"], b"payload-1")
                self.assertEqual(row["content_hash"], b"content-1")
                self._assert_relational_metadata(conn, row)
            finally:
                conn.close()

    def test_copied_transaction_history_replays_without_missing_support_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            target_dir = Path(tmpdir) / "target"
            source_dir.mkdir()
            target_dir.mkdir()
            source = self._connect(str(source_dir))
            target = self._connect(str(target_dir))
            try:
                self._insert_projection_parents(source)
                self._insert_transaction(
                    source,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )
                transactions = self._copied_transactions(source, [TXN_SET_1])

                bootstrap_replay_support_rows(conn=target, transactions=transactions)
                for transaction in transactions:
                    insert_transaction(conn=target, transaction=transaction)
                rebuild_secret_projections(conn=target)

                row = self._secret_row(target)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["owner_id"], OWNER_ID)
                self.assertEqual(row["service_group_id"], SERVICE_GROUP_ID)
                node_row = target.execute(
                    "SELECT peer_group_id FROM nodes WHERE node_id = ?",
                    (NODE_ID,),
                ).fetchone()
                self.assertEqual(
                    node_row["peer_group_id"],
                    local_peer_group_id_for_node(node_id=NODE_ID),
                )
                self._assert_relational_metadata(target, row)
            finally:
                source.close()
                target.close()

    def test_copied_set_delete_history_reconstructs_child_projections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            target_dir = Path(tmpdir) / "target"
            source_dir.mkdir()
            target_dir.mkdir()
            source = self._connect(str(source_dir))
            target = self._connect(str(target_dir))
            try:
                self._insert_projection_parents(source)
                self._insert_transaction(
                    source,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                    created_at="2026-05-25T00:00:00Z",
                )
                self._insert_transaction(
                    source,
                    transaction_id=TXN_DELETE_1,
                    transaction_type="secret.delete",
                    payload=self._delete_payload(),
                    created_at="2026-05-25T00:01:00Z",
                )
                transactions = self._copied_transactions(source, [TXN_SET_1, TXN_DELETE_1])

                bootstrap_replay_support_rows(conn=target, transactions=transactions)
                for transaction in transactions:
                    insert_transaction(conn=target, transaction=transaction)
                rebuild_secret_projections(conn=target)

                row = self._secret_row(target)
                self.assertEqual(row["state"], "deleted")
                self.assertEqual(row["updated_at"], "2026-05-25T00:01:00Z")
                self._assert_relational_metadata(target, row)
            finally:
                source.close()
                target.close()

    def test_newer_secret_set_replaces_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(encrypted_payload=b"payload-1"),
                    created_at="2026-05-25T00:00:00Z",
                )
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_2,
                    transaction_type="secret.set",
                    payload={
                        **self._set_payload(encrypted_payload=b"payload-2"),
                        "content_hash_b64": _b64(b"content-2"),
                        "projection_created_at": "2026-05-25T00:02:00Z",
                        "projection_updated_at": "2026-05-25T00:02:00Z",
                    },
                    created_at="2026-05-25T00:02:00Z",
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["encrypted_payload"], b"payload-2")
                self.assertEqual(row["content_hash"], b"content-2")
                self.assertEqual(row["created_at"], "2026-05-25T00:00:00Z")
                self.assertEqual(row["updated_at"], "2026-05-25T00:02:00Z")
                self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 1)
            finally:
                conn.close()

    def test_secret_delete_materializes_deleted_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                    created_at="2026-05-25T00:00:00Z",
                )
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_DELETE_1,
                    transaction_type="secret.delete",
                    payload=self._delete_payload(),
                    created_at="2026-05-25T00:01:00Z",
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "deleted")
                self.assertEqual(row["encrypted_payload"], b"")
                self.assertEqual(row["content_hash"], b"content-delete")
                self.assertEqual(row["updated_at"], "2026-05-25T00:01:00Z")
                self._assert_relational_metadata(conn, row)
            finally:
                conn.close()

    def test_secret_delete_does_not_require_plaintext_or_previous_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                delete_payload = self._delete_payload()
                self.assertNotIn("value", delete_payload)
                self.assertNotIn("encrypted_payload_b64", delete_payload)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_DELETE_1,
                    transaction_type="secret.delete",
                    payload=delete_payload,
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "deleted")
                self.assertEqual(row["encrypted_payload"], b"")
                self._assert_relational_metadata(conn, row)
            finally:
                conn.close()

    def test_invalid_base64_fails_before_projection_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_BAD,
                    transaction_type="secret.set",
                    payload={**self._set_payload(), "encrypted_payload_b64": "***not-base64***"},
                )

                with self.assertRaisesRegex(SQLiteValidationError, "encrypted_payload_b64"):
                    rebuild_secret_projections(conn=conn)

                self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)
            finally:
                conn.close()

    def test_rebuild_rolls_back_when_replay_fails_partway(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                conn.execute(
                    """
                    INSERT INTO secrets (
                        secret_id,
                        owner_id,
                        service_group_id,
                        entry_type_id,
                        entry_kind_id,
                        name,
                        service,
                        account,
                        source,
                        comment,
                        source_url,
                        source_label,
                        last_rotated_at,
                        expires_at,
                        locator_hash,
                        encrypted_name,
                        encrypted_payload,
                        content_hash,
                        state,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        STALE_SECRET_ID,
                        OWNER_ID,
                        SERVICE_GROUP_ID,
                        entry_type_id_for_name(name="secret"),
                        entry_kind_id_for_name(name="api_key"),
                        "STALE_KEY",
                        "svc-stale",
                        "acct-stale",
                        "manual",
                        "",
                        "",
                        "",
                        "",
                        "",
                        b"stale-locator",
                        b"stale-name",
                        b"stale-payload",
                        b"stale-content",
                        "active",
                        "2026-05-25T00:00:00Z",
                        "2026-05-25T00:00:00Z",
                    ),
                )
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_BAD,
                    transaction_type="secret.set",
                    payload={**self._set_payload(), "encrypted_payload_b64": "***not-base64***"},
                )

                with self.assertRaisesRegex(SQLiteValidationError, "encrypted_payload_b64"):
                    rebuild_secret_projections(conn=conn)

                rows = conn.execute("SELECT secret_id FROM secrets ORDER BY secret_id").fetchall()
                self.assertEqual([row["secret_id"] for row in rows], [STALE_SECRET_ID])
            finally:
                conn.close()

    def test_boolean_schema_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_BOOL_SCHEMA_VERSION,
                    transaction_type="secret.set",
                    payload={**self._set_payload(), "schema_version": True},
                )

                with self.assertRaisesRegex(SQLiteValidationError, "schema_version"):
                    rebuild_secret_projections(conn=conn)

                self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)
            finally:
                conn.close()

    def test_malformed_tags_are_rejected(self) -> None:
        invalid_values = (
            "prod",
            [1],
            [True],
            [""],
            ["prod", {}],
        )
        for value in invalid_values:
            with self.subTest(tags=value), tempfile.TemporaryDirectory() as tmpdir:
                conn = self._connect(tmpdir)
                try:
                    self._insert_projection_parents(conn)
                    self._insert_transaction(
                        conn,
                        transaction_id=TXN_BAD_TAGS,
                        transaction_type="secret.set",
                        payload={**self._set_payload(), "tags": value},
                    )

                    with self.assertRaisesRegex(SQLiteValidationError, "tags"):
                        rebuild_secret_projections(conn=conn)

                    self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)
                finally:
                    conn.close()

    def test_unsupported_transaction_type_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_UNKNOWN,
                    transaction_type="secret.rename",
                    payload=self._set_payload(),
                )

                with self.assertRaisesRegex(
                    SQLiteValidationError, "unsupported replay transaction type"
                ):
                    rebuild_secret_projections(conn=conn)
            finally:
                conn.close()

    def test_rebuild_clears_stale_projection_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                conn.execute(
                    """
                    INSERT INTO secrets (
                        secret_id,
                        owner_id,
                        service_group_id,
                        entry_type_id,
                        entry_kind_id,
                        name,
                        service,
                        account,
                        source,
                        comment,
                        source_url,
                        source_label,
                        last_rotated_at,
                        expires_at,
                        locator_hash,
                        encrypted_name,
                        encrypted_payload,
                        content_hash,
                        state,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        STALE_SECRET_ID,
                        OWNER_ID,
                        SERVICE_GROUP_ID,
                        entry_type_id_for_name(name="secret"),
                        entry_kind_id_for_name(name="api_key"),
                        "STALE_KEY",
                        "svc-stale",
                        "acct-stale",
                        "manual",
                        "",
                        "",
                        "",
                        "",
                        "",
                        b"stale-locator",
                        b"stale-name",
                        b"stale-payload",
                        b"stale-content",
                        "active",
                        "2026-05-25T00:00:00Z",
                        "2026-05-25T00:00:00Z",
                    ),
                )
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)

                self.assertIsNone(
                    conn.execute(
                        "SELECT * FROM secrets WHERE secret_id = ?", (STALE_SECRET_ID,)
                    ).fetchone()
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT * FROM secrets WHERE secret_id = ?", (SECRET_ID,)
                    ).fetchone()
                )
            finally:
                conn.close()

    def test_rebuild_is_idempotent_with_same_local_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)
                first_rows = [
                    tuple(row)
                    for row in conn.execute("SELECT * FROM secrets ORDER BY secret_id").fetchall()
                ]
                rebuild_secret_projections(conn=conn)
                second_rows = [
                    tuple(row)
                    for row in conn.execute("SELECT * FROM secrets ORDER BY secret_id").fetchall()
                ]

                self.assertEqual(first_rows, second_rows)
            finally:
                conn.close()

    def test_envelopes_do_not_affect_replay_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id=TXN_SET_1,
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )
                conn.execute(
                    """
                    INSERT INTO envelopes (
                        envelope_id,
                        transaction_id,
                        encrypted_payload,
                        envelope_hash,
                        state
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (ENV_ID, TXN_SET_1, b"envelope-payload", b"envelope-hash", "pending"),
                )

                rebuild_secret_projections(conn=conn)
                row = self._secret_row(conn)

                self.assertEqual(row["encrypted_payload"], b"payload-1")
                self.assertEqual(conn.execute("SELECT count(*) FROM envelopes").fetchone()[0], 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
