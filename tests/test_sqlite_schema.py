from __future__ import annotations

import sqlite3
import unittest

from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION, bootstrap_schema


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'",
    ).fetchall()
    return {str(row[0]) for row in rows}


def _column_names(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _foreign_keys(conn: sqlite3.Connection, table_name: str) -> set[tuple[str, str, str]]:
    rows = conn.execute(f"PRAGMA foreign_key_list({table_name})").fetchall()
    return {(str(row[3]), str(row[2]), str(row[4])) for row in rows}


class SQLiteSchemaTest(unittest.TestCase):
    def test_bootstrap_creates_erd_named_tables(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            tables = _table_names(conn)

            self.assertIn("business_organizations", tables)
            self.assertIn("business_clients", tables)
            self.assertIn("service_group_nodes", tables)
            self.assertIn("peer_endpoints", tables)
            self.assertNotIn("organization", tables)
            self.assertNotIn("clients", tables)
            self.assertNotIn("peer_node_service_groups", tables)

            self.assertNotIn("peer_node_peer_groups", tables)
        finally:
            conn.close()

    def test_bootstrap_sets_schema_version(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            version = conn.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(version, SCHEMA_VERSION)
        finally:
            conn.close()

    def test_nodes_columns_match_erd_shape(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            columns = _column_names(conn, "nodes")

            self.assertNotIn("public_key", columns)
            self.assertIn("signing_public_key", columns)
            self.assertIn("signing_algorithm", columns)
            self.assertIn("encryption_public_key", columns)
            self.assertIn("encryption_algorithm", columns)
            self.assertIn("service_address", columns)
            self.assertIn("operator_description", columns)
            self.assertIn("last_seen_at", columns)
            self.assertIn("state", columns)
            self.assertIn("created_at", columns)
            self.assertIn("updated_at", columns)
            self.assertIn("operator_comment", columns)
        finally:
            conn.close()

    def test_peer_endpoint_columns_match_lifecycle_shape(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)
            columns = _column_names(conn, "peer_endpoints")
            self.assertEqual(
                columns,
                {
                    "node_id",
                    "endpoint",
                    "state",
                    "created_at",
                    "updated_at",
                    "expires_at",
                    "last_seen_at",
                    "operator_comment",
                },
            )
        finally:
            conn.close()

    def test_transaction_columns_match_erd_shape(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            columns = _column_names(conn, "transactions")
            foreign_keys = _foreign_keys(conn, "transactions")

            self.assertIn("payload", columns)
            self.assertNotIn("payload_json_or_blob", columns)
            self.assertNotIn("payload_encoding", columns)
            self.assertIn("organization_id", columns)
            self.assertIn("client_id", columns)
            self.assertIn("owner_id", columns)
            self.assertIn("previous_transaction_id", columns)
            self.assertIn(
                ("previous_transaction_id", "transactions", "transaction_id"),
                foreign_keys,
            )
        finally:
            conn.close()

    def test_envelope_columns_match_erd_shape(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            columns = _column_names(conn, "envelopes")

            self.assertIn("organization_id", columns)
            self.assertIn("client_id", columns)
            self.assertIn("owner_id", columns)
            self.assertIn("source_node_id", columns)
            self.assertIn("destination_node_id", columns)
            self.assertIn("attempt_count", columns)
            self.assertIn("claimed_at", columns)
            self.assertIn("next_attempt_at", columns)
            self.assertIn("last_error", columns)
            self.assertNotIn("source_peer_group_id", columns)
            self.assertNotIn("destination_peer_group_id", columns)
            self.assertNotIn("rss_route_hint", columns)
        finally:
            conn.close()

    def test_secret_projection_surfaces_are_preserved(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            bootstrap_schema(conn=conn)

            tables = _table_names(conn)
            secret_columns = _column_names(conn, "secrets")

            self.assertIn("secret_tags", tables)
            self.assertIn("secret_tag_assignments", tables)
            self.assertIn("secret_domains", tables)
            self.assertIn("secret_custom_metadata", tables)
            self.assertIn("name", secret_columns)
            self.assertIn("service", secret_columns)
            self.assertIn("account", secret_columns)
            self.assertIn("source", secret_columns)
            self.assertIn("comment", secret_columns)
            self.assertIn("source_url", secret_columns)
            self.assertIn("source_label", secret_columns)
            self.assertIn("rotation_days", secret_columns)
            self.assertIn("rotation_warn_days", secret_columns)
            self.assertIn("last_rotated_at", secret_columns)
            self.assertIn("expires_at", secret_columns)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
