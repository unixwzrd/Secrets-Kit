"""
secrets_kit.backends.sqlite.schema

Schema bootstrap for SQLite transaction persistence.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 2


def bootstrap_schema(*, conn: sqlite3.Connection) -> None:
    """
    Create the Phase 2 canonical local datastore schema skeleton.

    Args:
        conn:
            SQLite connection.

    Returns:
        None.

    Raises:
        sqlite3.Error:
            SQLite schema creation failure.

    Side Effects:
        Creates schema tables, append-only triggers, and user_version.
    """
    # Phase 2 creates the canonical schema skeleton only. Projection
    # materialization, replay, envelope lifecycle, sync, and lifecycle
    # automation remain deferred to later explicit application layers.
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS organization (
            organization_id TEXT PRIMARY KEY,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES organization(organization_id),
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS owners (
            owner_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES clients(client_id),
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS service_groups (
            service_group_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL REFERENCES owners(owner_id),
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS peer_groups (
            peer_group_id TEXT PRIMARY KEY,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            peer_group_id TEXT NOT NULL REFERENCES peer_groups(peer_group_id),
            public_key BLOB,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS entry_types (
            entry_type_id TEXT PRIMARY KEY,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS entry_kinds (
            entry_kind_id TEXT PRIMARY KEY,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS secret_tags (
            tag_id TEXT PRIMARY KEY,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id TEXT PRIMARY KEY,
            transaction_version INTEGER NOT NULL,
            payload_version INTEGER NOT NULL,
            protocol_version INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            origin_node_id TEXT NOT NULL,
            origin_owner_id TEXT,
            origin_peer_group_id TEXT,
            origin_organization_id TEXT,
            target_peer_group_id TEXT,
            target_service_group_id TEXT,
            target_owner_id TEXT,
            target_object_id TEXT,
            source_class TEXT NOT NULL DEFAULT 'local',
            replication_policy TEXT,
            -- Phase 1 lineage placeholder. Future phases may split transaction
            -- ordering lineage from object mutation lineage.
            previous_transaction_id TEXT,
            payload_encoding TEXT NOT NULL DEFAULT 'json' CHECK(payload_encoding IN ('json')),
            payload_json_or_blob BLOB NOT NULL,
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
            signature BLOB,
            idempotency_key TEXT,
            state TEXT NOT NULL DEFAULT 'recorded' CHECK(state IN ('recorded')),
            created_at TEXT NOT NULL,
            received_at TEXT,
            applied_at TEXT,
            acknowledged_at TEXT,
            cleared_at TEXT
        );

        CREATE TABLE IF NOT EXISTS secrets (
            secret_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL REFERENCES owners(owner_id),
            service_group_id TEXT NOT NULL REFERENCES service_groups(service_group_id),
            entry_type_id TEXT NOT NULL REFERENCES entry_types(entry_type_id),
            entry_kind_id TEXT NOT NULL REFERENCES entry_kinds(entry_kind_id),
            schema_id TEXT,
            schema_version INTEGER,
            locator_hash BLOB NOT NULL,
            encrypted_name BLOB NOT NULL,
            encrypted_metadata BLOB,
            encrypted_payload BLOB NOT NULL,
            content_hash BLOB NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'deleted', 'superseded')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secret_tag_assignments (
            secret_id TEXT NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
            tag_id TEXT NOT NULL REFERENCES secret_tags(tag_id),
            PRIMARY KEY (secret_id, tag_id)
        );

        -- Reserved delivery-artifact persistence only. Standalone SQLite
        -- operation does not require envelope rows and transaction insertion
        -- never creates them.
        CREATE TABLE IF NOT EXISTS envelopes (
            envelope_id TEXT PRIMARY KEY,
            transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
            source_node_id TEXT REFERENCES nodes(node_id),
            destination_node_id TEXT REFERENCES nodes(node_id),
            source_peer_group_id TEXT REFERENCES peer_groups(peer_group_id),
            destination_peer_group_id TEXT REFERENCES peer_groups(peer_group_id),
            rss_route_hint TEXT,
            encrypted_payload BLOB NOT NULL,
            envelope_hash BLOB NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'recorded',
                'pending',
                'sent',
                'received',
                'acknowledged',
                'failed',
                'purged'
            )),
            sent_at TEXT,
            received_at TEXT,
            acknowledged_at TEXT,
            failed_at TEXT,
            purged_at TEXT
        );

        CREATE TABLE IF NOT EXISTS local_node_state (
            local_node_id TEXT PRIMARY KEY REFERENCES nodes(node_id),
            node_private_key_reference TEXT,
            state TEXT NOT NULL,
            last_transaction_id TEXT REFERENCES transactions(transaction_id),
            last_transaction_state TEXT,
            last_envelope_id TEXT REFERENCES envelopes(envelope_id),
            last_envelope_state TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS transactions_no_update
        BEFORE UPDATE ON transactions
        BEGIN
            SELECT RAISE(ABORT, 'transactions are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS transactions_no_delete
        BEFORE DELETE ON transactions
        BEGIN
            SELECT RAISE(ABORT, 'transactions are append-only');
        END;
        """
    )
    from secrets_kit.backends.sqlite.taxonomy import ensure_taxonomy_seeded

    ensure_taxonomy_seeded(conn=conn)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


__all__ = ["SCHEMA_VERSION", "bootstrap_schema"]
