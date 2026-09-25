"""
secrets_kit.backends.sqlite.schema

SQLite schema bootstrap for the local datastore backend.
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 3


def bootstrap_schema(*, conn: sqlite3.Connection) -> None:
    """
    Create the SQLite schema if it does not already exist.

    Raises:
        sqlite3.Error:
            If schema creation fails.
    """
    conn.executescript(
        f"""
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS datastore_metadata (
            metadata_key TEXT PRIMARY KEY,
            metadata_value TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS business_organizations (
            organization_id TEXT PRIMARY KEY,
            name TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS business_clients (
            client_id TEXT PRIMARY KEY,
            organization_id TEXT REFERENCES business_organizations(organization_id),
            name TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS owners (
            owner_id TEXT PRIMARY KEY,
            client_id TEXT REFERENCES business_clients(client_id),
            name TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS peer_groups (
            peer_group_id TEXT PRIMARY KEY,
            owner_id TEXT REFERENCES owners(owner_id),
            name TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            peer_group_id TEXT REFERENCES peer_groups(peer_group_id),
            signing_public_key BLOB CHECK(length(signing_public_key) = 32),
            signing_algorithm TEXT CHECK(signing_algorithm = 'ed25519'),
            encryption_public_key BLOB CHECK(length(encryption_public_key) = 32),
            encryption_algorithm TEXT CHECK(encryption_algorithm = 'x25519'),
            authorization_mode TEXT NOT NULL DEFAULT 'none' CHECK(
                authorization_mode IN ('none', 'allow_list', 'all')
            ),
            service_address TEXT,
            operator_description TEXT,
            last_seen_at TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS peer_endpoints (
            node_id TEXT NOT NULL REFERENCES nodes(node_id),
            endpoint TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'expired', 'removed')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            last_seen_at TEXT,
            operator_comment TEXT,
            PRIMARY KEY (node_id, endpoint)
        );

        CREATE TABLE IF NOT EXISTS node_private (
            node_id TEXT PRIMARY KEY REFERENCES nodes(node_id),
            signing_private_key_reference TEXT,
            encryption_private_key_reference TEXT,
            created_at TEXT,
            updated_at TEXT,
            CHECK(
                signing_private_key_reference IS NULL
                OR length(signing_private_key_reference) > 0
            ),
            CHECK(
                encryption_private_key_reference IS NULL
                OR length(encryption_private_key_reference) > 0
            )
        );

        CREATE TABLE IF NOT EXISTS service_groups (
            service_group_id TEXT PRIMARY KEY,
            peer_group_id TEXT REFERENCES peer_groups(peer_group_id),
            owner_id TEXT REFERENCES owners(owner_id),
            name TEXT,
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS service_group_nodes (
            service_group_id TEXT REFERENCES service_groups(service_group_id),
            node_id TEXT REFERENCES nodes(node_id),
            state TEXT,
            created_at TEXT,
            updated_at TEXT,
            PRIMARY KEY (service_group_id, node_id)
        );

        CREATE TABLE IF NOT EXISTS entry_types (
            entry_type_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS entry_kinds (
            entry_kind_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            operator_comment TEXT
        );

        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id TEXT PRIMARY KEY,
            transaction_version INTEGER NOT NULL,
            payload_version INTEGER NOT NULL,
            protocol_version INTEGER NOT NULL,
            organization_id TEXT REFERENCES business_organizations(organization_id),
            client_id TEXT REFERENCES business_clients(client_id),
            owner_id TEXT REFERENCES owners(owner_id),
            origin_node_id TEXT REFERENCES nodes(node_id),
            transaction_type TEXT NOT NULL,
            previous_transaction_id TEXT REFERENCES transactions(transaction_id),
            payload BLOB NOT NULL,
            payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
            signature BLOB,
            state TEXT NOT NULL CHECK(state IN ('pending', 'applied', 'replayed', 'failed')),
            created_at TEXT NOT NULL,
            received_at TEXT,
            applied_at TEXT,
            acknowledged_at TEXT,
            cleared_at TEXT
        );

        CREATE TABLE IF NOT EXISTS secrets (
            secret_id TEXT PRIMARY KEY,
            owner_id TEXT REFERENCES owners(owner_id),
            service_group_id TEXT REFERENCES service_groups(service_group_id),
            entry_type_id TEXT REFERENCES entry_types(entry_type_id),
            entry_kind_id TEXT REFERENCES entry_kinds(entry_kind_id),
            name TEXT NOT NULL,
            service TEXT NOT NULL,
            account TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            comment TEXT NOT NULL DEFAULT '',
            source_url TEXT NOT NULL DEFAULT '',
            source_label TEXT NOT NULL DEFAULT '',
            rotation_days INTEGER,
            rotation_warn_days INTEGER,
            last_rotated_at TEXT NOT NULL DEFAULT '',
            expires_at TEXT NOT NULL DEFAULT '',
            schema_id TEXT,
            schema_version INTEGER,
            locator_hash BLOB NOT NULL UNIQUE,
            encrypted_name BLOB NOT NULL,
            encrypted_payload BLOB NOT NULL,
            content_hash BLOB,
            state TEXT NOT NULL CHECK(state IN ('active', 'deleted')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secret_tags (
            tag_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secret_tag_assignments (
            secret_id TEXT NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
            tag_id TEXT NOT NULL REFERENCES secret_tags(tag_id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (secret_id, tag_id)
        );

        CREATE TABLE IF NOT EXISTS secret_domains (
            secret_id TEXT NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
            domain TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (secret_id, domain)
        );

        CREATE TABLE IF NOT EXISTS secret_custom_metadata (
            secret_id TEXT NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
            metadata_key TEXT NOT NULL,
            metadata_value TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (secret_id, metadata_key)
        );

        CREATE TABLE IF NOT EXISTS envelopes (
            envelope_id TEXT PRIMARY KEY,
            transaction_id TEXT NOT NULL REFERENCES transactions(transaction_id),
            organization_id TEXT REFERENCES business_organizations(organization_id),
            client_id TEXT REFERENCES business_clients(client_id),
            owner_id TEXT REFERENCES owners(owner_id),
            source_node_id TEXT REFERENCES nodes(node_id),
            destination_node_id TEXT REFERENCES nodes(node_id),
            state TEXT NOT NULL CHECK(
                state IN (
                    'pending',
                    'claimed',
                    'sending',
                    'sent',
                    'received',
                    'acknowledged',
                    'failed',
                    'retry_pending',
                    'authorization_denied',
                    'purged'
                )
            ),
            encrypted_payload BLOB NOT NULL,
            envelope_hash BLOB NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            claimed_at TEXT,
            sent_at TEXT,
            received_at TEXT,
            acknowledged_at TEXT,
            failed_at TEXT,
            next_attempt_at TEXT,
            last_error TEXT,
            purged_at TEXT
        );

        PRAGMA user_version = {SCHEMA_VERSION};
        """
    )

    conn.commit()


__all__ = ["SCHEMA_VERSION", "bootstrap_schema"]
