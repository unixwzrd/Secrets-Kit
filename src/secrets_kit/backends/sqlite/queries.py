"""
secrets_kit.backends.sqlite.queries

Canonical SQLite ``secrets`` column lists and composed ``SELECT`` strings.

**No business logic** — column order here must match how ``sqlite/backend.py`` maps
:class:`sqlite3.Row` columns (named access) and tuple slices derived from full rows.
"""

from __future__ import annotations

_SECRETS_TABLE = "secrets"

# Decrypt-free index iterator (``iter_index`` / ``_row_to_index_safe``).
SECRETS_COLUMNS_INDEX_SAFE: tuple[str, ...] = (
    "entry_id",
    "locator_hash",
    "locator_hint",
    "updated_at",
    "deleted",
    "deleted_at",
    "generation",
    "tombstone_generation",
    "backend_version",
    "corrupt",
    "corrupt_reason",
    "last_validation_at",
)

# Same as ``SECRETS_COLUMNS_INDEX_SAFE`` plus locator + ciphertext payload columns (rebuild / decrypt paths).
SECRETS_COLUMNS_DECRYPT_PREFIX: tuple[str, ...] = (
    "entry_id",
    "locator_hash",
    "locator_hint",
    "service",
    "account",
    "name",
    "updated_at",
    "deleted",
    "deleted_at",
    "generation",
    "tombstone_generation",
    "backend_version",
    "corrupt",
    "corrupt_reason",
    "last_validation_at",
)

SECRETS_COLUMNS_CRYPTO_TAIL: tuple[str, ...] = ("ciphertext", "nonce", "crypto_version")

SECRETS_COLUMNS_LINEAGE: tuple[str, ...] = (
    "entry_id",
    "service",
    "account",
    "name",
    "generation",
    "tombstone_generation",
    "deleted",
)

SECRETS_COLUMNS_RECONCILE_INDEX: tuple[str, ...] = (
    "entry_id",
    "service",
    "account",
    "name",
    "updated_at",
    "origin_host",
    "deleted",
    "deleted_at",
    "generation",
    "tombstone_generation",
    "content_hash",
    "corrupt",
    "corrupt_reason",
)

SECRETS_COLUMNS_FULL_ROW: tuple[str, ...] = SECRETS_COLUMNS_DECRYPT_PREFIX + SECRETS_COLUMNS_CRYPTO_TAIL


def _comma_join(columns: tuple[str, ...]) -> str:
    return ", ".join(columns)


def sql_select_iter_index() -> str:
    return f"""
                SELECT {_comma_join(SECRETS_COLUMNS_INDEX_SAFE)}
                FROM {_SECRETS_TABLE} ORDER BY entry_id
                """


def sql_select_rebuild_index() -> str:
    return f"""
                SELECT {_comma_join(SECRETS_COLUMNS_FULL_ROW)}
                FROM {_SECRETS_TABLE}
                """


def sql_select_lineage_by_entry_id() -> str:
    return f"""
                    SELECT {_comma_join(SECRETS_COLUMNS_LINEAGE)}
                    FROM {_SECRETS_TABLE} WHERE entry_id = ?
                    """


def sql_select_lineage_by_locator() -> str:
    return f"""
                    SELECT {_comma_join(SECRETS_COLUMNS_LINEAGE)}
                    FROM {_SECRETS_TABLE} WHERE service = ? AND account = ? AND name = ?
                    """


def sql_select_reconcile_index_by_entry_id() -> str:
    return f"""
                SELECT {_comma_join(SECRETS_COLUMNS_RECONCILE_INDEX)}
                FROM {_SECRETS_TABLE} WHERE entry_id = ?
                """


def sql_select_tombstone_deleted_by_entry_id() -> str:
    return "SELECT tombstone_generation, deleted FROM secrets WHERE entry_id = ?"


def sql_select_full_row_by_locator() -> str:
    return f"""
            SELECT {_comma_join(SECRETS_COLUMNS_FULL_ROW)}
            FROM {_SECRETS_TABLE} WHERE service = ? AND account = ? AND name = ?
            """


def sql_select_full_row_by_entry_id() -> str:
    return f"""
                SELECT {_comma_join(SECRETS_COLUMNS_FULL_ROW)}
                FROM {_SECRETS_TABLE} WHERE entry_id = ?
                """


def sql_select_deleted_by_locator() -> str:
    return "SELECT deleted FROM secrets WHERE service = ? AND account = ? AND name = ?"


def sql_select_iter_unlocked_active() -> str:
    return f"""
                SELECT {_comma_join(SECRETS_COLUMNS_FULL_ROW)}
                FROM {_SECRETS_TABLE} WHERE deleted = 0
                """
