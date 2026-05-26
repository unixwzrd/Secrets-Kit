"""
secrets_kit.backends.sqlite.vocabulary_projections

Project vocabulary.* transactions onto entry_types / entry_kinds / secret_tags tables.

Relational tables are projections only; canonical authority is TaxonomyRegistryDocument.
"""

from __future__ import annotations

import sqlite3

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument


def _required_text(*, payload: dict, field_name: str) -> str:
    value = payload.get(field_name)
    if value is None or str(value).strip() == "":
        raise SQLiteValidationError(f"{field_name} is required")
    return str(value)


def _optional_text(*, payload: dict, field_name: str) -> str:
    value = payload.get(field_name)
    if value is None:
        return ""
    return str(value)


def apply_vocabulary_entry_type_upsert(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """Materialize vocabulary.entry_type.upsert into entry_types."""
    payload = transaction.payload
    row_id = _required_text(payload=payload, field_name="entry_type_id")
    name = _required_text(payload=payload, field_name="name")
    comment = _optional_text(payload=payload, field_name="operator_comment")
    conn.execute(
        """
        INSERT INTO entry_types (entry_type_id, name, operator_comment)
        VALUES (?, ?, ?)
        ON CONFLICT(entry_type_id) DO UPDATE SET
            name = excluded.name,
            operator_comment = CASE
                WHEN excluded.operator_comment != '' THEN excluded.operator_comment
                ELSE entry_types.operator_comment
            END
        """,
        (row_id, name, comment),
    )


def apply_vocabulary_entry_kind_upsert(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """Materialize vocabulary.entry_kind.upsert into entry_kinds."""
    payload = transaction.payload
    row_id = _required_text(payload=payload, field_name="entry_kind_id")
    name = _required_text(payload=payload, field_name="name")
    comment = _optional_text(payload=payload, field_name="operator_comment")
    conn.execute(
        """
        INSERT INTO entry_kinds (entry_kind_id, name, operator_comment)
        VALUES (?, ?, ?)
        ON CONFLICT(entry_kind_id) DO UPDATE SET
            name = excluded.name,
            operator_comment = CASE
                WHEN excluded.operator_comment != '' THEN excluded.operator_comment
                ELSE entry_kinds.operator_comment
            END
        """,
        (row_id, name, comment),
    )


def apply_vocabulary_tag_upsert(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    """Materialize vocabulary.tag.upsert into secret_tags."""
    payload = transaction.payload
    row_id = _required_text(payload=payload, field_name="tag_id")
    name = _required_text(payload=payload, field_name="name")
    comment = _optional_text(payload=payload, field_name="operator_comment")
    conn.execute(
        """
        INSERT INTO secret_tags (tag_id, name, operator_comment)
        VALUES (?, ?, ?)
        ON CONFLICT(tag_id) DO UPDATE SET
            name = excluded.name,
            operator_comment = CASE
                WHEN excluded.operator_comment != '' THEN excluded.operator_comment
                ELSE secret_tags.operator_comment
            END
        """,
        (row_id, name, comment),
    )


def project_registry_vocabulary(*, conn: sqlite3.Connection, document: TaxonomyRegistryDocument) -> None:
    """
    Project all vocabulary rows from the canonical registry document (bootstrap / repair).

    Does not write transactions; use only as a trusted genesis/bootstrap
    exception or explicit repair fallback.
    """
    for entry in document.entry_types:
        conn.execute(
            """
            INSERT OR IGNORE INTO entry_types (entry_type_id, name, operator_comment)
            VALUES (?, ?, ?)
            """,
            (entry.id, entry.name, entry.operator_comment),
        )
    for entry in document.entry_kinds:
        conn.execute(
            """
            INSERT OR IGNORE INTO entry_kinds (entry_kind_id, name, operator_comment)
            VALUES (?, ?, ?)
            """,
            (entry.id, entry.name, entry.operator_comment),
        )
    for entry in document.tags:
        conn.execute(
            """
            INSERT OR IGNORE INTO secret_tags (tag_id, name, operator_comment)
            VALUES (?, ?, ?)
            """,
            (entry.id, entry.name, entry.operator_comment),
        )


def vocabulary_entry_type_payload(*, entry_type_id: str, name: str, operator_comment: str = "") -> dict:
    payload: dict = {"entry_type_id": entry_type_id, "name": name}
    if operator_comment:
        payload["operator_comment"] = operator_comment
    return payload


def vocabulary_entry_kind_payload(*, entry_kind_id: str, name: str, operator_comment: str = "") -> dict:
    payload: dict = {"entry_kind_id": entry_kind_id, "name": name}
    if operator_comment:
        payload["operator_comment"] = operator_comment
    return payload


__all__ = [
    "apply_vocabulary_entry_kind_upsert",
    "apply_vocabulary_entry_type_upsert",
    "apply_vocabulary_tag_upsert",
    "project_registry_vocabulary",
    "vocabulary_entry_kind_payload",
    "vocabulary_entry_type_payload",
]
