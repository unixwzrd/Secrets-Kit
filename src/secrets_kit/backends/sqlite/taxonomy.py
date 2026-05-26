"""
secrets_kit.backends.sqlite.taxonomy

SQLite projection helpers for vocabulary FK resolution (replay fallback only).

Canonical vocabulary authority is TaxonomyRegistryDocument + vocabulary.* transactions.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable, List, Tuple

from secrets_kit.models import EntryMetadata
from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name
from secrets_kit.taxonomy.uuid import (
    entry_kind_id_for_name,
    entry_type_id_for_name,
    tag_id_for_name,
)

# Re-export for tests and legacy imports
normalize_taxonomy_name = resolve_stored_taxonomy_name


def ensure_entry_type_id(*, conn: sqlite3.Connection, name: str, force_raw: bool = False) -> str:
    """Replay/import fallback: ensure entry_types row exists."""
    display = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    row_id = entry_type_id_for_name(name=display, force_raw=force_raw)
    conn.execute(
        """
        INSERT OR IGNORE INTO entry_types (entry_type_id, name, operator_comment)
        VALUES (?, ?, ?)
        """,
        (row_id, display, ""),
    )
    return row_id


def ensure_entry_kind_id(*, conn: sqlite3.Connection, name: str, force_raw: bool = False) -> str:
    """Replay/import fallback: ensure entry_kinds row exists."""
    display = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    row_id = entry_kind_id_for_name(name=display, force_raw=force_raw)
    conn.execute(
        """
        INSERT OR IGNORE INTO entry_kinds (entry_kind_id, name, operator_comment)
        VALUES (?, ?, ?)
        """,
        (row_id, display, ""),
    )
    return row_id


def ensure_tag_id(*, conn: sqlite3.Connection, name: str, force_raw: bool = False) -> str:
    """Replay/import fallback: ensure secret_tags row exists."""
    display = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    row_id = tag_id_for_name(name=display, force_raw=force_raw)
    conn.execute(
        """
        INSERT OR IGNORE INTO secret_tags (tag_id, name, operator_comment)
        VALUES (?, ?, ?)
        """,
        (row_id, display, ""),
    )
    return row_id


def ensure_taxonomy_seeded(*, conn: sqlite3.Connection) -> None:
    """
    Project bundled taxonomy seeds into vocabulary tables.

    Trusted genesis/bootstrap exception only; normal vocabulary authority should
    flow through recorded vocabulary transactions or explicit repair tooling.
    """
    from secrets_kit.backends.sqlite.vocabulary_projections import project_registry_vocabulary
    from secrets_kit.taxonomy.seed import load_bundled_taxonomy_seeds

    project_registry_vocabulary(conn=conn, document=load_bundled_taxonomy_seeds())


def resolve_entry_type_and_kind_ids(
    *,
    conn: sqlite3.Connection,
    entry_type: str,
    entry_kind: str,
    force_raw: bool = False,
) -> Tuple[str, str]:
    """Resolve type/kind names to UUIDs; ensure_* is bootstrap/repair fallback only."""
    type_id = entry_type_id_for_name(name=entry_type, force_raw=force_raw)
    kind_id = entry_kind_id_for_name(name=entry_kind, force_raw=force_raw)
    type_row = conn.execute(
        "SELECT 1 FROM entry_types WHERE entry_type_id = ?", (type_id,)
    ).fetchone()
    kind_row = conn.execute(
        "SELECT 1 FROM entry_kinds WHERE entry_kind_id = ?", (kind_id,)
    ).fetchone()
    if type_row is None:
        type_id = ensure_entry_type_id(conn=conn, name=entry_type, force_raw=force_raw)
    if kind_row is None:
        kind_id = ensure_entry_kind_id(conn=conn, name=entry_kind, force_raw=force_raw)
    return type_id, kind_id


def sync_secret_tags(
    *,
    conn: sqlite3.Connection,
    secret_id: str,
    tags: Iterable[str],
    force_raw: bool = False,
) -> None:
    """Replace tag assignments for one secret from a tag name list."""
    conn.execute("DELETE FROM secret_tag_assignments WHERE secret_id = ?", (secret_id,))
    seen: set[str] = set()
    for raw in tags:
        display = resolve_stored_taxonomy_name(raw=str(raw), force_raw=force_raw)
        key = display.lower()
        if key in seen:
            continue
        seen.add(key)
        tag_id = ensure_tag_id(conn=conn, name=display, force_raw=force_raw)
        conn.execute(
            """
            INSERT OR IGNORE INTO secret_tag_assignments (secret_id, tag_id)
            VALUES (?, ?)
            """,
            (secret_id, tag_id),
        )


def tags_from_payload(*, payload: dict) -> List[str]:
    """Extract tag list from a canonical secret.set payload."""
    raw = payload.get("tags", [])
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if str(item).strip()]


def sync_tags_from_metadata(
    *,
    conn: sqlite3.Connection,
    secret_id: str,
    metadata: EntryMetadata,
) -> None:
    """Sync tag assignments from EntryMetadata (CLI / direct API paths)."""
    sync_secret_tags(conn=conn, secret_id=secret_id, tags=metadata.tags)


__all__ = [
    "ensure_entry_kind_id",
    "ensure_entry_type_id",
    "ensure_tag_id",
    "ensure_taxonomy_seeded",
    "entry_kind_id_for_name",
    "entry_type_id_for_name",
    "normalize_taxonomy_name",
    "resolve_entry_type_and_kind_ids",
    "sync_secret_tags",
    "sync_tags_from_metadata",
    "tag_id_for_name",
    "tags_from_payload",
]
