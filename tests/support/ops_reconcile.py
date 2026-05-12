"""Mechanical helpers for reconciliation tests: projections, import wrapper."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore
else:  # pragma: no cover - reconciliation tests skip without nacl
    SqliteSecretStore = None  # type: ignore[misc, assignment]


def _store_cls():
    if SqliteSecretStore is None:
        raise RuntimeError("ops_reconcile requires PyNaCl (SQLite backend)")
    return SqliteSecretStore


def lineage_projection(
    db_path: str | Path,
    *,
    kek_keychain_path: Optional[str] = None,
) -> List[Tuple[object, ...]]:
    """Return ordered lineage-shaped rows from ``secrets`` (SQLite store).

    Tuple shape: ``entry_id, service, account, name, generation,
    tombstone_generation, deleted`` ordered by ``entry_id``.
    """
    st_cls = _store_cls()
    st = st_cls(db_path=str(db_path), kek_keychain_path=kek_keychain_path)
    conn = st._conn()
    try:
        cur = conn.execute(
            """
            SELECT entry_id, service, account, name, generation, tombstone_generation, deleted
            FROM secrets ORDER BY entry_id
            """
        )
        return [tuple(row) for row in cur.fetchall()]
    finally:
        conn.close()


def assert_lineage_projection_equal(
    a: List[Tuple[object, ...]],
    b: List[Tuple[object, ...]],
    *,
    ignore_entry_id: bool = False,
) -> None:
    """Raise ``AssertionError`` if lineage projections differ."""
    if ignore_entry_id:
        a_norm = sorted([tuple(t[1:]) for t in a])
        b_norm = sorted([tuple(t[1:]) for t in b])
        if a_norm != b_norm:
            raise AssertionError(f"lineage projection mismatch (ignore entry_id): {a_norm!r} != {b_norm!r}")
    elif a != b:
        raise AssertionError(f"lineage projection mismatch: {a!r} != {b!r}")


def run_import_sequence(
    *,
    inner_entries: List[Dict[str, object]],
    local_host_id: str,
    dry_run: bool,
    path: str,
    backend: str,
    kek_keychain_path: Optional[str] = None,
    home: Optional[Path] = None,
    domain_filter: Optional[List[str]] = None,
    trace_out: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Call :func:`apply_peer_sync_import` and return ``(stats, trace)``.

    If ``trace_out`` is ``None``, trace events are collected in a new list.
    Otherwise events are appended to ``trace_out`` and the same list is returned.
    """
    buf = trace_out if trace_out is not None else []
    stats = apply_peer_sync_import(
        inner_entries=inner_entries,
        local_host_id=local_host_id,
        dry_run=dry_run,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
        domain_filter=domain_filter,
        home=home,
        trace_out=buf,
    )
    return stats, buf
