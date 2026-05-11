"""Lineage snapshot for reconciliation (SQLite index + Phase 6A merge)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LineageSnapshot:
    """Decrypt-free lineage fields for one ``secrets`` row (SQLite)."""

    entry_id: str
    service: str
    account: str
    name: str
    generation: int
    tombstone_generation: int
    deleted: bool
