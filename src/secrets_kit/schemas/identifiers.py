"""
secrets_kit.schemas.identifiers

Canonical schema identifier helpers.
"""

from __future__ import annotations

from secrets_kit.identifiers import deterministic_identifier


def schema_id_for_name(*, name: str) -> str:
    """Return deterministic canonical schema id for a stable schema name."""
    return deterministic_identifier(
        identifier_type="schema",
        namespace="schema",
        name=name,
    )


__all__ = ["schema_id_for_name"]
