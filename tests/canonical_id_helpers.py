from __future__ import annotations

from secrets_kit.identifiers import IdentifierType, deterministic_identifier


def tid(identifier_type: IdentifierType, name: str) -> str:
    return deterministic_identifier(
        identifier_type=identifier_type,
        namespace="tests",
        name=name,
    )
