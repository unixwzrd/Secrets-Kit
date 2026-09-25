"""
secrets_kit.taxonomy.normalize

Canonical vocabulary name normalization (single UUID per logical name).
"""

from __future__ import annotations

import re

from secrets_kit.models import ValidationError

_CANONICAL_CHARSET = re.compile(r"^[a-z0-9_]+$")
_SEPARATOR_RUN = re.compile(r"[-\s]+")


def canonical_taxonomy_name(*, raw: str) -> str:
    """
    Return the canonical stored name for a vocabulary label.

    Steps: strip, lowercase, hyphen/whitespace to underscore, collapse underscores.
    """
    stripped = raw.strip()
    if not stripped:
        raise ValidationError("taxonomy name cannot be empty")
    lowered = stripped.lower()
    underscored = _SEPARATOR_RUN.sub("_", lowered)
    collapsed = re.sub(r"_+", "_", underscored).strip("_")
    if not collapsed:
        raise ValidationError("taxonomy name cannot be empty after normalization")
    validate_taxonomy_name_charset(name=collapsed)
    return collapsed


def validate_taxonomy_name_charset(*, name: str) -> None:
    """Require lowercase snake_case charset for stored vocabulary names."""
    if not _CANONICAL_CHARSET.match(name):
        raise ValidationError(
            "taxonomy name must use lowercase letters, digits, and underscores only "
            f"(got {name!r})"
        )


def resolve_stored_taxonomy_name(*, raw: str, force_raw: bool = False) -> str:
    """
    Return the name stored in registry / used for UUID hashing.

    When force_raw is True, use the trimmed literal string (discouraged; forks UUIDs).
    """
    stripped = raw.strip()
    if not stripped:
        raise ValidationError("taxonomy name cannot be empty")
    if force_raw:
        return stripped
    return canonical_taxonomy_name(raw=raw)


def normalization_changed(*, raw: str) -> bool:
    """Return True when raw input differs from canonical form."""
    try:
        return raw.strip() != canonical_taxonomy_name(raw=raw)
    except ValidationError:
        return True


__all__ = [
    "canonical_taxonomy_name",
    "normalization_changed",
    "resolve_stored_taxonomy_name",
    "validate_taxonomy_name_charset",
]
