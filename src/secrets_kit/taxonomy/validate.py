"""
secrets_kit.taxonomy.validate

Write-policy helpers for taxonomy vocabulary.
"""

from __future__ import annotations

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument


def require_known_entry_type(
    *,
    registry: TaxonomyRegistryDocument,
    name: str,
    policy_mode: bool = False,
) -> None:
    """Fail in policy mode when entry_type is not registered."""
    if not policy_mode:
        return
    if registry.find_entry_type(name=name) is None:
        raise ValidationError(
            f"unknown entry_type {name!r}; install via seckit taxonomy install or use developer mode"
        )


def require_known_entry_kind(
    *,
    registry: TaxonomyRegistryDocument,
    name: str,
    policy_mode: bool = False,
) -> None:
    """Fail in policy mode when entry_kind is not registered."""
    if not policy_mode:
        return
    if registry.find_entry_kind(name=name) is None:
        raise ValidationError(
            f"unknown entry_kind {name!r}; install via seckit taxonomy install or use developer mode"
        )


def policy_mode_active(*, sqlite_dev_mode: bool = False, force_policy: bool = False) -> bool:
    """Return True when writes should reject unknown vocabulary (non-dev)."""
    if sqlite_dev_mode:
        return False
    return force_policy


__all__ = [
    "policy_mode_active",
    "require_known_entry_kind",
    "require_known_entry_type",
]
