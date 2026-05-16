"""
secrets_kit.schemas.identity_public

Mirror for :meth:`~secrets_kit.identity.core.HostIdentity.export_public_payload` dicts.
"""

from __future__ import annotations

from typing import Any

from secrets_kit.schemas.base import BaseSchema


class IdentityPublicExportDict(BaseSchema):
    """Public identity JSON shape (``seckit identity export`` / ``peer add``)."""

    format: str
    version: int
    host_id: str
    signing_public: str
    box_public: str


def validate_identity_public_export(row: dict[str, Any]) -> IdentityPublicExportDict:
    """Validate exported public identity JSON (tests / tooling)."""
    return IdentityPublicExportDict.model_validate(row)
