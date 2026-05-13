"""Mirror for public enrollment dicts from ``identity.enrollment``."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field, model_validator

from secrets_kit.schemas.base import BaseSchema
from secrets_kit.schemas.identity_public import IdentityPublicExportDict

_ENROLLMENT_FORMAT = "seckit.enrollment_public"
_ENROLLMENT_VERSION = 1

# Keys that must never appear on an enrollment payload (even as "unknown").
_SECRETISH_ENROLLMENT_KEYS: frozenset[str] = frozenset(
    {
        "signing_seed",
        "box_secret",
        "signing_private",
        "box_private",
        "private_key",
        "secret",
        "payload",
        "api_key",
        "token",
        "password",
    }
)


class PublicEnrollmentDict(BaseSchema):
    """Public enrollment composite (``build_public_enrollment_payload`` shape; field ``peer_endpoints``, wire ``relay_endpoints``)."""

    format: str = Field(description="Must match seckit.enrollment_public")
    enrollment_version: int
    identity: IdentityPublicExportDict
    peer_endpoints: Optional[List[str]] = Field(
        default=None,
        validation_alias="relay_endpoints",
        serialization_alias="relay_endpoints",
        description="Non-secret peer reach hints (wire key: relay_endpoints).",
    )


    @model_validator(mode="before")
    @classmethod
    def _reject_secretish_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            bad = sorted(k for k in data if k in _SECRETISH_ENROLLMENT_KEYS)
            if bad:
                raise ValueError(f"forbidden enrollment key(s): {', '.join(bad)}")
        return data

    @model_validator(mode="after")
    def _format_version(self) -> PublicEnrollmentDict:
        if self.format != _ENROLLMENT_FORMAT:
            raise ValueError(f"unsupported enrollment format: {self.format!r}")
        if int(self.enrollment_version) != _ENROLLMENT_VERSION:
            raise ValueError("unsupported enrollment_version")
        return self


def validate_public_enrollment(row: Dict[str, Any]) -> PublicEnrollmentDict:
    """Validate public enrollment JSON (tests / tooling)."""
    return PublicEnrollmentDict.model_validate(row)
