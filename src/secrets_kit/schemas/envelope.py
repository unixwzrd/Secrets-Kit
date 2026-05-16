"""
secrets_kit.schemas.envelope

Mirror for minimal transport message wrapper dicts (not sync bundle v1).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import Field, field_validator
from secrets_kit.schemas.base import BaseSchema


class TransportMessageWrapperDict(BaseSchema):
    """Phase 4 conceptual outer message (opaque ``payload`` string slot)."""

    source_peer: str
    destination_peer: str
    timestamp: str
    payload_type: str = Field(
        description="Advisory only; intermediaries must not branch routing on this field.",
    )
    payload: str
    message_id: Optional[str] = None
    forward_token: Optional[str] = Field(
        default=None,
        validation_alias="route_token",
        serialization_alias="route_token",
        description="Optional forwarding hint (wire key: route_token).",
    )
    ttl: Optional[int] = Field(
        default=None,
        description="Optional operational expiry (seconds). Omitted from most fixtures.",
    )

    @field_validator("ttl")
    @classmethod
    def _ttl_positive(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        if int(v) <= 0:
            raise ValueError("ttl must be positive when present")
        return int(v)


def validate_transport_message_wrapper(row: Dict[str, Any]) -> TransportMessageWrapperDict:
    """Validate a transport wrapper dict (tests / tooling)."""
    return TransportMessageWrapperDict.model_validate(row)
