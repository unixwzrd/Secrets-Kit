"""Mirror for :func:`~secrets_kit.sync.bundle.inspect_bundle` result dicts."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from secrets_kit.schemas.base import BaseSchema


class InspectBundleSummaryDict(BaseSchema):
    """Stable keys returned by :func:`secrets_kit.sync.bundle.inspect_bundle`."""

    entry_count_manifest: Optional[int]
    recipient_fingerprints: List[str]
    signature_ok: bool
    signer_fingerprint: str
    signer_host_id: str
    verify_message: str


def validate_inspect_bundle_summary(row: Dict[str, Any]) -> InspectBundleSummaryDict:
    """Validate an inspect summary dict (tests / offline tooling)."""
    return InspectBundleSummaryDict.model_validate(row)
