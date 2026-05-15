"""SQLite joint authority payload encoding (JSON envelope + legacy UTF-8 parse).

On-disk / on-wire bytes must stay compatible with historical releases — see
``docs/BACKEND_STORE_CONTRACT.md``. Schema version is aligned with
:data:`~secrets_kit.backends.base.PAYLOAD_SCHEMA_VERSION`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional, Tuple

from secrets_kit.backends.base import PAYLOAD_SCHEMA_VERSION
from secrets_kit.models.core import EntryMetadata

JOINT_PAYLOAD_VERSION = PAYLOAD_SCHEMA_VERSION


def build_joint_payload_bytes(*, secret: str, metadata: EntryMetadata) -> bytes:
    """UTF-8 JSON body encrypted as the SQLite authority blob (adapter-internal)."""
    payload = {"v": JOINT_PAYLOAD_VERSION, "secret": secret, "metadata": asdict(metadata)}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_joint_payload_or_legacy(
    *,
    plain: bytes,
    legacy_metadata_json: Optional[str],
    service: str,
    account: str,
    name: str,
) -> Tuple[str, EntryMetadata]:
    """Parse decrypted blob: joint v1 JSON, or legacy UTF-8 secret string + sidecar metadata_json."""
    text = plain.decode("utf-8")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("v") == JOINT_PAYLOAD_VERSION and "secret" in obj and "metadata" in obj:
            meta_raw = obj["metadata"]
            if isinstance(meta_raw, dict):
                return str(obj["secret"]), EntryMetadata.from_dict(meta_raw)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError):
        pass
    if legacy_metadata_json and legacy_metadata_json.strip():
        parsed = EntryMetadata.from_keychain_comment(legacy_metadata_json)
        if parsed is not None:
            return text, parsed
    return text, _minimal_metadata_locator(service=service, account=account, name=name)


def _minimal_metadata_locator(*, service: str, account: str, name: str) -> EntryMetadata:
    from secrets_kit.models.core import now_utc_iso

    ts = now_utc_iso()
    return EntryMetadata(
        name=name,
        service=service,
        account=account,
        source="legacy-sqlite",
        created_at=ts,
        updated_at=ts,
    )
