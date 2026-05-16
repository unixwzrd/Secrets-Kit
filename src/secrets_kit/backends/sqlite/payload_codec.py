"""SQLite current joint authority payload encoding.

Runtime code parses only the current joint payload format. Historical payloads
are promoted by ``sqlite.migrations`` using ``sqlite.legacy_payload`` before
normal store operations continue. Schema version is aligned with
:data:`~secrets_kit.backends.base.PAYLOAD_SCHEMA_VERSION`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Tuple

from secrets_kit.backends.base import PAYLOAD_SCHEMA_VERSION
from secrets_kit.models.core import EntryMetadata

JOINT_PAYLOAD_VERSION = PAYLOAD_SCHEMA_VERSION


def build_joint_payload_bytes(*, secret: str, metadata: EntryMetadata) -> bytes:
    """UTF-8 JSON body encrypted as the SQLite authority blob (adapter-internal)."""
    payload = {"v": JOINT_PAYLOAD_VERSION, "secret": secret, "metadata": asdict(metadata)}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_current_payload(*, plain: bytes) -> Tuple[str, EntryMetadata]:
    """Parse the current SQLite joint payload format."""
    text = plain.decode("utf-8")
    obj = json.loads(text)
    if not isinstance(obj, dict) or obj.get("v") != JOINT_PAYLOAD_VERSION:
        raise ValueError("unsupported SQLite payload version")
    if "secret" not in obj or "metadata" not in obj or not isinstance(obj["metadata"], dict):
        raise ValueError("invalid SQLite joint payload")
    return str(obj["secret"]), EntryMetadata.from_dict(obj["metadata"])
