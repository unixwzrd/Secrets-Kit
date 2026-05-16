"""Registry v2 minimal index — contract types and hashing.

`registry_v2.py` defines **alternate contract helpers** (e.g. opaque ``name_hash`` rows) for experiments and tests. The default on-disk ``registry.json`` format is implemented in ``registry.py`` (**v2 slim index**: locator + ``entry_id`` + timestamps); see [METADATA_REGISTRY.md](../docs/METADATA_REGISTRY.md).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Literal

REGISTRY_FORMAT_VERSION_V2 = 2

BackendId = Literal["secure", "sqlite"]


def registry_entry_key(*, service: str, account: str, name: str) -> str:
    """Return canonical triple string used for hashing and legacy registry keys."""
    return f"{service}::{account}::{name}"


def name_hash_hex(*, service: str, account: str, name: str) -> str:
    """SHA-256 hex digest of UTF-8 canonical entry key (v2 opaque name slot)."""
    raw = registry_entry_key(service=service, account=account, name=name).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RegistryIndexEntryV2:
    """Single row in a v2 registry (minimal local index / journal)."""

    id: str
    backend: BackendId
    service: str
    account: str
    name_hash: str
    updated_at: str
    deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "RegistryIndexEntryV2":
        """Construct a v2 registry index entry from a plain dict."""
        return cls(
            id=str(payload["id"]),
            backend=str(payload["backend"]),  # type: ignore[arg-type]
            service=str(payload["service"]),
            account=str(payload["account"]),
            name_hash=str(payload["name_hash"]),
            updated_at=str(payload["updated_at"]),
            deleted=bool(payload.get("deleted", False)),
        )


def new_entry_id() -> str:
    """Return a new UUID string for registry index rows."""
    return str(uuid.uuid4())


def v2_registry_document_payload(*, entries: List[RegistryIndexEntryV2]) -> Dict[str, Any]:
    """Build the top-level JSON object for a v2 registry file (for tests / future writer)."""
    return {
        "version": REGISTRY_FORMAT_VERSION_V2,
        "entries": [e.to_dict() for e in entries],
    }
