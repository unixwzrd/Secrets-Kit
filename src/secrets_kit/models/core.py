"""
secrets_kit.models.core

Data models and validation for seckit.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

EntryType = Literal["secret", "pii"]
EntryKind = Literal[
    "generic",
    "token",
    "password",
    "user_id",
    "api_key",
    "email",
    "phone",
    "address",
    "credit_card",
    "wallet",
    "pii_other",
]
KEY_PATTERN = re.compile(r"^[A-Z0-9_]+$")
ENTRY_KIND_VALUES: List[str] = [
    "generic",
    "token",
    "password",
    "user_id",
    "api_key",
    "email",
    "phone",
    "address",
    "credit_card",
    "wallet",
    "pii_other",
]


class ValidationError(ValueError):
    """Input validation error."""


METADATA_SCHEMA_VERSION = 1

# Custom-metadata keys that are peer/sync-only; omitted from Keychain comments (and SQLite
# synthetic comment surfaces) so local authority matches migration-friendly shape; registry/SQLite
# blobs may still carry lineage elsewhere.
AUTHORITY_OMIT_CUSTOM_KEYS: frozenset[str] = frozenset({"seckit_sync_origin_host"})


@dataclass
class EntryMetadata:
    """Non-secret metadata for one stored secret entry."""

    name: str
    entry_type: EntryType = "secret"
    entry_kind: EntryKind = "generic"
    tags: List[str] = field(default_factory=list)
    comment: str = ""
    service: str = "seckit"
    account: str = "default"
    created_at: str = field(default_factory=lambda: now_utc_iso())
    updated_at: str = field(default_factory=lambda: now_utc_iso())
    source: str = "manual"
    schema_version: int = METADATA_SCHEMA_VERSION
    source_url: str = ""
    source_label: str = ""
    rotation_days: Optional[int] = None
    rotation_warn_days: Optional[int] = None
    last_rotated_at: str = ""
    expires_at: str = ""
    domains: List[str] = field(default_factory=list)
    custom: Dict[str, Any] = field(default_factory=dict)
    #: Immutable sync identity (UUID); generated on first persist when empty.
    entry_id: str = ""
    #: SHA-256 hex of canonical record (secret + metadata without this field); optional until populated.
    content_hash: str = ""

    def key(self) -> str:
        """Return unique registry key."""
        return make_registry_key(service=self.service, account=self.account, name=self.name)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dict."""
        return asdict(self)

    def to_authority_dict(self) -> Dict[str, Any]:
        """Metadata dict aligned with migratable local authority: same fields as ``to_dict()`` minus peer/lineage-only.

        Omits ``content_hash`` (peer row digest). Strips sync-origin entries from ``custom``.
        Used for Keychain generic-password comments and SQLite's keychain-shaped ``comment`` field.
        """
        d = dict(self.to_dict())
        d.pop("content_hash", None)
        custom_raw = d.get("custom")
        if isinstance(custom_raw, dict):
            custom = {str(k): v for k, v in custom_raw.items() if str(k) not in AUTHORITY_OMIT_CUSTOM_KEYS}
            d["custom"] = custom
        return d

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "EntryMetadata":
        """Create metadata from dict payload."""
        return cls(
            name=str(payload["name"]),
            entry_type=str(payload.get("entry_type", payload.get("type", "secret"))),
            entry_kind=str(payload.get("entry_kind", payload.get("kind", "generic"))),
            tags=list(payload.get("tags", [])),
            comment=str(payload.get("comment", "")),
            service=str(payload.get("service", "seckit")),
            account=str(payload.get("account", "default")),
            created_at=str(payload.get("created_at", now_utc_iso())),
            updated_at=str(payload.get("updated_at", now_utc_iso())),
            source=str(payload.get("source", "manual")),
            schema_version=int(payload.get("schema_version", METADATA_SCHEMA_VERSION)),
            source_url=str(payload.get("source_url", "")),
            source_label=str(payload.get("source_label", "")),
            rotation_days=_optional_int(payload.get("rotation_days")),
            rotation_warn_days=_optional_int(payload.get("rotation_warn_days")),
            last_rotated_at=str(payload.get("last_rotated_at", "")),
            expires_at=str(payload.get("expires_at", "")),
            domains=normalize_domains(payload.get("domains", [])),
            custom=normalize_custom(payload.get("custom", {})),
            entry_id=str(payload.get("entry_id", "")),
            content_hash=str(payload.get("content_hash", "")),
        )

    def to_keychain_comment(self) -> str:
        """Serialize metadata into the keychain comment payload (authority shape; legacy JSON still parses)."""
        return json.dumps(self.to_authority_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_keychain_comment(cls, comment: str) -> Optional["EntryMetadata"]:
        """Parse a metadata payload stored in the keychain comment field."""
        stripped = comment.strip()
        if not stripped:
            return None
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        if "name" not in payload or "service" not in payload or "account" not in payload:
            return None
        return cls.from_dict(payload)


def now_utc_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_key_name(*, name: str) -> str:
    """Validate and normalize env-style key names."""
    stripped = name.strip()
    if not stripped:
        raise ValidationError("name cannot be empty")
    if not KEY_PATTERN.match(stripped):
        raise ValidationError(f"invalid key name '{name}': allowed pattern is [A-Z0-9_]+")
    return stripped


def validate_entry_type(*, entry_type: str) -> EntryType:
    """Validate entry type."""
    if entry_type not in {"secret", "pii"}:
        raise ValidationError("type must be one of: secret, pii")
    return entry_type  # type: ignore[return-value]


def validate_entry_kind(*, entry_kind: str) -> EntryKind:
    """Validate semantic kind classification."""
    if entry_kind not in set(ENTRY_KIND_VALUES):
        raise ValidationError(f"kind must be one of: {', '.join(ENTRY_KIND_VALUES)}")
    return entry_kind  # type: ignore[return-value]


def infer_entry_kind_from_name(*, name: str) -> EntryKind:
    """Infer semantic kind from env-style key name."""
    upper = name.upper()
    if "TOKEN" in upper:
        return "token"
    if "PASSWORD" in upper or "PASSWD" in upper or upper.endswith("_PWD"):
        return "password"
    if "USER_ID" in upper or upper.endswith("_UID") or upper.endswith("_USER"):
        return "user_id"
    if "API_KEY" in upper or upper.endswith("_KEY"):
        return "api_key"
    if "EMAIL" in upper:
        return "email"
    if "PHONE" in upper or "MOBILE" in upper:
        return "phone"
    if "ADDRESS" in upper or "ADDR" in upper:
        return "address"
    if "CREDIT_CARD" in upper or "CARD_NUMBER" in upper or "PAN" in upper:
        return "credit_card"
    if "WALLET" in upper or "SEED_PHRASE" in upper or "PRIVATE_KEY" in upper:
        return "wallet"
    return "generic"


def normalize_tags(*, tags_csv: str | None = None, tags: List[str] | None = None) -> List[str]:
    """Normalize tag inputs into a unique sorted list."""
    raw: List[str] = []
    if tags_csv:
        raw.extend(tags_csv.split(","))
    if tags:
        raw.extend(tags)
    out = sorted({item.strip() for item in raw if item.strip()})
    return out


def normalize_domains(raw: Any) -> List[str]:
    """Normalize domain metadata into a unique sorted list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        items = raw.split(",")
    elif isinstance(raw, list):
        items = raw
    else:
        return []
    return sorted({str(item).strip() for item in items if str(item).strip()})


def normalize_custom(raw: Any) -> Dict[str, Any]:
    """Normalize custom metadata to a plain string-keyed dict."""
    if not isinstance(raw, dict):
        return {}
    return {str(key): value for key, value in raw.items()}


def _optional_int(value: Any) -> Optional[int]:
    if value in {None, ""}:
        return None
    return int(value)


@dataclass(frozen=True)
class Locator:
    """Mutable runtime secret locator (service, account, name); normalize at store boundaries."""

    service: str
    account: str
    name: str

    @classmethod
    def from_parts(cls, *, service: str, account: str, name: str) -> "Locator":
        """Strip strings for consistent lookups and registry keys."""
        return cls(service=str(service).strip(), account=str(account).strip(), name=str(name).strip())


def make_registry_key(*, service: str, account: str, name: str) -> str:
    """Create composite key for metadata registry."""
    return f"{service}::{account}::{name}"


def ensure_entry_id(metadata: EntryMetadata) -> EntryMetadata:
    """Return metadata with a non-empty ``entry_id`` (assign UUID v4 when missing)."""
    import uuid
    from dataclasses import replace

    if str(metadata.entry_id).strip():
        return metadata
    return replace(metadata, entry_id=str(uuid.uuid4()))
