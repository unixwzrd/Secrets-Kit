"""Data models and validation for seckit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Literal

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

    def key(self) -> str:
        """Return unique registry key."""
        return make_registry_key(service=self.service, account=self.account, name=self.name)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dict."""
        return asdict(self)

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
        )


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


def make_registry_key(*, service: str, account: str, name: str) -> str:
    """Create composite key for metadata registry."""
    return f"{service}::{account}::{name}"
