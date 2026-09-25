"""
secrets_kit.identifiers

Canonical typed identifier creation, parsing, formatting, and validation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Final, Literal, Mapping

IdentifierType = Literal[
    "organization",
    "client",
    "owner",
    "peer_group",
    "service_group",
    "node",
    "secret",
    "transaction",
    "envelope",
    "entry_type",
    "entry_kind",
    "schema",
]

CANONICAL_IDENTIFIER_NAMESPACE: Final = uuid.UUID("4bdc25e7-6e50-4c47-a136-b447f15f8035")

PREFIX_BY_TYPE: Final[Mapping[IdentifierType, str]] = {
    "organization": "org",
    "client": "cli",
    "owner": "own",
    "peer_group": "pg",
    "service_group": "sg",
    "node": "node",
    "secret": "sec",
    "transaction": "txn",
    "envelope": "env",
    "entry_type": "et",
    "entry_kind": "ek",
    "schema": "sch",
}
TYPE_BY_PREFIX: Final[Mapping[str, IdentifierType]] = {
    prefix: identifier_type for identifier_type, prefix in PREFIX_BY_TYPE.items()
}


class IdentifierValidationError(ValueError):
    """Raised when a canonical typed identifier is invalid."""


@dataclass(frozen=True)
class CanonicalIdentifier:
    """Parsed canonical typed identifier."""

    identifier_type: IdentifierType
    prefix: str
    uuid: uuid.UUID

    def __str__(self) -> str:
        return format_identifier(identifier_type=self.identifier_type, value=self.uuid)


def random_identifier(*, identifier_type: IdentifierType) -> str:
    """Return a new UUIDv4 canonical typed identifier."""
    return format_identifier(identifier_type=identifier_type, value=uuid.uuid4())


def random_uuid_text() -> str:
    """Return lowercase UUIDv4 text for non-protocol local metadata."""
    return str(uuid.uuid4())


def deterministic_identifier(
    *,
    identifier_type: IdentifierType,
    namespace: str,
    name: str,
) -> str:
    """Return a deterministic UUIDv5 canonical typed identifier."""
    if not namespace:
        raise IdentifierValidationError("namespace is required for deterministic identifier")
    if not name:
        raise IdentifierValidationError("name is required for deterministic identifier")
    value = uuid.uuid5(
        CANONICAL_IDENTIFIER_NAMESPACE,
        f"{identifier_type}\0{namespace}\0{name}",
    )
    return format_identifier(identifier_type=identifier_type, value=value)


def deterministic_uuid_text(
    *,
    namespace: str,
    name: str,
) -> str:
    """Return deterministic UUIDv5 text for non-protocol local catalog ids."""
    if not namespace:
        raise IdentifierValidationError("namespace is required for deterministic UUID")
    if not name:
        raise IdentifierValidationError("name is required for deterministic UUID")
    return str(uuid.uuid5(CANONICAL_IDENTIFIER_NAMESPACE, f"uuid\0{namespace}\0{name}"))


def format_identifier(*, identifier_type: IdentifierType, value: uuid.UUID | str) -> str:
    """Format a UUID as a canonical typed identifier."""
    prefix = PREFIX_BY_TYPE[identifier_type]
    parsed_uuid = value if isinstance(value, uuid.UUID) else _parse_uuid_text(str(value), "uuid")
    return f"{prefix}:{parsed_uuid}"


def parse_identifier(*, value: str, field: str = "identifier") -> CanonicalIdentifier:
    """Parse one canonical typed identifier."""
    if not isinstance(value, str) or not value:
        raise IdentifierValidationError(f"{field} is required")
    if value.count(":") != 1:
        raise IdentifierValidationError(
            f"{field} must be a canonical typed identifier with one ':' separator: {value!r}"
        )
    prefix, uuid_text = value.split(":", 1)
    identifier_type = TYPE_BY_PREFIX.get(prefix)
    if identifier_type is None:
        raise IdentifierValidationError(
            f"{field} has unknown identifier prefix {prefix!r}: {value!r}"
        )
    parsed_uuid = _parse_uuid_text(uuid_text, field)
    canonical = f"{prefix}:{parsed_uuid}"
    if value != canonical:
        raise IdentifierValidationError(
            f"{field} must use lowercase canonical UUID text: {value!r}"
        )
    return CanonicalIdentifier(
        identifier_type=identifier_type,
        prefix=prefix,
        uuid=parsed_uuid,
    )


def validate_identifier(
    *,
    value: str,
    expected_type: IdentifierType,
    field: str,
) -> str:
    """Validate and return a canonical typed identifier of the expected type."""
    parsed = parse_identifier(value=value, field=field)
    if parsed.identifier_type != expected_type:
        expected_prefix = PREFIX_BY_TYPE[expected_type]
        raise IdentifierValidationError(
            f"{field} must be {expected_prefix}:<uuid>; got {parsed.prefix}: {value!r}"
        )
    return str(parsed)


def identifier_type(*, value: str, field: str = "identifier") -> IdentifierType:
    """Return the canonical identifier type for a value."""
    return parse_identifier(value=value, field=field).identifier_type


def identifier_uuid(*, value: str, field: str = "identifier") -> uuid.UUID:
    """Return the UUID portion of a canonical identifier."""
    return parse_identifier(value=value, field=field).uuid


def _parse_uuid_text(value: str, field: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise IdentifierValidationError(f"{field} must contain a valid UUID: {value!r}") from exc
    if str(parsed) != value:
        raise IdentifierValidationError(
            f"{field} must contain lowercase canonical UUID text: {value!r}"
        )
    return parsed


__all__ = [
    "CANONICAL_IDENTIFIER_NAMESPACE",
    "PREFIX_BY_TYPE",
    "TYPE_BY_PREFIX",
    "CanonicalIdentifier",
    "IdentifierType",
    "IdentifierValidationError",
    "deterministic_identifier",
    "deterministic_uuid_text",
    "format_identifier",
    "identifier_type",
    "identifier_uuid",
    "parse_identifier",
    "random_identifier",
    "random_uuid_text",
    "validate_identifier",
]
