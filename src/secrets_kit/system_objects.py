"""
secrets_kit.system_objects

Reserved system-object identities and locator semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, Optional, Tuple


class SystemObjectKind(str, Enum):
    """Kinds of reserved system objects stored like secrets but not listed as operator entries."""

    SCHEMA_REGISTRY = "schema_registry"
    TAXONOMY_REGISTRY = "taxonomy_registry"
    NODE_IDENTITY = "node_identity"


SYSTEM_SERVICE: Final[str] = "seckit"
SYSTEM_ACCOUNT: Final[str] = "__system__"

ORG_LOCAL_ID: Final[str] = "org:local"
CLIENT_LOCAL_ID: Final[str] = "client:local"
PEER_GROUP_LOCAL_ID: Final[str] = "peer-group:local"
NODE_LOCAL_ID: Final[str] = "node:local"
SERVICE_GROUP_LOCAL_PREFIX: Final[str] = "service-group:local:"


def system_object_id(*, kind: SystemObjectKind) -> str:
    """Return stable logical id for a system object kind (documentation / future use)."""
    return f"system:{kind.value}"


def system_secret_name(*, kind: SystemObjectKind) -> str:
    """Return Keychain item name for a system object."""
    return f"__{kind.value}__"


@dataclass(frozen=True)
class SystemLocator:
    """Keychain generic-password locator for a system object."""

    service: str
    account: str
    name: str
    kind: SystemObjectKind
    object_id: str


def locator_for_kind(*, kind: SystemObjectKind) -> SystemLocator:
    """Build the canonical locator for one system object kind."""
    return SystemLocator(
        service=SYSTEM_SERVICE,
        account=SYSTEM_ACCOUNT,
        name=system_secret_name(kind=kind),
        kind=kind,
        object_id=system_object_id(kind=kind),
    )


def is_system_locator(*, service: str, account: str, name: str) -> bool:
    """Return whether service/account/name identifies a system object."""
    if service != SYSTEM_SERVICE or account != SYSTEM_ACCOUNT:
        return False
    return name.startswith("__") and name.endswith("__")


def kind_from_locator(*, service: str, account: str, name: str) -> Optional[SystemObjectKind]:
    """Resolve system object kind from locator components."""
    if not is_system_locator(service=service, account=account, name=name):
        return None
    inner = name.strip("_")
    try:
        return SystemObjectKind(inner)
    except ValueError:
        return None


def is_operator_locator(*, service: str, account: str, name: str) -> bool:
    """Return whether locator is a normal operator secret (not system-reserved)."""
    return not is_system_locator(service=service, account=account, name=name)


def is_operator_metadata(*, metadata: object) -> bool:
    """Return whether metadata belongs to an operator secret."""
    from secrets_kit.models import EntryMetadata

    if not isinstance(metadata, EntryMetadata):
        return True
    return is_operator_locator(
        service=metadata.service, account=metadata.account, name=metadata.name
    )


def parse_system_locator_tuple(locator: Tuple[str, str, str]) -> Optional[SystemObjectKind]:
    """Parse (service, account, name) into a system object kind when applicable."""
    service, account, name = locator
    return kind_from_locator(service=service, account=account, name=name)


__all__ = [
    "CLIENT_LOCAL_ID",
    "NODE_LOCAL_ID",
    "ORG_LOCAL_ID",
    "PEER_GROUP_LOCAL_ID",
    "SERVICE_GROUP_LOCAL_PREFIX",
    "SYSTEM_ACCOUNT",
    "SYSTEM_SERVICE",
    "SystemLocator",
    "SystemObjectKind",
    "is_operator_locator",
    "is_operator_metadata",
    "is_system_locator",
    "kind_from_locator",
    "locator_for_kind",
    "parse_system_locator_tuple",
    "system_object_id",
    "system_secret_name",
]
