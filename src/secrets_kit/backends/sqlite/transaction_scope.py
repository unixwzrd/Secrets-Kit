"""
secrets_kit.backends.sqlite.transaction_scope

Canonical transaction scope classification for synchronization authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier


class TransactionScopeKind(str, Enum):
    """Closed transaction-scope classes used by authorization checks."""

    SERVICE_GROUP = "service_group"
    CONTROL = "control"
    LOCAL_SYSTEM = "local_system"


@dataclass(frozen=True)
class TransactionScope:
    """Validated canonical transaction scope."""

    kind: TransactionScopeKind
    service_group_id: str | None = None


SERVICE_GROUP_SCOPED_TRANSACTION_TYPES = frozenset(
    {
        "secret.set",
        "secret.delete",
    }
)
CONTROL_TRANSACTION_TYPES = frozenset(
    {
        "peer.admission.request",
        "peer.admission.accept",
        "peer.admission.reject",
        "peer.endpoint.register",
        "peer.endpoint.update",
        "peer.endpoint.replace",
        "peer.endpoint.expire",
        "peer.endpoint.remove",
    }
)
LOCAL_SYSTEM_TRANSACTION_PREFIXES = (
    "vocabulary.",
)


def transaction_scope(*, transaction: Transaction) -> TransactionScope:
    """Return the validated canonical synchronization scope for one transaction."""
    transaction_type = transaction.transaction_type
    if transaction_type in SERVICE_GROUP_SCOPED_TRANSACTION_TYPES:
        return TransactionScope(
            kind=TransactionScopeKind.SERVICE_GROUP,
            service_group_id=_required_service_group_id(transaction=transaction),
        )
    if transaction_type in CONTROL_TRANSACTION_TYPES:
        _reject_unexpected_service_group_id(transaction=transaction)
        return TransactionScope(kind=TransactionScopeKind.CONTROL)
    if transaction_type.startswith(LOCAL_SYSTEM_TRANSACTION_PREFIXES):
        _reject_unexpected_service_group_id(transaction=transaction)
        return TransactionScope(kind=TransactionScopeKind.LOCAL_SYSTEM)
    raise SQLiteValidationError(
        "transaction scope is unknown: "
        f"transaction_id={transaction.transaction_id} transaction_type={transaction_type}"
    )


def service_group_scope_id(*, transaction: Transaction) -> str | None:
    """Return the validated service-group scope id, if the transaction has one."""
    scope = transaction_scope(transaction=transaction)
    return scope.service_group_id


def _required_service_group_id(*, transaction: Transaction) -> str:
    value = transaction.payload.get("service_group_id")
    if value is None:
        raise SQLiteValidationError(
            "service_group_id is required for transaction type: "
            f"transaction_id={transaction.transaction_id} "
            f"transaction_type={transaction.transaction_type}"
        )
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(
            "service_group_id must be a non-empty canonical service_group identifier: "
            f"transaction_id={transaction.transaction_id}"
        )
    _validate_service_group_id(value=value)
    return value


def _reject_unexpected_service_group_id(*, transaction: Transaction) -> None:
    if "service_group_id" in transaction.payload:
        raise SQLiteValidationError(
            "service_group_id is not valid for transaction type: "
            f"transaction_id={transaction.transaction_id} "
            f"transaction_type={transaction.transaction_type}"
        )


def _validate_service_group_id(*, value: str) -> None:
    try:
        validate_identifier(value=value, expected_type="service_group", field="service_group_id")
    except IdentifierValidationError as exc:
        raise SQLiteValidationError(str(exc)) from exc


__all__ = [
    "CONTROL_TRANSACTION_TYPES",
    "LOCAL_SYSTEM_TRANSACTION_PREFIXES",
    "SERVICE_GROUP_SCOPED_TRANSACTION_TYPES",
    "TransactionScope",
    "TransactionScopeKind",
    "service_group_scope_id",
    "transaction_scope",
]
