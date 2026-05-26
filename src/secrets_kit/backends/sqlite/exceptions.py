"""
secrets_kit.backends.sqlite.exceptions

SQLite backend exception types.
"""

from __future__ import annotations


class SQLiteBackendError(Exception):
    """
    Base SQLite backend failure.

    Args:
        message:
            Human-readable failure detail.

    Returns:
        Exception instance.

    Side Effects:
        None.
    """


class SQLiteValidationError(SQLiteBackendError):
    """
    Transaction validation failure.

    Args:
        message:
            Human-readable validation detail.

    Returns:
        Exception instance.

    Side Effects:
        None.
    """


class DuplicateTransactionError(SQLiteBackendError):
    """
    Duplicate transaction identifier failure.

    Args:
        message:
            Human-readable duplicate detail.

    Returns:
        Exception instance.

    Side Effects:
        None.
    """


class TransactionNotFoundError(SQLiteBackendError):
    """
    Missing transaction failure.

    Args:
        message:
            Human-readable lookup detail.

    Returns:
        Exception instance.

    Side Effects:
        None.
    """


__all__ = [
    "DuplicateTransactionError",
    "SQLiteBackendError",
    "SQLiteValidationError",
    "TransactionNotFoundError",
]
