"""Shared backend exceptions.

Backend errors are not Keychain-specific. Concrete stores and backend-facing
CLI helpers raise this exception for recoverable operator-facing backend
failures.
"""

from __future__ import annotations


class BackendError(RuntimeError):
    """Backend operation failed."""

