"""
secrets_kit.backends.base

Backend-neutral secret authority contracts.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from secrets_kit.models import EntryMetadata


@runtime_checkable
class SecretStore(Protocol):
    """Logical contract for local secret authority backends."""

    def set(
        self,
        *,
        service: str,
        account: str,
        name: str,
        value: str,
        metadata: Optional[EntryMetadata] = None,
        comment: str = "",
        label: Optional[str] = None,
    ) -> None: ...

    def get(self, *, service: str, account: str, name: str) -> str: ...

    def metadata(self, *, service: str, account: str, name: str) -> EntryMetadata: ...

    def exists(self, *, service: str, account: str, name: str) -> bool: ...

    def delete(self, *, service: str, account: str, name: str) -> None: ...

    def list(
        self, *, service: str | None = None, account: str | None = None
    ) -> list[EntryMetadata]: ...

    def doctor_roundtrip(
        self, *, service: str = "seckit-doctor", account: str = "doctor"
    ) -> None: ...


__all__ = ["SecretStore"]
