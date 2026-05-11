"""Backend abstraction layer: index rows, capabilities, security posture, and store protocol.

CLI and application code should depend on these types and on :class:`BackendStore` only —
not on SQLite row layout, ciphertext shapes, or Keychain comment wire format.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Literal, Optional, Protocol

from secrets_kit.models.core import EntryMetadata, Locator

SetAtomicity = Literal["atomic", "eventual", "best_effort"]

# Version constants (align SQLite Keychain and wire format evolution).
INDEX_SCHEMA_VERSION = 1
PAYLOAD_SCHEMA_VERSION = 1  # Must match :data:`JOINT_PAYLOAD_VERSION`.
BACKEND_IMPL_VERSION = 1


@dataclass(frozen=True)
class BackendSecurityPosture:
    """Security-relevant properties of a backend (honest comparison for tooling)."""

    metadata_encrypted: bool
    """True when authoritative metadata lives inside an encrypted envelope (e.g. SQLite joint payload)."""

    safe_index_supported: bool
    """True when decrypt-free index rows are available (see :meth:`BackendStore.iter_index`)."""

    requires_unlock_for_metadata: bool
    """True when reading full authority requires unlock/decrypt (or equivalent)."""

    supports_secure_delete: bool
    """Backend can physically remove secret material (vs tombstone-only)."""


@dataclass(frozen=True)
class BackendCapabilities:
    """Functional capabilities separate from posture."""

    supports_safe_index: bool
    supports_unlock_enumeration: bool
    supports_atomic_rename: bool
    supports_tombstones: bool
    supports_backend_migrate: bool
    supports_transactional_set: bool
    """True when point lookup / resolution by entry_id or locator is efficient (vs scan-only backends)."""
    supports_selective_resolve: bool
    set_atomicity: SetAtomicity
    supports_peer_lineage_merge: bool
    """True when durable ``generation`` / ``tombstone_generation`` / ``deleted`` index supports Phase 6A merge (SQLite)."""
    supports_reconcile_transaction: bool
    """True when multi-step peer reconcile (e.g. rename + set, tombstone) can commit in one IMMEDIATE transaction."""


@dataclass(frozen=True)
class IndexRow:
    """Decrypt-free index row for application/CLI safe views.

    Carries no plaintext service/account/name locator triple (those stay adapter-private on
    SQLite). Must not carry sensitive operational metadata (tags, source, domains, entry_kind, …).

    ``payload_ref`` is an opaque backend handle (e.g. primary key), never ciphertext bytes.
    """

    entry_id: str
    locator_hash: str
    locator_hint: str
    updated_at: str
    deleted: bool
    deleted_at: str
    generation: int
    tombstone_generation: int
    index_schema_version: int
    payload_schema_version: int
    backend_impl_version: int
    payload_ref: Optional[str]
    corrupt: bool = False
    corrupt_reason: str = ""
    last_validation_at: str = ""

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serializable safe listing; omits ``payload_ref`` and corruption diagnostics by default."""
        return {
            "entry_id": self.entry_id,
            "locator_hash": self.locator_hash,
            "locator_hint": self.locator_hint,
            "updated_at": self.updated_at,
            "deleted": self.deleted,
            "deleted_at": self.deleted_at,
            "generation": self.generation,
            "tombstone_generation": self.tombstone_generation,
            "index_schema_version": self.index_schema_version,
            "payload_schema_version": self.payload_schema_version,
            "backend_impl_version": self.backend_impl_version,
        }

    def to_diag_dict(self) -> Dict[str, Any]:
        """Diagnostics (doctor): includes corruption flags and opaque ref; do not log in production."""
        d = dict(self.to_safe_dict())
        d.update(
            {
                "payload_ref": self.payload_ref,
                "corrupt": self.corrupt,
                "corrupt_reason": self.corrupt_reason,
                "last_validation_at": self.last_validation_at,
            }
        )
        return d


@dataclass(frozen=True)
class ResolvedEntry:
    """One decrypted authority view (secret + logical metadata).

    Plaintext is **resolved-within-handling** until some other layer **materializes** it (stdout,
    child env, files, etc.). :meth:`repr` intentionally **redacts** ``secret`` so tracebacks and
    logs do not implicitly leak. See ``docs/RUNTIME_AUTHORITY_ADR.md``.
    """

    secret: str
    metadata: EntryMetadata

    def __repr__(self) -> str:
        return f"ResolvedEntry(secret=<redacted>, metadata={self.metadata!r})"


class UnlockedFilter(Protocol):
    """Optional predicate for bounded unlocked iteration."""

    def __call__(self, row: IndexRow, meta: EntryMetadata) -> bool: ...


class BackendStore(ABC):
    """Backend contract: SQLite / Keychain / future.

    Only adapters implement payload encryption, row layout, and comment formats. All work here
    is **protected authority handling**: adapters may **resolve** full authority (including
    in-memory plaintext) without **materialization** until a caller crosses the boundary to
    operators, child processes, filesystems, or IPC (see ``docs/RUNTIME_AUTHORITY_ADR.md`` and
    ``docs/BACKEND_STORE_CONTRACT.md``).

    **Enumeration vs resolution**

    - :meth:`iter_index` — decrypt-free **index** surface; must not decrypt ciphertext or parse
      rich comment JSON. Output stays **inside** safe-index semantics (no secret plaintext).
      Rows must not expose operator-sensitive metadata (tags, domains, kinds, detailed source)
      in the :class:`IndexRow` itself; those appear only after **resolution**.
    - :meth:`resolve_by_entry_id` / :meth:`resolve_by_locator` — **authority** (secret + metadata)
      for in-process consumers; **does not** by itself **materialize** to the operator.
    - :meth:`iter_unlocked` — heavy scan with decrypt; must not be used to implement ``iter_index``.

    **Corruption and repair**

    Adapters set :class:`IndexRow` corruption fields when index/state inconsistencies are detected.
    Operators use diagnostics/``rebuild_index`` per capability; see ``docs/BACKEND_STORE_CONTRACT.md``.
    """

    @abstractmethod
    def security_posture(self) -> BackendSecurityPosture:
        """Return honest security properties for this backend."""

    @abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Return functional capability flags."""

    @abstractmethod
    def set_entry(
        self,
        *,
        service: str,
        account: str,
        name: str,
        secret: str,
        metadata: EntryMetadata,
    ) -> None:
        """Atomically persist authority + safe index state (per :attr:`BackendCapabilities.set_atomicity`)."""

    @abstractmethod
    def get_secret(self, *, service: str, account: str, name: str) -> str:
        """Return plaintext secret for active (non-deleted) entry."""

    @abstractmethod
    def resolve_by_entry_id(self, *, entry_id: str) -> Optional[ResolvedEntry]:
        """Load authority for one entry id, or None if missing/deleted.

        Returns :class:`ResolvedEntry` (secret + metadata) **in-process** — **resolved-within-handling**,
        not a CLI **materialization** path. Do not substitute documentary-only types from
        ``runtime_authority`` as return types here.
        """

    @abstractmethod
    def resolve_by_locator(self, *, service: str, account: str, name: str) -> Optional[ResolvedEntry]:
        """Load authority by runtime locator (normalize via :class:`~secrets_kit.models.core.Locator` in implementations).

        Same **resolved-within-handling** semantics as :meth:`resolve_by_entry_id` (see ADR).
        """

    def resolve_by_locator_obj(self, *, locator: Locator) -> Optional[ResolvedEntry]:
        """Convenience: resolve using a normalized :class:`~secrets_kit.models.core.Locator`."""
        loc = Locator.from_parts(service=locator.service, account=locator.account, name=locator.name)
        return self.resolve_by_locator(service=loc.service, account=loc.account, name=loc.name)

    @abstractmethod
    def delete_entry(self, *, service: str, account: str, name: str) -> None:
        """Apply tombstone / delete semantics per backend."""

    @abstractmethod
    def exists(self, *, service: str, account: str, name: str) -> bool:
        """True if an active (non-deleted) entry exists for the locator."""

    @abstractmethod
    def iter_index(self) -> Iterator[IndexRow]:
        """Decrypt-free index scan; must not decrypt payloads or parse rich metadata from comments.

        Index rows are **index-only** / safe-index surfaces — not **materialization** paths.
        Implementations must populate version fields consistently (index/payload/backend impl)
        and use ``corrupt`` / ``corrupt_reason`` / ``last_validation_at`` when the adapter
        detects damaged or inconsistent state without breaking the iterator contract.
        """

    @abstractmethod
    def iter_unlocked(self, *, filter_fn: Optional[Callable[[IndexRow, EntryMetadata], bool]] = None) -> Iterator[tuple[IndexRow, ResolvedEntry]]:
        """Bounded unlocked enumeration."""

    @abstractmethod
    def rename_entry(self, *, entry_id: str, new_service: str, new_account: str, new_name: str) -> None:
        """Update runtime locator; ``entry_id`` unchanged."""

    @abstractmethod
    def rebuild_index(self) -> None:
        """Rebuild decrypt-free index fields from authority payloads (repair drift, hashes, hints).

        No-op or best-effort when the backend has no separate index layer.
        """

    def migrate_entry(self, *args: Any, **kwargs: Any) -> Any:
        """Within-backend entry migration hook; override when ``supports_backend_migrate`` is True."""
        raise NotImplementedError("migrate_entry is not implemented for this backend")

    def export_authority(self, *args: Any, **kwargs: Any) -> Any:
        """Export canonical authority blob(s) for backup/sync."""
        raise NotImplementedError("export_authority is not implemented for this backend")

    def import_authority(self, *args: Any, **kwargs: Any) -> Any:
        """Import authority from :meth:`export_authority` wire format."""
        raise NotImplementedError("import_authority is not implemented for this backend")


JOINT_PAYLOAD_VERSION = PAYLOAD_SCHEMA_VERSION


def build_joint_payload_bytes(*, secret: str, metadata: EntryMetadata) -> bytes:
    """UTF-8 JSON body encrypted as the SQLite authority blob (adapter-internal helper).

    Kept here so callers share one version constant; SQLite adapter performs encryption.
    """
    import json

    from dataclasses import asdict

    payload = {"v": JOINT_PAYLOAD_VERSION, "secret": secret, "metadata": asdict(metadata)}
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_joint_payload_or_legacy(
    *,
    plain: bytes,
    legacy_metadata_json: Optional[str],
    service: str,
    account: str,
    name: str,
) -> tuple[str, EntryMetadata]:
    """Parse decrypted blob: joint v1 JSON, or legacy UTF-8 secret string + sidecar metadata_json."""
    import json

    text = plain.decode("utf-8")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("v") == JOINT_PAYLOAD_VERSION and "secret" in obj and "metadata" in obj:
            meta_raw = obj["metadata"]
            if isinstance(meta_raw, dict):
                return str(obj["secret"]), EntryMetadata.from_dict(meta_raw)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError):
        pass
    if legacy_metadata_json and legacy_metadata_json.strip():
        parsed = EntryMetadata.from_keychain_comment(legacy_metadata_json)
        if parsed is not None:
            return text, parsed
    return text, _minimal_metadata_locator(service=service, account=account, name=name)


def _minimal_metadata_locator(*, service: str, account: str, name: str) -> EntryMetadata:
    from secrets_kit.models.core import EntryMetadata, now_utc_iso

    ts = now_utc_iso()
    return EntryMetadata(
        name=name,
        service=service,
        account=account,
        source="legacy-sqlite",
        created_at=ts,
        updated_at=ts,
    )


def normalize_store_locator(*, service: str, account: str, name: str) -> Locator:
    """Normalize locator at BackendStore boundaries."""
    return Locator.from_parts(service=service, account=account, name=name)


def resolve_backend_store(
    *,
    backend: str,
    path: Optional[str] = None,
    kek_keychain_path: Optional[str] = None,
) -> BackendStore:
    """Concrete :class:`BackendStore` for ``secure`` or ``sqlite`` (canonical ids)."""
    from secrets_kit.backends.security import BACKEND_SQLITE, normalize_backend
    import os

    normalized = normalize_backend(backend)
    if normalized == BACKEND_SQLITE:
        from secrets_kit.backends.sqlite import SqliteSecretStore, default_sqlite_db_path

        db_path = path or default_sqlite_db_path()
        kc = kek_keychain_path
        if not kc:
            env_kc = os.environ.get("SECKIT_SQLITE_KEK_KEYCHAIN", "").strip()
            kc = os.path.expanduser(env_kc) if env_kc else None
        else:
            kc = os.path.expanduser(kc)
        return SqliteSecretStore(db_path=os.path.expanduser(db_path), kek_keychain_path=kc)

    from secrets_kit.backends.security_store import KeychainBackendStore

    return KeychainBackendStore(path=path)
