"""Keychain :class:`~secrets_kit.backends.base.BackendStore` adapter (``security`` CLI).

Metadata today lives in the **generic-password comment** (structured JSON) alongside the
secret — honest posture flags surface that comments are not encrypted. A future layout can
store ciphertext elsewhere without changing :class:`~secrets_kit.backends.base.BackendStore`.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import replace
from typing import Any, Callable, Dict, Iterator, Optional

from secrets_kit.backends.base import (
    INDEX_SCHEMA_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    BackendCapabilities,
    BackendSecurityPosture,
    BackendStore,
    IndexRow,
    ResolvedEntry,
)
from secrets_kit.backends.keychain.inventory import (
    GenpCandidate,
    dump_keychain_text,
    iter_seckit_genp_candidates,
)
from secrets_kit.backends.security import BackendError, SecurityCliStore, keychain_path
from secrets_kit.models.core import EntryMetadata, Locator, ensure_entry_id, now_utc_iso
from secrets_kit.models.locator import locator_hash_hex, opaque_locator_hint

# Temporary migration compatibility: extract UUID from comment without full JSON parse.
# Must not become permanent architecture; see docs/METADATA_SEMANTICS_ADR.md.
_ENTRY_ID_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _entry_id_from_comment_shim(comment: str) -> str:
    """Extract a UUID ``entry_id`` from a keychain comment via regex fallback.

    Temporary migration compatibility; see ``docs/METADATA_SEMANTICS_ADR.md``.
    """
    m = _ENTRY_ID_UUID_RE.search(comment or "")
    return m.group(0) if m else ""


def _stable_entry_id_from_locator(*, service: str, account: str, name: str) -> str:
    """Deterministic id for legacy items with no ``entry_id`` in comment (read-only index)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"seckit:keychain:{service}:{account}:{name}"))


def _meta_and_entry_id(
    *, service: str, account: str, name: str, comment: str
) -> tuple[EntryMetadata, str]:
    """Parse metadata from a keychain comment and return a stable ``entry_id``.

    When the comment lacks valid metadata, creates a synthetic record and
    derives a deterministic UUID from the locator.
    """
    parsed = EntryMetadata.from_keychain_comment(comment)
    if parsed is None:
        meta = EntryMetadata(name=name, service=service, account=account, source="keychain-manual", comment="")
        eid = _stable_entry_id_from_locator(service=service, account=account, name=name)
        return meta, eid
    meta = replace(parsed, name=name, service=service, account=account)
    if str(meta.entry_id).strip():
        return meta, str(meta.entry_id).strip()
    return meta, _stable_entry_id_from_locator(service=service, account=account, name=name)


class KeychainBackendStore(BackendStore):
    """Keychain-backed :class:`BackendStore` using :class:`SecurityCliStore`."""

    def __init__(self, *, path: Optional[str] = None) -> None:
        """Initialise a Keychain backend bound to an optional custom keychain file."""
        self._path = path
        self._cli = SecurityCliStore(path=path)

    def security_posture(self) -> BackendSecurityPosture:
        """Return honest posture flags for the Keychain backend.

        Metadata lives in the generic-password **comment**; comments are
        **not encrypted** on macOS.
        """
        return BackendSecurityPosture(
            metadata_encrypted=False,
            safe_index_supported=False,
            requires_unlock_for_metadata=True,
            supports_secure_delete=True,
        )

    def capabilities(self) -> BackendCapabilities:
        """Return capability flags for the Keychain backend."""
        return BackendCapabilities(
            supports_safe_index=False,
            supports_unlock_enumeration=True,
            supports_atomic_rename=False,
            supports_tombstones=False,
            supports_backend_migrate=False,
            supports_transactional_set=False,
            supports_selective_resolve=True,
            set_atomicity="best_effort",
            supports_peer_lineage_merge=False,
            supports_reconcile_transaction=False,
        )

    def rebuild_index(self) -> None:
        """No separate decrypt-free index file; items are the source of truth on Keychain."""
        return

    def _dump_text(self) -> str:
        """Return the raw text output of ``security dump-keychain``."""
        kc = keychain_path(path=self._path)
        return dump_keychain_text(path=kc)

    def set_entry(
        self,
        *,
        service: str,
        account: str,
        name: str,
        secret: str,
        metadata: EntryMetadata,
    ) -> None:
        """Write a secret and its metadata to the Keychain via ``security`` CLI."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        meta = ensure_entry_id(metadata)
        meta = replace(meta, name=loc.name, service=loc.service, account=loc.account)
        if not (meta.updated_at or "").strip():
            meta = replace(meta, updated_at=now_utc_iso())
        self._cli.set(
            service=loc.service,
            account=loc.account,
            name=loc.name,
            value=secret,
            comment=meta.to_keychain_comment(),
            label=loc.name,
        )

    def get_secret(self, *, service: str, account: str, name: str) -> str:
        """Read the secret value for a given locator from the Keychain."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        return self._cli.get(service=loc.service, account=loc.account, name=loc.name)

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        """Read raw keychain metadata attributes for a given locator."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        return self._cli.metadata(service=loc.service, account=loc.account, name=loc.name)

    def resolve_by_entry_id(self, *, entry_id: str) -> Optional[ResolvedEntry]:
        """Scan the keychain dump for a matching ``entry_id`` and return the decrypted secret."""
        want = str(entry_id).strip()
        if not want:
            return None
        dump = self._dump_text()
        for cand in iter_seckit_genp_candidates(dump):
            _meta, eid = _meta_and_entry_id(
                service=cand.service, account=cand.account, name=cand.name, comment=cand.comment
            )
            if eid != want:
                continue
            try:
                secret = self._cli.get(service=cand.service, account=cand.account, name=cand.name)
            except BackendError:
                return None
            full = EntryMetadata.from_keychain_comment(cand.comment)
            if full is None:
                full = replace(_meta, entry_id=eid)
            else:
                full = ensure_entry_id(replace(full, name=cand.name, service=cand.service, account=cand.account))
            return ResolvedEntry(secret=secret, metadata=full)
        return None

    def resolve_by_locator(self, *, service: str, account: str, name: str) -> Optional[ResolvedEntry]:
        """Look up a secret by service/account/name and return the decrypted entry."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        if not self._cli.exists(service=loc.service, account=loc.account, name=loc.name):
            return None
        try:
            secret = self._cli.get(service=loc.service, account=loc.account, name=loc.name)
            raw = self._cli.metadata(service=loc.service, account=loc.account, name=loc.name)
        except BackendError:
            return None
        comment = str(raw.get("comment", "") or "")
        meta = EntryMetadata.from_keychain_comment(comment)
        if meta is None:
            meta = EntryMetadata(
                name=loc.name,
                service=loc.service,
                account=loc.account,
                source="keychain-manual",
                comment="",
            )
        meta = ensure_entry_id(replace(meta, name=loc.name, service=loc.service, account=loc.account))
        return ResolvedEntry(secret=secret, metadata=meta)

    def delete_entry(self, *, service: str, account: str, name: str) -> None:
        """Delete a keychain entry by locator if it exists."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        if self._cli.exists(service=loc.service, account=loc.account, name=loc.name):
            self._cli.delete(service=loc.service, account=loc.account, name=loc.name)

    def exists(self, *, service: str, account: str, name: str) -> bool:
        """Return ``True`` when a keychain entry exists for the given locator."""
        loc = Locator.from_parts(service=service, account=account, name=name)
        return self._cli.exists(service=loc.service, account=loc.account, name=loc.name)

    def _index_row_for_candidate(self, cand: GenpCandidate) -> IndexRow:
        """Build an ``IndexRow`` from a keychain generic-password candidate."""
        eid = _entry_id_from_comment_shim(cand.comment)
        if not eid:
            eid = _stable_entry_id_from_locator(service=cand.service, account=cand.account, name=cand.name)
        lh = opaque_locator_hint(entry_id=eid)
        lhash = locator_hash_hex(service=cand.service, account=cand.account, name=cand.name)
        return IndexRow(
            entry_id=eid,
            locator_hash=lhash,
            locator_hint=lh,
            updated_at="",
            deleted=False,
            deleted_at="",
            generation=1,
            tombstone_generation=0,
            index_schema_version=INDEX_SCHEMA_VERSION,
            payload_schema_version=PAYLOAD_SCHEMA_VERSION,
            backend_impl_version=1,
            payload_ref=None,
            corrupt=False,
            corrupt_reason="",
            last_validation_at="",
        )

    def iter_index(self) -> Iterator[IndexRow]:
        """Yield ``IndexRow`` objects for every seckit-tagged keychain entry."""
        dump = self._dump_text()
        for cand in iter_seckit_genp_candidates(dump):
            yield self._index_row_for_candidate(cand)

    def iter_unlocked(
        self, *, filter_fn: Optional[Callable[[IndexRow, EntryMetadata], bool]] = None
    ) -> Iterator[tuple[IndexRow, ResolvedEntry]]:
        """Yield decrypted ``(IndexRow, ResolvedEntry)`` pairs for every seckit entry.

        Skips entries that cannot be unlocked. Optional ``filter_fn`` narrows
        the result without materialising skipped rows.
        """
        dump = self._dump_text()
        for cand in iter_seckit_genp_candidates(dump):
            idx = self._index_row_for_candidate(cand)
            try:
                res = self.resolve_by_locator(service=cand.service, account=cand.account, name=cand.name)
            except BackendError:
                continue
            if res is None:
                continue
            if filter_fn is None or filter_fn(idx, res.metadata):
                yield idx, res

    def rename_entry(self, *, entry_id: str, new_service: str, new_account: str, new_name: str) -> None:
        """Copy a secret to a new locator and delete the old entry.

        This is a read-then-write operation; it is **not atomic** on Keychain.
        """
        nloc = Locator.from_parts(service=new_service, account=new_account, name=new_name)
        resolved = self.resolve_by_entry_id(entry_id=entry_id)
        if resolved is None:
            raise BackendError("secret not found")
        old = resolved.metadata
        if not self._cli.exists(service=old.service, account=old.account, name=old.name):
            raise BackendError("secret not found")
        secret = self._cli.get(service=old.service, account=old.account, name=old.name)
        meta = ensure_entry_id(
            replace(
                resolved.metadata,
                service=nloc.service,
                account=nloc.account,
                name=nloc.name,
                updated_at=now_utc_iso(),
            )
        )
        self._cli.set(
            service=nloc.service,
            account=nloc.account,
            name=nloc.name,
            value=secret,
            comment=meta.to_keychain_comment(),
            label=nloc.name,
        )
        self._cli.delete(service=old.service, account=old.account, name=old.name)
