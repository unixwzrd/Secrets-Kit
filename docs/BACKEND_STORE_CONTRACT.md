# BackendStore contract

**Created**: 2026-05-05  
**Updated**: 2026-05-05

This note summarizes the :class:`~secrets_kit.backends.base.BackendStore` protocol as implemented in Phase 3. Authoritative code remains `src/secrets_kit/backends/base.py`; semantics for authority and materialization are in [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Responsibilities

- **Decrypt-free index** — :meth:`~secrets_kit.backends.base.BackendStore.iter_index` yields :class:`~secrets_kit.backends.base.IndexRow` instances suitable for `backend-index` and other safe listings. Implementations must **not** decrypt ciphertext or parse rich keychain/SQLite comment JSON inside this loop. Rows carry opaque handles (e.g. ``payload_ref``), hashes, and hints — not plaintext service/account/name triples on backends that keep locators private (SQLite).
- **Resolution** — :meth:`~secrets_kit.backends.base.BackendStore.resolve_by_entry_id` and :meth:`~secrets_kit.backends.base.BackendStore.resolve_by_locator` return :class:`~secrets_kit.backends.base.ResolvedEntry` (secret + :class:`~secrets_kit.models.core.EntryMetadata`) **in-process**. This is *resolved-within-handling* until a caller **materializes** (stdout, env, files, IPC). It is **not** a safe diagnostic surface by itself.
- **Unlocked enumeration** — :meth:`~secrets_kit.backends.base.BackendStore.iter_unlocked` performs decrypt/authority reads for maintenance or migration; it must **not** be used to implement ``iter_index``.
- **Repair** — :meth:`~secrets_kit.backends.base.BackendStore.rebuild_index` rebuilds decrypt-free index fields from authority payloads where the backend has a separate index layer; otherwise no-op or best-effort.

## Index row semantics

- **Safe dict** — :meth:`~secrets_kit.backends.base.IndexRow.to_safe_dict` is the canonical operator/CLI shape for listings: it **omits** ``payload_ref`` and corruption diagnostics by default.
- **Diagnostics** — :meth:`~secrets_kit.backends.base.IndexRow.to_diag_dict` adds ``payload_ref``, ``corrupt``, ``corrupt_reason``, and ``last_validation_at``. Treat as sensitive / non-loggable in production (doctor-only).
- **Corruption flags** — When present, ``corrupt`` indicates the adapter detected inconsistent or unreadable payload state at index level; ``corrupt_reason`` is adapter-defined text. Consumers should not treat index rows as authority when repair or operator action is required.

## Capabilities and posture

- **:meth:`~secrets_kit.backends.base.BackendStore.security_posture`** — Honest flags: metadata encryption, safe index availability, unlock requirement for full metadata, secure delete.
- **:meth:`~secrets_kit.backends.base.BackendStore.capabilities`** — Behavioral flags (safe index, tombstones, atomic set/rename, selective resolve, ``set_atomicity``, etc.).

## Validation mirrors (Phase 3)

Pydantic schemas under :mod:`secrets_kit.schemas` validate dict shapes **for tests and drift detection** — not as replacement types. See [plans/PHASE_3_PAYLOAD_INVENTORY.md](plans/PHASE_3_PAYLOAD_INVENTORY.md).

## References

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — resolve vs materialize, ``ResolvedEntry``.
- [IMPORT_LAYER_RULES.md](IMPORT_LAYER_RULES.md) — allowed imports (``backends`` → ``models``; ``schemas`` → ``models`` only for shared normalizers).
