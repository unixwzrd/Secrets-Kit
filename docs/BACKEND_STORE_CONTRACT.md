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

## Validation mirrors

Pydantic schemas under :mod:`secrets_kit.schemas` validate dict shapes **for tests and drift detection** — not as replacement types. They do not replace `BackendStore`, `EntryMetadata`, or runtime model objects.

## Keychain (secure) comment payload vs SQLite authority

- **Login / custom Keychain** stores non-secret metadata in the generic-password **comment** field as JSON.
- **Serializer:** :meth:`~secrets_kit.models.core.EntryMetadata.to_keychain_comment` uses :meth:`~secrets_kit.models.core.EntryMetadata.to_authority_dict`: the same logical fields as full metadata **minus peer/lineage-only** data (``content_hash`` and ``custom["seckit_sync_origin_host"]``). This matches the migratable “authority” shape; the encrypted SQLite joint payload continues to use full :class:`~secrets_kit.models.core.EntryMetadata` inside the blob for Phase 6A lineage.
- **Registry** still carries slim rows (including ``entry_id`` and optional ``sync_origin_host`` for merge); resolution merges registry index with store authority where needed.

## Operational audit vs lineage / replication

- **Operational audit** — append-only, backend-local traces of *what changed* in the store (e.g. SQLite ``secrets_audit`` + triggers). Useful for operator forensics; **not** authoritative for merge, recovery, or cross-host replication. Constants and read helpers live in ``src/secrets_kit/backends/sqlite/audit.py``; DDL stays in ``src/secrets_kit/backends/sqlite/schema.py``.
- **Lineage / merge authority** — ``generation``, ``tombstone_generation``, ``deleted``, and related fields on the canonical row (and encrypted authority payload where applicable) per [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) and peer-sync docs. This is the contract surface for deterministic merge, not the audit tail.
- **Replication logs** — if introduced, they are separate from operational audit; do not treat ``secrets_audit`` as a transport or source-of-truth stream.

## SQLite schema versions and audit

The encrypted SQLite backend uses ``PRAGMA user_version`` for forward-only, idempotent migrations:

- **2** — v2 ``secrets`` table (decrypt-free index columns + joint ciphertext payload); legacy v1 rows are migrated on first open.
- **3** — adds append-only **``secrets_audit``** and **INSERT/UPDATE/DELETE** triggers on ``secrets`` (installed idempotently via ``CREATE … IF NOT EXISTS``).

**``secrets_audit``** columns (authoritative DDL in ``src/secrets_kit/backends/sqlite/schema.py``): ``audit_id``, ``operation`` (`insert` / `update` / `delete`), ``changed_at`` (UTC ISO via SQLite ``strftime``), ``entry_id``, ``service``, ``account``, ``name``, ``generation``, ``tombstone_generation``, ``deleted``, ``content_hash``. The audit log **must not** store plaintext secret material, ciphertext, nonces, or other decrypted payload fields—only the safe columns above.

The audit table is **not** the authority for merge or recovery; it exists for operator diagnostics and local change tracing.

## References

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — resolve vs materialize, ``ResolvedEntry``.
- [IMPORT_LAYER_RULES.md](IMPORT_LAYER_RULES.md) — allowed imports (``backends`` → ``models``; ``schemas`` → ``models`` only for shared normalizers).
