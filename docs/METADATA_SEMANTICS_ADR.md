# Metadata and index semantics (ADR)

**Created**: 2026-05-07  
**Updated**: 2026-05-07  

This ADR fixes merge, tombstone, atomicity, and **BackendStore** index semantics. Code implementing `BackendStore` must follow these rules.

## Safe index (`IndexRow`)

- **Decrypt-free:** `iter_index()` must not decrypt ciphertext or parse rich Keychain comment JSON (Keychain may use a **temporary migration shim**: extract `entry_id` via UUID regex only; see below — **not permanent architecture**).
- **Minimal transport fields:** `entry_id`, `locator_hash`, `locator_hint`, timestamps, tombstone/generation flags, **`index_schema_version`**, **`payload_schema_version`**, **`backend_impl_version`**, optional **`payload_ref`** (opaque handle, never ciphertext bytes), optional corruption diagnostics for operators.
- **No plaintext locator triple** on `IndexRow` or in `to_safe_dict()` output: `service` / `account` / `name` remain **adapter-private** on SQLite rows for tooling and performance but are not part of the shared safe index type.
- **Sensitive fields** (tags, source, source_url, domains, comments, custom, entry_kind, full secret names, provider/topology identifiers) live **only** in the **encrypted authority payload** (or Keychain comment during transition), not in the safe index.

## Version triple (replace overloaded `backend_version`)

- **`index_schema_version`:** Layout of decrypt-free index rows / index migrations.
- **`payload_schema_version`:** Encrypted joint payload / authority JSON version (wire inside ciphertext).
- **`backend_impl_version`:** Adapter implementation level (diagnostics); stored in SQLite `backend_version` column until a dedicated rename migration.

## Corruption and validation (SQLite index)

- Rows may carry **`corrupt`**, **`corrupt_reason`**, **`last_validation_at`** for operator and rebuild tooling (truncated ciphertext, failed decrypt, interrupted writes). Semantics: **`rebuild_index`** attempts repair and clears flags when decrypt succeeds.

## `rebuild_index` / `reindex`

- Rebuilds decrypt-free index fields (hashes, hints) from decrypted **authority**; marks corrupt rows when decrypt fails. Keychain: no separate index file — **no-op**.
- **`migrate_entry`**, **`export_authority`**, **`import_authority`:** Optional hooks; default raises `NotImplementedError` until implemented per backend.

## Generation ownership

- **Generation is monotonic per `entry_id` within a backend authority lineage** (not a vague global truth). Supports future import/restore/replay and split-brain policies without claiming a single global counter.

## Keychain `iter_index` bridge (temporary)

- UUID extraction from comment text **without full JSON parse** is a **migration compatibility shim only** and **must not become permanent architecture**. Long-term: sidecar index, dedicated metadata item, deterministic mapping, or encrypted metadata blob.

## `BackendCapabilities`

- **`supports_selective_resolve`:** Efficient point lookup by locator or `entry_id`. Backends that only support full scans must set **False** so the CLI can degrade filtering behavior.

## Locator normalization

- Runtime locator is conceptually a **`Locator(service, account, name)`**; store implementations normalize at boundaries (strip strings) even when public methods still accept separate string arguments.

## Registry append-only journal

- **`registry_events.jsonl`** is **operational convenience** for audit and tooling. **It is never authoritative state** — authority remains in `BackendStore`; registry is a slim non-secret index.

## Identity

- **`entry_id`**: Immutable UUID for the life of the entry (sync identity, tombstones, conflicts). Never changes.
- **Locator** `(service, account, name)**: Mutable runtime alias; changes only via **`rename_entry`**. Not authoritative for long-term identity.

## Per-entry `generation` (SQLite index)

- Monotonic **integer** on the index row for that `entry_id` / locator.
- **Increment on every successful mutation** that changes authority or tombstone state: `set_entry`, `rename_entry`, tombstone `delete_entry`, restore (when implemented).
- **Not** a substitute for wall-clock time; used for deterministic merge ordering with peers when both sides carry generations.

## Tombstones (SQLite)

- **Delete** is a state transition: `deleted=1`, `deleted_at` set (ISO UTC), **`tombstone_generation`** incremented (and **`generation`** bumped with the same transaction as other index fields).
- **Physical remove** is backend-specific (Keychain may delete the item; SQLite keeps the row tombstoned until a future compaction policy).

## Conflict ordering (peer sync and future merge)

When comparing two versions of the same `entry_id` / registry key:

1. Higher **`generation`** wins (when both sides expose it; otherwise treat as absent / 0).
2. Else higher **`updated_at`** (lexicographic ISO string compare as today).
3. Else **`origin_host`** / sync-origin tie-break (see `sync_merge.effective_origin_host`).

Equal vectors with **different secret values** → **conflict** (caller must not auto-merge).

## `set_entry` atomicity

- **SQLite**: One transaction updates ciphertext, nonce, safe index columns, `generation`, tombstone fields, and `updated_at` / `origin_host` as applicable.
- **Keychain**: Best-effort sequential operations; advertised via `BackendCapabilities.set_atomicity`.

## Authority vs registry (`registry.json`)

- **On disk (v2):** `registry.json` stores only a **slim index** (locator, `entry_id`, `created_at`, `updated_at`, optional **`sync_origin_host`** for peer merge). It does **not** duplicate tags, source, paths, kinds, or domains — those belong in the backend payload only (see [METADATA_REGISTRY.md](METADATA_REGISTRY.md)).
- **SQLite**: Authoritative metadata is inside the **encrypted joint payload**; the registry row is not a second copy of that blob.
- **Peer import**: Local merge considers the **stronger** of registry **index** timestamps and store metadata (by `(updated_at, origin)` vector). Rich fields come from the store; the registry supplies coarse timestamps when the store read fails.

## Transport-neutral `EntryMetadata`

- Portable fields only (no `sqlite_*`, no Keychain wire keys). Safe **index** state is on **`IndexRow`**; adapter-private row fields (e.g. SQLite plaintext locator columns) are not part of the transport-neutral metadata model.
