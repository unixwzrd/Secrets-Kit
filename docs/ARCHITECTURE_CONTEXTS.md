# Architecture Contexts

## Summary

Secrets-Kit currently has several concepts historically called "registry." They
are not the same subsystem, and the shared word should not be used as evidence
that they share authority, storage semantics, or cleanup fate.

This document separates the bounded contexts so later cleanup can proceed in
small, safe passes. It does not authorize source moves, module renames, runtime
changes, SQLite schema changes, or deletion of compatibility surfaces.

## Shipped (2026-05)

Operator-facing layout in this repository today:

| Area | Path |
|------|------|
| Metadata index persistence | `src/secrets_kit/registry/storage.py` |
| Cross-backend metadata resolution | `src/secrets_kit/registry/resolve.py` |
| CLI argparse metadata build | `src/secrets_kit/cli/metadata_build.py` |
| Backend-neutral CRUD | `src/secrets_kit/backends/dispatch.py` |
| Keychain comment JSON codec | `src/secrets_kit/backends/keychain/comment_codec.py` |
| Keychain `security` subprocess | `src/secrets_kit/backends/keychain/security_run.py` |
| SQLite dev-mode gate | `src/secrets_kit/backends/sqlite/gate.py` |
| SQLite secret API | `src/secrets_kit/backends/sqlite/secrets_api.py` |
| Encrypted export/import crypto | `src/secrets_kit/crypto/cli/` |
| SQLite column codec | `src/secrets_kit/crypto/storage/sqlite.py` |

## Planned (not shipped here)

- `src/secrets_kit/runtime/registry.py` — endpoint directory (future rename)
- `src/secrets_kit/backends/registry.py` — backend provider factory (future)
- `seckitd`, sync/merge transport, production SQLite encryption-at-rest

## Bounded Contexts

### 1. Metadata Index

Current examples:

- `registry.json`
- `src/secrets_kit/registry/core.py`
- `src/secrets_kit/registry/resolve.py`
- `src/secrets_kit/schemas/metadata.py`

Purpose:

- local inventory, index, and recovery compatibility
- Keychain-era metadata support
- not backend authority
- not sync authority
- not SQLite architecture

### 2. Keychain Comment Metadata

Current examples:

- `src/secrets_kit/backends/keychain/comment_codec.py`
- `src/secrets_kit/backends/keychain/store.py`
- `src/secrets_kit/backends/keychain/inventory.py`
- `src/secrets_kit/backends/compat/keychain_projection.py`

Purpose:

- structured metadata stored in the Keychain comment field
- required because Keychain is constrained key/value storage
- valid Keychain compatibility surface
- must not define SQLite persistence architecture

### 3. Runtime Endpoint Registry

Current examples:

- `src/secrets_kit/runtime/registry.py`
- `src/secrets_kit/runtime/paths.py`
- `src/secrets_kit/seckitd/server.py`

Purpose:

- transient runtime endpoint and session discovery
- local IPC/runtime state
- not secret metadata
- not backend authority

### 4. Peer Trust Store

Current examples:

- `src/secrets_kit/identity/peers.py`

Purpose:

- trusted peer public keys by alias
- identity and trust metadata
- not secret metadata registry
- not SQLite persistence model

### 5. Backend Provider Registry

Current examples:

- `src/secrets_kit/backends/registry.py`
- `src/secrets_kit/backends/factory.py`

Purpose:

- backend selection, factory behavior, and provider normalization
- not `registry.json`
- not secret metadata storage

### 6. SQLite Secret Store

Current examples:

- `src/secrets_kit/backends/sqlite/*`

Purpose:

- local relational secret storage
- should own canonical SQLite state relationally
- no fake migration obligation
- no Keychain comment emulation
- no registry JSON as canonical persistence

### 7. Sync/Reconciliation Layer

Current examples:

- `src/secrets_kit/sync/merge.py`
- `src/secrets_kit/sync/bundle.py`
- reconciliation tests

Purpose:

- import, export, and reconcile secret state
- may use metadata transfer objects
- must not treat `registry.json` as merge authority
- must not treat Keychain comment format as SQLite sync semantics

## Do Not Infer

- Do not infer that all `registry` references belong to one subsystem.
- Do not infer that registry cleanup means deleting all registry-named files.
- Do not infer that Keychain metadata behavior defines SQLite behavior.
- Do not infer that SQLite has released migration compatibility requirements.
- Do not introduce a new abstraction layer to unify these contexts.

## Deferred Cleanup Notes

These are possible future low-risk cleanup directions only. They are deferred
until each can be handled in a small, reviewed pass.

- `src/secrets_kit/backends/registry.py` may later be renamed toward backend provider/factory terminology.
- `src/secrets_kit/runtime/registry.py` may later be renamed toward endpoint directory terminology.
- `src/secrets_kit/registry/core.py` may later be moved under Keychain/index compatibility.
- `src/secrets_kit/registry/v2.py` may later be deleted if no compatibility use remains.
