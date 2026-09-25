# Architecture Contexts
- [Architecture Contexts](#architecture-contexts)
  - [Summary](#summary)
  - [Shipped (2026-06)](#shipped-2026-06)
  - [Planned (not shipped here)](#planned-not-shipped-here)
  - [Bounded Contexts](#bounded-contexts)
    - [1. Metadata Catalog](#1-metadata-catalog)
    - [2. Keychain Comment Metadata](#2-keychain-comment-metadata)
    - [3. Daemon Endpoint and Routing Cache](#3-daemon-endpoint-and-routing-cache)
    - [4. Peer Trust Store](#4-peer-trust-store)
    - [5. Backend Provider Registry](#5-backend-provider-registry)
    - [6. SQLite Secret Store](#6-sqlite-secret-store)
    - [7. Sync/Reconciliation Layer](#7-syncreconciliation-layer)
  - [Do Not Infer](#do-not-infer)

## Summary

Secrets-Kit currently has several concepts historically called "registry." They are not the same subsystem, and the shared word should not be used as evidence that they share authority, storage semantics, or cleanup fate.

This document separates the bounded contexts so later cleanup can proceed in small, safe passes. It does not authorize source moves, module renames, runtime changes, SQLite schema changes, or deletion of compatibility surfaces.

## Shipped (2026-06)

Operator-facing layout in this repository today:

| Area                              | Path                                                 |
| --------------------------------- | ---------------------------------------------------- |
| Metadata index persistence        | `src/secrets_kit/registry/storage.py`                |
| Cross-backend metadata resolution | `src/secrets_kit/registry/resolve.py`                |
| CLI argparse metadata build       | `src/secrets_kit/cli/metadata_build.py`              |
| Backend-neutral CRUD              | `src/secrets_kit/backends/dispatch.py`               |
| Keychain comment JSON codec       | `src/secrets_kit/backends/keychain/comment_codec.py` |
| Keychain `security` subprocess    | `src/secrets_kit/backends/keychain/security_run.py`  |
| SQLite storage-mode gate         | `src/secrets_kit/backends/sqlite/gate.py`            |
| SQLite secret API                 | `src/secrets_kit/backends/sqlite/secrets_api.py`     |
| Daemon runtime plumbing           | `src/secrets_kit/daemon/`                            |
| Envelope persistence helpers      | `src/secrets_kit/backends/sqlite/envelopes.py`       |
| Encrypted export/import crypto    | `src/secrets_kit/crypto/cli/`                        |
| SQLite column codec               | `src/secrets_kit/crypto/storage/sqlite.py`           |

## Planned (not shipped here)

- endpoint discovery remains daemon transport work; durable endpoint lifecycle registration and replacement are runtime Peer Registry projections
- `src/secrets_kit/backends/registry.py` — backend provider factory (future)
- cross-host peer synchronization, relay-assisted synchronization, production SQLite encryption-at-rest

## Bounded Contexts

### 1. Metadata Catalog

Current examples:

- `registry.json`
- `src/secrets_kit/registry/core.py`
- `src/secrets_kit/registry/resolve.py`
- `src/secrets_kit/schemas/metadata.py`

Purpose:

- local schema/catalog definitions
- metadata validation, defaults, and field rules
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

### 3. Daemon Endpoint and Routing Cache

Current examples:

- `src/secrets_kit/daemon/server.py`
- `src/secrets_kit/daemon/client.py`

Purpose:

- durable endpoint lifecycle is owned by the runtime Peer Registry; the daemon owns only active endpoint binding, routing, and session discovery
- local transport/IPC state
- endpoint selection may change after restart or host-network changes
- discovery locates candidates but does not authorize peers
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
