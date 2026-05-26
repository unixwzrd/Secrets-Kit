# Object Model And Schema Semantics

**Created**: 2026-05-25  
**Status**: Semantic authority for future SQLite replay, projection, synchronization, and envelope lifecycle work.

This document defines object-model semantics for the SQLite local-first datastore. It complements [LOCAL_FIRST_DATASTORE_ARCHITECTURE.md](LOCAL_FIRST_DATASTORE_ARCHITECTURE.md), which remains the canonical schema architecture note.

This document does not implement replay, projection materialization, daemon IPC, peer synchronization, envelope lifecycle behavior, encryption, signing, migrations, ORM layers, repository abstractions, or CLI/backend integration.

## Authoritative State

Transactions are authoritative immutable history. A transaction records a canonical mutation event and is the durable source for audit, recovery, and future replay.

Projections are derived operational state. Projection rows such as `secrets` may be deleted and rebuilt entirely from canonical transaction history by a future replay implementation.

Envelopes are transient delivery state. Envelope persistence is a delivery artifact only and must not affect canonical replay outcome.

## Identity Model

Transaction identity is represented by `transaction_id`. It identifies one immutable mutation event, not the object being mutated.

Object identity is the stable identity of the secure object across mutations. Object identity should survive update, rename, replacement, deletion, and supersession events unless a later semantic rule explicitly creates a new object.

Projection identity is represented by projection table keys such as `secret_id`. Projection identity is derived operational state and may be recreated during replay.

Locator identity is represented by lookup/index material such as `locator_hash`. A locator exists to find candidate objects without storing plaintext names. `locator_hash` is lookup/index material only and must never be treated as proof of object identity or object integrity.

## Lineage And Ordering

`previous_transaction_id` is currently a simplified Phase 2 lineage placeholder. It should not be treated as a global blockchain-style transaction chain.

Future replay work may split lineage into:

- transaction ordering lineage;
- object mutation lineage.

Transaction ordering is not currently guaranteed by `created_at` alone. Phase 4 local replay uses SQLite `rowid` as an internal local replay cursor. That ordering is deterministic only within a single local SQLite database instance and rebuild sequence; it is not a distributed consensus ordering mechanism. Future replay may require a dedicated monotonic sequencing mechanism beyond timestamps.

Replay must be deterministic from canonical transaction history. Projections must be reproducible. Envelopes must not affect canonical replay outcome.

## Object Typing

`entry_type` identifies the broad secure object category (policy / handling bucket). Shipped examples: `secret`, `pii`. Operators may register additional types locally via the taxonomy registry — see [TAXONOMY.md](TAXONOMY.md).

`entry_kind` identifies a narrower subtype or operational interpretation (shape of the value). Examples include `generic`, `password`, `api_key`, `token`, `jwt`, `oauth_refresh_token`. **Do not** use provider names as kinds (`openai` belongs in `custom.provider` or tags).

**Aspirational / future examples** (not all are bundled seeds today): `credential`, `certificate`, `keypair`, `binary_blob`, `identity`, `payment`, `wallet`, `document`, `ssh_key`, `email`, `phone`, `address`, `credit_card`.

Vocabulary authority is the `__taxonomy_registry__` system object (JSON), not static Python lists. SQLite `entry_types` / `entry_kinds` tables are projections only.

`schema_id` identifies an object schema when built-in type/kind semantics are not enough. It should not be required for built-in or simple objects in early phases. When `schema_id` is absent, the built-in semantics implied by `entry_type` and `entry_kind` apply. User-defined or custom objects should eventually provide a stable `schema_id`.

`schema_version` identifies the schema revision for the object payload or metadata shape. Schema evolution must preserve deterministic replay behavior.

The current schema stores `entry_type` and `entry_kind` in clear. Production encrypted metadata and index policy may later revisit whether those fields remain clear, become blinded, or are duplicated into encrypted metadata.

## Projection Semantics

`secrets` is a derived encrypted current-state projection. It is not canonical history and is not synchronization authority.

Projection rows should be replaceable. Update, delete, and supersession semantics should be expressed through transactions first; projection rows reflect the result of accepted transaction application.

Current replay materializes `secret.set` and `secret.delete` into the `secrets` projection and applies vocabulary transactions for `vocabulary.entry_type.upsert`, `vocabulary.entry_kind.upsert`, and `vocabulary.tag.upsert`. It does not implement distributed replay, schema migration, production encryption, or daemon/sync behavior.

Standalone SQLite operation may use local transaction and projection tables without any envelope rows.

## Hashing Semantics

`payload_hash` is the hash of canonical serialized transaction payload bytes. It is not a hash of encrypted projection bytes and is not a hash of envelope payloads.

`content_hash` belongs to derived object/projection content semantics. Its exact boundary may evolve independently from transaction payload hashing semantics.

`locator_hash` belongs to lookup/index semantics only. It must not be used as proof of object identity, object integrity, transaction validity, or replay correctness.

Metadata participates in hashing only when the canonical transaction payload includes that metadata in the hashed payload boundary. Encrypted metadata stored in projections is not automatically part of `payload_hash` unless it was represented in the canonical transaction payload.

Canonical hashing requires deterministic serialization before hashing or signing. Incidental JSON formatting, dictionary insertion order, or transport envelope formatting must not affect transaction hashes.

## Encrypted And Indexable Fields

Encrypted object payloads contain secure object material and may include binary data. Binary object material belongs in encrypted payload bytes, not ad hoc JSON field sprawl.

Indexable fields such as `locator_hash` should reveal only the minimum lookup material required by the local datastore. Index material is not authoritative state.

The production policy may change which fields are clear, blinded, hashed, or duplicated into encrypted metadata. Those policy choices must preserve replay determinism and plaintext-minimization goals.

## Replacement And Tombstones

Object replacement should be represented as a new transaction that supersedes prior projected state.

Deletion should be represented as a transaction that produces tombstone or deleted projection state. Projection state may use `deleted` to preserve the fact of deletion while preventing resurrection from stale projection rows.

`superseded` indicates a projection row no longer represents current object state. It is projection vocabulary, not canonical historical authority.

## Envelope Semantics

Envelopes are delivery artifacts. They are not canonical history and are not required for standalone SQLite operation.

The current schema contains an `envelopes` table as reserved inert persistence for future daemon, RSS, or peer delivery integration. Its presence does not mean SQLite sends, receives, routes, retries, acknowledges, purges, or synchronizes anything.

Envelope persistence may eventually become optional or externally pluggable even though the current schema contains an `envelopes` table.

## Lifecycle Vocabulary

Current Phase 2 state constraints are intentionally narrow schema vocabulary constraints. They are not finalized lifecycle/state machines.

Transactions:

- `recorded`

Secrets:

- `active`
- `deleted`
- `superseded`

Envelopes:

- `recorded`
- `pending`
- `sent`
- `received`
- `acknowledged`
- `failed`
- `purged`

These values constrain stored vocabulary only. They do not implement lifecycle automation, replay, projection application, envelope routing, acknowledgment, retry, purge behavior, or synchronization.
