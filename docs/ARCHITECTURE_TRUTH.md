# Architecture Truth

SQLite is an unreleased experimental backend. No production SQLite database format exists. There is no SQLite v1, v2, v3, or v4 migration obligation. Any existing SQLite schema/code in this branch is development scaffolding and may be replaced.

Keychain and SQLite are equivalent backend targets, not structurally identical implementations.

Keychain uses structured JSON metadata in the Keychain comment field because Keychain is a constrained key/value store.

SQLite must not emulate Keychain comment metadata, registry JSON, or projection payloads as canonical persistence.

`registry.json` is local inventory/recovery/index compatibility. It is not backend authority, sync authority, persistence authority, replay authority, or SQLite architecture.

`EntryMetadata` is allowed as a runtime/API transfer object and Keychain comment payload shape. It is not SQLite canonical persistence authority.

SQLite canonical state must be relational:
- store metadata
- secret objects
- secret versions
- labels
- lifecycle events
- typed history/audit evidence

Forbidden SQLite architecture:
- metadata_json
- registry_json
- authority_json
- legacy SQLite payloads
- fake SQLite migration support
- Keychain projection imports in canonical SQLite paths
- treating provisional SQLite code as released compatibility

Do not introduce broad abstraction layers to unify Keychain and SQLite internals. Keep the shared public API stable, but let each backend implement storage correctly for its platform.