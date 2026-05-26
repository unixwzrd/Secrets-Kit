# SecretStore contract

**Created**: 2026-05-05  
**Updated**: 2026-05-26

This note summarizes the current :class:`~secrets_kit.backends.base.SecretStore`
protocol. Authoritative code remains `src/secrets_kit/backends/base.py`;
semantics for resolve, materialize, inject, and export are in
[RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Scope

`SecretStore` is the local storage authority interface used by the CLI dispatch
layer. Current public backend ids are:

- `keychain`
- `sqlite`

The interface is intentionally small. It is not a daemon API, remote sync API,
transport protocol, or diagnostics schema.

## Responsibilities

- **Set** stores or updates one secret value and its optional
  :class:`~secrets_kit.models.EntryMetadata`.
- **Get** returns one secret value in process. A caller must still decide whether
  to materialize it to stdout, a file, an environment, IPC, or another boundary.
- **Metadata** returns metadata for one locator. It is not a general plaintext
  secret dump path.
- **Exists** checks whether one locator is present.
- **Delete** removes one locator according to backend behavior.
- **List** returns inventory metadata, optionally scoped by service/account.
- **Doctor roundtrip** performs backend health checks using test data.

## Backend notes

- The Keychain implementation uses macOS generic-password items and Keychain
  comment JSON for non-secret metadata projection.
- The SQLite implementation is bounded developer-mode local storage until
  production encryption-at-rest is implemented. SQLite CLI use requires
  `--sqlite-dev-mode` or `SECKIT_SQLITE_DEVELOPER_MODE=1`.
- SQLite transaction and projection internals are documented separately in
  [LOCAL_FIRST_DATASTORE_ARCHITECTURE.md](LOCAL_FIRST_DATASTORE_ARCHITECTURE.md)
  and [OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md](OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md).

## Non-goals

- This contract does not define cross-host sync, remote storage, hosted relay
  behavior, daemon sessions, or network transport semantics.
- Pydantic schemas under `src/secrets_kit/schemas/` validate dict shapes for
  tests and drift detection. They do not replace `SecretStore`,
  `EntryMetadata`, or runtime model objects.

## References

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — resolve vs materialize.
- [IMPORT_LAYER_RULES.md](IMPORT_LAYER_RULES.md) — import boundaries.
- `src/secrets_kit/backends/base.py` — authoritative protocol definition.
