# Metadata Registry

- [Metadata Registry](#metadata-registry)
  - [Purpose](#purpose)
  - [Security posture](#security-posture)
  - [Schema (v2, current)](#schema-v2-current)
  - [Legacy schema (v1, migrated)](#legacy-schema-v1-migrated)
  - [Lifecycle rules](#lifecycle-rules)
    - [set](#set)
    - [import](#import)
    - [delete](#delete)
  - [Composite key identity](#composite-key-identity)
  - [Recovering a lost registry](#recovering-a-lost-registry)
  - [Notes](#notes)
  - [Back to README](#back-to-readme)

## Purpose

The registry stores a local inventory and recovery index for secret metadata.

The registry is:
- local-only
- non-authoritative
- metadata-only

Secret values are never stored in the registry.

Registry path:

```text id
~/.config/seckit/registry.json
```

Authoritative secret material lives in the configured storage backend:
- `keychain`
- `sqlite`

The registry exists to support:
- local inventory
- list/display operations
- recovery assistance
- metadata reconstruction
- operational tooling

It is not a vault and not a synchronization database.

## Security posture

Registry protections:

- registry directory permissions enforced to `0700`
- registry file permissions enforced to `0600`
- atomic writes
- no secret payload storage

The registry intentionally stores only slim locator/index metadata.

Filesystem access may still reveal:
- service names
- account names
- secret names
- timestamps
- entry ids
- optional synchronization metadata

but not secret values.

Security posture is a property of backend configuration, not registry identity.

## Schema (v2, current)

Top-level object:

```json
{
  "version": 2,
  "$schema": "https://unixwzrd.ai/schemas/seckit/registry-slim-v2.json",
  "entries": [
    {
      "name": "API_TOKEN",
      "service": "myapp",
      "account": "local",
      "entry_id": "550e8400-e29b-41d4-a716-446655440000",
      "created_at": "2026-03-02T18:20:00Z",
      "updated_at": "2026-03-02T19:05:00Z",
      "sync_origin_host": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    }
  ]
}
```

**Allowed keys per entry:** `name`, `service`, `account`, `entry_id`, `created_at`, `updated_at`, and optionally **`sync_origin_host`** (peer-merge host id only; same meaning as `custom.seckit_sync_origin_host` in full metadata). Any other key causes **load failure**.

**Migration:** If `version` is `1`, the next load rewrites the file as v2 (fat fields are dropped; timestamps, `entry_id`, and peer sync origin are preserved when present).

The full :class:`~secrets_kit.models.core.EntryMetadata` shape is the **logical schema** for the backend payload (see code and [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md)); it must not be mirrored into `registry.json`.

**Keychain comments:** items written via the ``keychain`` backend serialize metadata with :meth:`~secrets_kit.models.core.EntryMetadata.to_authority_dict` (omits ``content_hash`` and peer-only custom keys) so local Keychain payloads stay aligned with SQLite authority for migration; see [SECRET_STORE_CONTRACT.md](SECRET_STORE_CONTRACT.md).

## Legacy schema (v1, migrated)

Older installs used a **full** metadata blob per entry (see below). That format is **no longer written**; Open **v1** files are converted on load.

Historical example (for reference only):

```json
{
  "version": 1,
  "entries": [
    {
      "name": "OPENAI_API_KEY",
      "entry_type": "secret",
      "entry_kind": "api_key",
      "tags": ["openclaw", "prod"],
      "comment": "primary provider",
      "service": "openclaw",
      "account": "miafour",
      "created_at": "2026-03-02T18:20:00Z",
      "updated_at": "2026-03-02T19:05:00Z",
      "source": "manual",
      "schema_version": 1,
      "source_url": "https://platform.openai.com/api-keys",
      "source_label": "OpenAI dashboard",
      "rotation_days": 90,
      "rotation_warn_days": 14,
      "last_rotated_at": "2026-03-02T19:05:00Z",
      "expires_at": "",
      "domains": ["openai", "prod"],
      "custom": {"owner": "ops"}
    }
  ]
}
```

Legacy field meanings match the previous documentation; authoritative copies now live only in the secret backend after migration.

## Lifecycle rules

### set

- writes secret value to configured backend
- inserts or updates slim registry row
- preserves `created_at`
- refreshes `updated_at`

### import

- imports candidate entries
- applies overwrite policy
- writes secret material to backend
- writes slim registry rows

### delete

- removes backend secret material
- removes matching registry entry

Registry state is derived operational metadata only.

## Composite key identity

Entries are uniquely identified by:

```text
service + account + name
```

The same name may exist in multiple services/accounts without collision.

## Recovering a lost registry

If `registry.json` is missing or damaged, registry metadata may be rebuilt from backend-visible locator metadata.

Examples:

```bash
seckit recover --dry-run
seckit recover
seckit recover --dry-run --json
```

SQLite recovery:

```bash
seckit recover --backend sqlite
```

Optional Keychain path override:

```bash
seckit recover --backend keychain --keychain ~/Library/Keychains/custom.keychain-db
```

Limit recovery to one service:

```bash
seckit recover --service hermes
```

Compatibility alias:

```bash
seckit migrate recover-registry
```

Recovery behavior depends on backend-visible locator metadata only.

Current SQLite recovery behavior is local-only and bounded to standalone backend inspection.

Recovery must not imply:
- remote synchronization
- distributed consensus
- transport-layer replication
- daemon-managed recovery
- authoritative registry semantics

## Notes

- The registry is not authoritative storage.
- Secret values are never stored in `registry.json`.
- Missing registry state may be rebuilt from backend-visible metadata.
- Backend identity is separate from security posture.
- Current storage backends:
  - `keychain`
  - `sqlite`
- Future P2P/RSS work represents synchronization/transport layers over local storage backends.
- P2P/RSS are not authoritative remote secret stores.
- SQLite encryption-at-rest is not implemented yet.
- SQLite developer mode requires explicit acknowledgement until encryption-at-rest lands.
- Registry semantics must remain backend-neutral and transport-neutral.

## [Back to README](../README.md)

**Created**: 2026-03-02  
**Updated**: 2026-05-25
