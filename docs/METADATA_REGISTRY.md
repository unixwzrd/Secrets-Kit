# Metadata Registry

- [Metadata Registry](#metadata-registry)
  - [Purpose](#purpose)
    - [Backend authority, ``entry_id``, and operator journal](#backend-authority-entry_id-and-operator-journal)
  - [Security posture](#security-posture)
  - [Schema (v2, current)](#schema-v2-current)
  - [Legacy schema (v1, migrated)](#legacy-schema-v1-migrated)
  - [Lifecycle rules](#lifecycle-rules)
  - [Composite key identity](#composite-key-identity)
  - [Recovering a lost registry](#recovering-a-lost-registry)
- [Machine-readable (includes ``recovered_entries`` and every skip detail):](#machine-readable-includes-recovered_entries-and-every-skip-detail)
- [SQLite (needs unlock the same as ``get`` / ``list`` — passphrase or KEK keychain):](#sqlite-needs-unlock-the-same-as-get--list--passphrase-or-kek-keychain)
- [Optional: non-login keychain file (secure backend only)](#optional-non-login-keychain-file-secure-backend-only)
- [Limit to one logical service:](#limit-to-one-logical-service)
  - [Notes](#notes)
  - [Back to README](#back-to-readme)

## Purpose

The registry stores a local inventory and recovery copy of metadata for each entry. Secret values are not stored here, and the registry is not the source of truth.

Registry path:

- `~/.config/seckit/registry.json`

### Backend authority, ``entry_id``, and operator journal

- **Transport model:** Application code should treat :class:`~secrets_kit.backend_store.BackendStore` and ``IndexRow`` as the abstraction; CLI helpers include **`seckit backend-index`** (decrypt-free index, JSON lines).
- **Immutable sync identity:** Each :class:`~secrets_kit.models.EntryMetadata` may carry an **`entry_id`** (UUID) assigned on first persist when empty; the locator tuple ``service`` / ``account`` / ``name`` remains mutable (see **`seckit`** rename flows). Merge and tombstone rules are documented in [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md).
- **Optional audit log:** **`seckit journal append '<json-object>'`** appends one line to **`~/.config/seckit/registry_events.jsonl`** (non-authoritative; does not replace backend storage).

## Security posture

- Registry directory permissions are enforced to `0700`.
- Registry file permissions are enforced to `0600`.
- Writes are atomic.
- Secret values are never stored in this file.

- **v2 index only:** The file stores a **slim** row per entry so it does **not** duplicate operational metadata (tags, source, kinds, domains, paths to dotenv files, etc.). That detail lives in the **backend** (Keychain comment JSON or SQLite encrypted payload). Attackers with filesystem access still see the locator tuple, timestamps, ``entry_id``, and optionally the peer-merge host id — not your import tool or provider labels.

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

The full :class:`~secrets_kit.models.EntryMetadata` shape is the **logical schema** for the backend payload (see code and [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md)); it must not be mirrored into `registry.json`.

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

1. `set`

- Writes secret value to the configured backend.
- Inserts/updates **slim** registry index (locator + `entry_id` + timestamps).
- Preserves `created_at` on index updates; refreshes `updated_at` on updates.
- Full metadata is written **only** to the backend (Keychain / SQLite joint payload).

2. `import env` / `import file`

- Builds candidate records.
- Applies overwrite policy (`--allow-overwrite`).
- Writes secret values to the backend and a **slim** registry row per accepted entry (full :class:`~secrets_kit.models.EntryMetadata` is stored in the backend only).

3. `delete`

- Removes Keychain value.
- Removes matching metadata record.

## Composite key identity

Entries are uniquely identified by the tuple:

- `service` + `account` + `name`

So the same `name` can exist in multiple services/accounts without collision.

## Recovering a lost registry

If `registry.json` is missing or empty but generic passwords remain in the Keychain with seckit’s service naming (`svce` = `{service}:{name}`), rebuild the registry from a `security dump-keychain` scan:

\```bash
seckit recover --dry-run
seckit recover
# Machine-readable (includes ``recovered_entries`` and every skip detail):
seckit recover --dry-run --json
# SQLite (needs unlock the same as ``get`` / ``list`` — passphrase or KEK keychain):
seckit recover --backend sqlite --db ~/.config/seckit/secrets.db
# Optional: non-login keychain file (secure backend only)
seckit recover --keychain ~/Library/Keychains/custom.keychain-db
# Limit to one logical service:
seckit recover --service hermes
\```

With **`--dry-run`** (and without **`--json`**), seckit prints a **table** in the same columns as **`seckit list`** for rows that would be recovered, then a **JSON** summary (counts and **`skipped_bad_names`** / other skip lists). Use **`--json`** for a **single** JSON document (no table) including **`recovered_entries`** for tooling.

The same operation is available as **`seckit migrate recover-registry`** for compatibility with older docs and scripts.

**Note:** You need a `seckit` build that includes `recover` / `recover-registry`. If `migrate` only lists `dotenv` and `metadata`, upgrade or reinstall from a current checkout (for example `pip install -e /path/to/secrets-kit`).

Requirements and limits:

- **`--backend secure`** or **`sqlite`**. For **SQLite**, recovery scans plaintext index columns (`service`, `account`, `name`, `metadata_json`); it does not dump the Keychain. You must be able to open the DB the same way as normal CLI use (passphrase / KEK).
- The login keychain (or `--keychain`) must be readable to **`security dump-keychain`** (unlock if needed).
- Only rows whose **`svce`** looks like **`logical:name`** are considered; other Keychain items are ignored.
- When the item’s comment field holds valid metadata JSON that matches `service` / `account` / `name`, that metadata is reused; otherwise a minimal row is written (`source`: `recovered-keychain`, `entry_kind` inferred from the name).

## Notes

- If registry permissions drift to unsafe values, write operations fail.
- If Keychain / SQLite metadata is missing but a **slim** registry index row exists, Secrets-Kit can still locate the secret by locator and may report **registry-fallback** with mostly default metadata until the backend comment/payload is repaired (`seckit migrate metadata`, re-import, or recover).
- If metadata is missing but a Keychain value exists, `get --raw` can still retrieve the value by explicit tuple.

## [Back to README](../README.md)

**Created**: 2026-03-02  
**Updated**: 2026-05-07
