# Metadata schema registry

**Updated:** 2026-05-26

This document describes how Secrets-Kit stores typed metadata schemas for operator secrets.

## Not the same as entry type, kind, or tags

| Concept | Purpose |
|---------|---------|
| `entry_type` | Broad category (`secret`, `pii`) — SQLite `entry_types.name`; FK `secrets.entry_type_id` (UUID) |
| `entry_kind` | Narrow subtype (`api_key`, `password`, `token`) — SQLite `entry_kinds.name`; FK `secrets.entry_kind_id` (UUID) |
| `tags` | Free-form labels — SQLite `secret_tags.name` + UUID `tag_id`; also in metadata JSON |
| `schema_id` | JSON descriptor registry (`builtin.secret.api_key`, …) — this document |

## Authority

- **Canonical store:** JSON document on the `schema_registry` **system object** (`seckit` / `__system__` / `__schema_registry__` on Keychain and SQLite).
- **Seeds only:** `secrets_kit/schemas/builtin/*.json` and optional `~/.config/seckit/schemas/*.json` are merged at `seckit init` or `seckit schema install` — not read on every CLI invocation.
- **Export:** `seckit schema export` writes deterministic JSON (`sort_keys`, sorted `fields`, compact separators) for docs and controlled re-import.

## Descriptor shape (v1)

```json
{
  "schema_id": "builtin.secret.api_key",
  "schema_version": 1,
  "entry_type": "secret",
  "entry_kind": "api_key",
  "fields": {
    "provider": { "type": "string" },
    "endpoint": { "type": "string" }
  }
}
```

- Only `type: string` custom fields are supported in v1.
- `schema_version` on the descriptor is **store-authoritative**; it increments on any successful mutation (install merge that changes fields, field remove, deprecate).
- Seed file `schema_version` is a hint for **new** `schema_id` values only.

## Registry document

```json
{
  "registry_version": 1,
  "schemas": { "...": { } },
  "deprecated": {
    "builtin.secret.legacy": {
      "deprecated_at": "2026-05-26T00:00:00Z",
      "reason": "use api_key",
      "replacement_schema_id": "builtin.secret.api_key"
    }
  }
}
```

- **Deprecated** `schema_id` values block new `seckit set` / import writes.
- **`seckit schema remove`** fails when operator secrets still reference the id (use `--force` with confirmation).

## Merge rules (`schema install`)

| Rule | Behavior |
|------|----------|
| New `schema_id` | Insert descriptor; use seed `schema_version` or `1` |
| Existing `schema_id` | Union `fields` (add-only) by default |
| Field definition collision | Fail unless `--replace` (+ confirm) |
| `entry_type` / `entry_kind` | Never silently overwritten on existing ids |
| Field removal | Reference scan; `--force` sets `custom[field]` to `__undefined__` then removes from descriptor |

Constant: `SECKIT_UNDEFINED = "__undefined__"` — retired attribute sentinel (not JSON `null`).

## Metadata merge on writes

`merge_entry_metadata()` applies layers in order:

1. Operator `defaults.json` (`type`, `kind`, `service`, `account`)
2. Resolved schema descriptor (gaps for `schema_id` / `schema_version`)
3. Existing secret metadata (base)
4. Incoming overlay (CLI flags, import row)

Custom fields are validated against the resolved descriptor before persistence.

## CLI

| Command | Purpose |
|---------|---------|
| `seckit schema list` | Active schemas; `--all` includes deprecated |
| `seckit schema show <schema_id>` | One descriptor from store |
| `seckit schema export` | Deterministic JSON (`-o`, optional `--schema-id`) |
| `seckit schema install <paths…>` | Merge seeds; `--replace` for collisions |
| `seckit schema field remove <schema_id> <field>` | Reference-safe field removal |
| `seckit schema deprecate <schema_id>` | Block new assignments |
| `seckit schema remove <schema_id>` | Remove when unused |

`--type` and `--kind` on `seckit set` are validated dynamically against the registry (no static argparse `choices`).

## System objects

Reserved kinds live in `secrets_kit/system_objects.py`:

- `schema_registry` — this document
- `node_identity` — minimal local node JSON (foundation for future sync)

Operator `seckit list` excludes system locators (`seckit` / `__system__` / `__schema_registry__`, etc.) by metadata service/account/name — not by changing SQLite table layout.

See also: [TAXONOMY.md](TAXONOMY.md) for entry type/kind/tag vocabulary (separate from this document), and [LOCAL_FIRST_DATASTORE_ARCHITECTURE.md](LOCAL_FIRST_DATASTORE_ARCHITECTURE.md) for SQLite projections.
