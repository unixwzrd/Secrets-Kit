# Taxonomy registry (entry types, kinds, tags)

**Updated:** 2026-05-26

Secrets-Kit separates **vocabulary** (type / kind / tags) from the **metadata schema registry** (`schema_id`, custom fields). See [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) for field descriptors.

## Canonical semantics

| Field | Role | Examples |
|-------|------|----------|
| `entry_type` | Policy / handling bucket | `secret`, `pii` |
| `entry_kind` | Shape of the value | `password`, `api_key`, `token`, `jwt` |
| `tags` | Operator labels | `prod`, `openai` |
| `custom` | Per-secret values | `provider=openai` (via `schema_id`) |

Provider names are **not** kinds. Use `kind=api_key` with `custom.provider` (and optional tags).

## Canonical names (UUID stability)

Vocabulary names are normalized before storage:

- trim whitespace
- lowercase
- `-` and spaces → `_`
- collapse repeated `_`

Examples: `API_Key`, `api-key`, and ` api_key ` all become `api_key` (one UUID).

Interactive writes show the transform and accept `Y` / decline `n` / `force-raw` (developer mode only). Non-interactive: `--accept-normalized` or fix spelling.

## Authority

| Store | Role |
|-------|------|
| `__taxonomy_registry__` system object (JSON) | **Canonical** vocabulary |
| SQLite `entry_types` / `entry_kinds` / `secret_tags` | **Projections** for indexes/FKs |
| `vocabulary.entry_type/kind.upsert` transactions | Mutation log for replay / future sync |

## CLI — `seckit taxonomy`

| Subcommand | Purpose |
|------------|---------|
| `list` | Table of vocabulary rows with **comments** (filterable) |
| `show` | One entry as JSON (`id`, `name`, `builtin`, `operator_comment`) |
| `export` | Deterministic registry JSON (`-o` file optional) |
| `install` | Merge seed JSON files (add-only by name) |

Common flags on subcommands: `--backend`, `--sqlite-dev-mode` (SQLite developer store).

### `taxonomy list`

Lists **entry types**, **entry kinds**, and **tags** from the canonical registry.

| Flag | Effect |
|------|--------|
| *(none)* | All three lists (types, kinds, tags) |
| `--types` | Only `entry_type` rows (`secret`, `pii`, …) |
| `--kinds` | Only `entry_kind` rows (`api_key`, `password`, …) |
| `--tags` | Only `tag` rows |
| `--types --kinds` | Union of selected lists (combine any filters) |
| `--json` | JSON array: `list`, `name`, `id`, `builtin`, `operator_comment` |

Human table columns: `list`, `name`, `builtin`, `comment`.

Examples:

```bash
seckit taxonomy list
seckit taxonomy list --kinds
seckit taxonomy list --types --json
seckit taxonomy list --tags --kinds
```

### `taxonomy show`

```bash
seckit taxonomy show entry_kind api_key
seckit taxonomy show entry_type secret
seckit taxonomy show tag prod
```

### `taxonomy export` / `install`

```bash
seckit taxonomy export -o taxonomy-registry.json
seckit taxonomy install ./custom-kinds.json
seckit taxonomy install ~/.config/seckit/taxonomy/*.json --accept-normalized
```

Seeds ship under `secrets_kit/taxonomy/builtin/` and optional `~/.config/seckit/taxonomy/`.

## Related: `seckit set` normalization

On `seckit set`, `--type` and `--kind` are validated against the taxonomy registry. Use:

- `--accept-normalized` / `-y` — accept canonical spelling without a prompt
- `--force-raw-name` — keep literal spelling (developer mode only; forks UUIDs)

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for the full command tree.

## Keychain vs SQLite

Keychain stores vocabulary in the system object JSON (and per-secret metadata strings). SQLite adds relational projections and vocabulary transactions on write.
