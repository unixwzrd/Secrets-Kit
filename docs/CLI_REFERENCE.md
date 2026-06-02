# CLI reference — `seckit`

**Created**: 2026-05-07  
**Updated**: 2026-06-01

Exhaustive command list in **taxonomy order** (same as `seckit --help` epilog). For mental models and policies, see [CONCEPTS.md](CONCEPTS.md), [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md), [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md), and [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Output conventions

- **Operators:** default tables and prose may change between releases.
- **Automation:** prefer **`--json`** / structured fields where offered; treat those as **more stable** than human formatting. See [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Everyday operations

| Command | Purpose |
|---------|---------|
| `set` | Store or update one secret (`--stdin` recommended for values). |
| `get` | Read one secret; **redacted** unless **`--raw`** (materialization). |
| `list` | **Inventory**; safe paths; selective resolve when filters/capabilities require it. |
| `explain` | Inspect one entry; metadata JSON **without** secret plaintext on stdout by default. |
| `run` | **Inject** into child env (**runtime-scoped materialization**); see ADR inject wording. |
| `export` | Bulk **materialization** to stdout formats or an **externalized** encrypted-json **artifact**. |
| `import` | Subcommands: `env`, `file`, `encrypted-json`. |
| `delete` | Remove one entry from store + registry metadata. |

## Configuration

| Command | Purpose |
|---------|---------|
| `config` | `show` / `set` / `unset` / `path` for `defaults.json`. |
| `defaults` | **Alias** for `config` (compatibility). |
| `unlock` | Unlock configured **macOS Keychain** backend. |
| `lock` | Lock configured **macOS Keychain** backend. |
| `init` | Reset `defaults.json` + empty `registry.json` (`-y` to skip confirm). `--backend keychain\|sqlite` chooses the initialized backend; SQLite requires `--dev` / `--sqlite-dev-mode` because plaintext developer storage is a footgun. Subcommand `sqlite` recreates developer DB. |
| `install` | Show `curl \| bash` instructions; supports `--upgrade`, `--repair`, `--safe`, `--verbose`, `--no-uv-download`, `--skip-verify-if-unchanged`, and `user@host` remote SSH install (remote defaults to caller version ref). See [INSTALL.md](INSTALL.md). |
| `info` | Environment status: version, defaults, backend encryption posture, Keychain policy (**macOS** only), SQLite when active or on non-macOS. `--json` for automation. |

## Inventory / diagnostics

| Command | Purpose |
|---------|---------|
| `doctor` | Backend posture, registry checks, metadata drift (JSON). `--install-check` fast post-install gate (no roundtrips). `--acceptance-test` ephemeral CRUD in `__seckit_test__` (keychain + sqlite on macOS; sqlite on Linux). |
| `backend-index` | **Decrypt-safe** index lines from backend-specific safe index support — **not** authority, **not** materialization. |
| `rebuild-index` | Rebuild decrypt-free index from authority (SQLite-oriented repair path). |
| `recover` | Rebuild slim `registry.json` from live store (`migrate recover-registry` is an **alias**). |

## Migration / maintenance

| Command | Purpose |
|---------|---------|
| `migrate` | Subcommands: `dotenv`, `metadata`, `recover-registry` (alias for recover). |
| `service` | `copy` between service scopes. |

## Metadata schema registry (`schema`)

Canonical JSON **field descriptors** for `custom` metadata (`schema_id`). Full detail: [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md).

| Subcommand | Purpose |
|------------|---------|
| `schema list` | Active descriptors; `--all` includes deprecated; `--json` |
| `schema show <schema_id>` | One descriptor |
| `schema export` | Deterministic JSON; `-o` path; optional `--schema-id` |
| `schema install <paths…>` | Merge seed files; `--replace` for field collisions |
| `schema field remove <schema_id> <field>` | Reference-safe field removal |
| `schema deprecate <schema_id>` | Block new assignments |
| `schema remove <schema_id>` | Remove when unused (`--force` with confirmation) |

## Taxonomy registry (`taxonomy`)

Canonical **vocabulary** for `entry_type`, `entry_kind`, and `tags` (separate from `schema_id`). Full detail: [TAXONOMY.md](TAXONOMY.md).

| Subcommand | Purpose |
|------------|---------|
| `taxonomy list` | Table of types/kinds/tags with comments; filter with `--types`, `--kinds`, `--tags`; `--json` |
| `taxonomy show <list> <name>` | One entry (`entry_type`, `entry_kind`, or `tag` + name) |
| `taxonomy export` | Deterministic registry JSON; `-o` path |
| `taxonomy install <paths…>` | Merge vocabulary seeds (add-only); `--accept-normalized`, `--force-raw-name` |

`seckit set` honors taxonomy normalization via `--accept-normalized` and `--force-raw-name` (see [TAXONOMY.md](TAXONOMY.md)).

## Peer / sync

| Command | Purpose |
|---------|---------|
| `identity` | Host keys for signed bundles. |
| `peer` | Trusted peer aliases. |
| `sync` | `export` / `import` / `verify` / `inspect` peer bundles. |

## Advanced / internal

| Command | Purpose |
|---------|---------|
| `helper` | `status` — backend/helper metadata (JSON, no secrets). |
| `journal` | `append` — optional append-only registry event log. |

## File layout (reminder)

Under **`~/.config/seckit/`**: `defaults.json`, `registry.json`, default SQLite `secrets.db`, `identity/` for peer sync. See `seckit --help` epilog and [DEFAULTS.md](DEFAULTS.md).
