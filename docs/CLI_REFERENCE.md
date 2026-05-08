# CLI reference — `seckit`

**Created**: 2026-05-07  
**Updated**: 2026-05-05

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
| `keychain-status` | Keychain accessibility / policy (**macOS**). |
| `version` | Version; `--info` / `--json` for diagnostics (no secrets). |

## Inventory / diagnostics

| Command | Purpose |
|---------|---------|
| `doctor` JSON diagnostics | Backend posture, registry checks, capabilities (output is JSON-oriented). |
| `backend-index` | **Decrypt-safe** index lines via `BackendStore.iter_index()` — **not** authority, **not** materialization. |
| `rebuild-index` | Rebuild decrypt-free index from authority (SQLite-oriented repair path). |
| `recover` | Rebuild slim `registry.json` from live store (`migrate recover-registry` is an **alias**). |

## Migration / maintenance

| Command | Purpose |
|---------|---------|
| `migrate` | Subcommands: `dotenv`, `metadata`, `recover-registry` (alias for recover). |
| `service` | `copy` between service scopes. |

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
