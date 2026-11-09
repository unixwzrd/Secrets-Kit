> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# CLI reference — `seckit`

**Created**: 2026-05-07  
**Updated**: 2026-11-07

Command list aligned with the current `seckit --help` output. For mental models and policies, see [CONCEPTS.md](CONCEPTS.md).

- [CLI reference — `seckit`](#cli-reference--seckit)
  - [Output conventions](#output-conventions)
  - [Everyday operations](#everyday-operations)
  - [Configuration](#configuration)
  - [Diagnostics and lifecycle](#diagnostics-and-lifecycle)
  - [Migration / maintenance](#migration--maintenance)
  - [Metadata schema registry (`schema`)](#metadata-schema-registry-schema)
  - [Taxonomy registry (`taxonomy`)](#taxonomy-registry-taxonomy)
  - [Internal command](#internal-command)
  - [File layout (reminder)](#file-layout-reminder)

## Output conventions

- **Operators:** default tables and prose may change between releases.
- **Automation:** prefer **`--json`** / structured fields where offered; treat those as **more stable** than human formatting.

## Everyday operations

| Command | Purpose |
| --- | --- |
| `set` | Store or update one secret value (`--stdin` recommended for values). |
| `get` | Read one stored secret value; **redacted** unless **`--raw`** (materialization). |
| `list` | List stored metadata entries, redacted by default. |
| `explain` | Show resolved metadata for a stored entry without printing secret plaintext. |
| `run` | Resolve secrets in the parent process and exec a child command. |
| `export` | Export selected secrets for runtime use (`shell`, placeholder `dotenv`, `encrypted-json`, or portable `age`). Shell and encrypted output support protected new-file `--out`; age requires an installed executable and `--recipient`. |
| `import` | Subcommands: `env`, `file`, `encrypted-json`. |
| `delete` | Delete one stored secret and its metadata. |
| `service` | Subcommand: `copy` between service scopes in SQLite. |

## Configuration

| Command | Purpose |
| --- | --- |
| `config` | `show` / `set` / `unset` / `path` for `defaults.json`. |
| `init` | Initialize customer defaults and registry with SQLite and encrypted storage; no security-mode selection is required. `init sqlite` recreates the standalone SQLite DB. |
| `install` | Install, upgrade, repair, or show install instructions. Supports local and `@host` / `user@host` remote install targets. See [INSTALL.md](INSTALL.md). |
| `upgrade` | Check for or explicitly install a newer release through the preserving installer. `service install\|status\|uninstall` manages the optional same-user daily checker. See [INSTALL.md](INSTALL.md). |
| `info` | Show version, defaults, and backend status. `--json` for automation. |

## Diagnostics and lifecycle

| Command | Purpose |
| --- | --- |
| `status` | Concise operator health summary across daemon reachability, SQLite datastore posture, transaction lifecycle counts, envelope lifecycle counts, Peer Registry eligibility, and recent synchronization timestamps. Use `--json` for stable automation fields. |
| `doctor` | Backend posture, catalog checks, backend metadata validation. `--install-check` is a fast post-install gate. |
| `daemon` | Manage local `seckitd`: `start`, `stop`, `restart`, `status`, `ping`, and `service install\|uninstall\|status`. `daemon run` is the foreground service-manager entry point. |
| `envelope` | Read-only inspection of persisted outbound envelopes: `list`, `show <envelope_id>`. |
| `peer` | SQLite peer admission: `request`, `import-request`, `accept`, `import-acceptance`, `reject`, `revoke`, `export-identity`, `list`, `show`. `peer reject` applies only to pending requests; `peer revoke NODE_ID` locally ends an active admission, denies queued work, and does not retract already delivered secrets. `peer accept NODE_ID --service SERVICE --account ACCOUNT` authorizes only that named scope. Both names are required and cannot be combined with ID or wildcard options. With no scope, acceptance grants authorization mode `none`; repeated `--service-group-id` supplies an explicit allow-list; `--all-service-groups` is an explicit wildcard and cannot be combined with scoped options. |
| `transaction` | Read-only inspection of persisted transactions: `list`, `show <transaction_id>`. |

`status`, `info`, and `doctor` intentionally answer different questions: `status` summarizes current operational health and lifecycle counts; `info` reports version/default/backend configuration; `doctor` performs validation and the supported install check.

The daemon is authoritative for `status`. If its response is unavailable, including a timeout or invalid response, the CLI reports `UNKNOWN`, JSON `daemon.running: null`, an error and a nonzero exit status. Failed communication does not establish that the daemon stopped. The CLI does not fall back to reading SQLite.

`daemon service install` creates and starts a same-user managed service. macOS uses `~/Library/LaunchAgents/net.unixwzrd.secrets-kit.daemon.plist`; Linux uses `~/.config/systemd/user/secrets-kit-daemon.service`. Successful RSS enrollment, RSS configuration, and RSS identity import install the service automatically. Linux reports when administrator-enabled user lingering is required but never escalates privileges. MCP remains fail-closed when the daemon is unavailable.

`rss enroll` and `rss configure` retain local configuration and start the managed daemon independently of remote authorization. Their JSON output distinguishes `configured` from `rss_authenticated`; exit zero requires the daemon to have observed an authenticated RSS relay. Pending or unavailable authorization returns nonzero without stopping local operation. A verified capacity rejection reports `device_capacity_exhausted`; ask the operator to increase capacity or explicitly deprovision a device. `seckit status --json` includes `rss.configured` and `rss.authenticated_relays` from the daemon's latest authentication check, not a guarantee of continuous relay availability.

## Migration / maintenance

### Non-SSH peer invitations

Production 2.0.3 uses the supported [SSH peer installation and enrollment](INSTALL.md#remote-install) path. The optional persistent peer-invitation mailbox is not enabled in production. A peer invitation is distinct from the retired beta Checkout invitation; ordinary paid Checkout and enrollment require no beta invitation. Where a mailbox is configured, independent peer onboarding uses an encrypted, short-lived invitation without SSH or manual request/acceptance files; see [INSTALL.md](INSTALL.md#independent-installation-without-ssh) for prerequisites and the complete procedure. On an initialized source, run `seckit peer invite --service SERVICE --account ACCOUNT`; add `--rss` only when that user has the separate billing-owner credential and intends to authorize the new device's RSS enrollment. The code is displayed only on an interactive terminal and must be delivered privately. On the initialized target, run `seckit peer join`, enter the code at its hidden prompt and confirm the source identity and scope. On the source, run `seckit peer approve SESSION_ID`, compare the target's fingerprints with that user and confirm. On the target, run `seckit peer join --resume SESSION_ID` to apply the approval; rerun source approval to observe the target's signed completion. Use the non-secret session ID, not the private invitation code, for approval and resume commands. A retained source offer can be retried with `seckit peer invite --resume SESSION_ID`; retrying never creates a new code or extends its original 15-minute deadline.

The invitation grants only the named service/account scope. With `--rss`, the target keeps its own private RSS key and receives an enrollment token bound to that key and connection ID. A full subscription leaves approval pending; the billing owner uses `seckit rss billing units N` to preview and authorize an increase, then retries approval after payment is verified and paid capacity is available. The mailbox cannot authorize a peer, bill an account or read secrets. Peer admission, local RSS configuration, authenticated relay enrollment and a connected route remain separate results. A successful invitation does not prove network reachability; inspect `seckit status` before synchronization testing.

| Command | Purpose |
| --- | --- |
| `migrate` | Subcommands: `dotenv` and explicitly invoked macOS `keychain` inventory/import into encrypted SQLite. The retained `metadata` command fails closed because registry inventory migration is unsupported. Keychain migration is dry-run by default and never deletes original records or authorizes peer synchronization without an explicit option. |

## Metadata schema registry (`schema`)

Canonical JSON **field descriptors** for `custom` metadata (`schema_id`). Full detail: [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md).

Schema descriptors live in the local catalog; normal operations use SQLite. Legacy Keychain is not an operational schema backend.

| Subcommand | Purpose |
| --- | --- |
| `schema list` | List schema descriptors from the store. |
| `schema show <schema_id>` | Show one schema descriptor. |
| `schema export` | Export canonical schema registry JSON. |
| `schema install <paths...>` | Merge seed schema JSON into the canonical registry. |
| `schema field ...` | Schema field operations. |
| `schema deprecate <schema_id>` | Mark a schema id as deprecated. |
| `schema remove <schema_id>` | Remove a schema id from the registry. |

## Taxonomy registry (`taxonomy`)

Canonical **vocabulary** for `entry_type`, `entry_kind`, and `tags` (separate from `schema_id`). Full detail: [TAXONOMY.md](TAXONOMY.md).

Taxonomy operations use SQLite. Legacy Keychain is not an operational taxonomy backend.

| Subcommand | Purpose |
| --- | --- |
| `taxonomy list` | List vocabulary entries (types, kinds, tags) with comments; supports `--types`, `--kinds`, `--tags`, and `--json`. |
| `taxonomy show <list> <name>` | Show one vocabulary entry (`entry_type`, `entry_kind`, or `tag` + name). |
| `taxonomy export` | Export taxonomy registry JSON. |
| `taxonomy install <paths...>` | Merge taxonomy seed JSON files. |

`seckit set` honors taxonomy normalization via `--accept-normalized` and `--force-raw-name` (see [TAXONOMY.md](TAXONOMY.md)).

## Internal command

| Command | Purpose |
| --- | --- |
| `internal apply-envelope --stdin` | Internal/compatibility transaction-envelope handoff owned by the runtime, not by `seckit daemon`. This is not an operator workflow command. |
| `internal deliver-pending` | Hidden runtime-owned delivery worker for due persisted envelopes. The daemon may schedule it, but it is not an operator workflow command and the daemon does not inspect SQLite state. |

## Programmatic agent access

`seckit-mcp [--policy PATH]` starts the read-only stdio MCP server for same-user local agent clients. It never opens a network listener. Startup requires a valid owner-only fixed-scope policy; the default is `~/.config/seckit/mcp-policy.json`.

The policy pins one backend, service, account, metadata-name allowlist, and explicit-retrieval allowlist. Callers cannot override that scope. Metadata is filtered to the policy. `seckit_get_secret` fails closed unless the requested name is present in `retrieval_names`; successful retrieval materializes plaintext to the MCP client. Keep the retrieval allowlist empty unless model-visible retrieval is specifically authorized.

## File layout (reminder)

Under **`~/.config/seckit/`**: `defaults.json`, optional `config.json`, `registry.json`, the default SQLite database `seckit.sqlite`, `node-identity.key`, and `sqlite-storage.key` for encrypted SQLite datastores.

The daemon runtime directory defaults to **`~/.local/share/seckit/runtime`** and contains `seckitd.json`, `seckitd.sock`, and startup lock state. See [DEFAULTS.md](DEFAULTS.md).

The development lab root defaults to **`~/.config/seckit-lab/`**. Each lab node owns independent config, SQLite, runtime, logs, sockets, TCP port, and node identity paths. The lab is orchestration only; the daemon transports opaque envelopes and the runtime owns protocol processing. Default lab admission uses explicit allow-list authorization for service `lab-service` and account `local`.
