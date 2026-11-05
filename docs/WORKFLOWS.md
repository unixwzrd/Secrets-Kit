> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# Workflows — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-11-04

Task-oriented recipes. Command taxonomy and flags: [CLI_REFERENCE.md](CLI_REFERENCE.md). Concepts: [CONCEPTS.md](CONCEPTS.md).

- [Workflows — Secrets Kit](#workflows--secrets-kit)
  - [Local development (encrypted SQLite)](#local-development-encrypted-sqlite)
  - [CI/CD runtime injection](#cicd-runtime-injection)
  - [Backup / export](#backup--export)
  - [Migration from dotenv](#migration-from-dotenv)
  - [Daemon and transport inspection](#daemon-and-transport-inspection)
  - [Backend diagnostics](#backend-diagnostics)
  - [Legacy Keychain migration](#legacy-keychain-migration)
  - [Browse vocabulary (types, kinds, tags)](#browse-vocabulary-types-kinds-tags)
  - [Store an API key with provider metadata](#store-an-api-key-with-provider-metadata)
  - [Appendix: Common operator flow categories](#appendix-common-operator-flow-categories)

## Local development (encrypted SQLite)

1. Confirm `seckit info` reports encrypted SQLite; do not reinitialize an existing store.
2. Store a value using `seckit set --name KEY --stdin --service my-stack --account local-dev`, supplying the value on stdin.
3. Inspect `seckit list --service my-stack --account local-dev` without printing secret values.
4. Launch with `seckit run --service my-stack --account local-dev -- your-command`.

Use `--backend sqlite` only when an explicit backend selection is useful; see [DEFAULTS.md](DEFAULTS.md) for an optional local database path override.

## CI/CD runtime injection

- Prefer **`seckit run`** so secrets **materialize** in the **child** process environment: **injection** is a **runtime-scoped materialization path** that **transfers plaintext into another execution context** (may propagate via env inheritance).  
- Avoid **`get --raw`** in shared logs; scope with **`--service` / `--account` / `--names`**.  
- For automation, prefer **`--json`** on commands that support it over scraping tables.

## Backup / export

- **Encrypted JSON:** `seckit export … --format encrypted-json --out backup.json` (materialization into a file you protect).  
- **Cross-host:** move an encrypted export/import artifact through an operator-selected transfer path, or explicitly admit and authorize peers for encrypted transaction synchronization over LAN P2P or RSS.

## Migration from dotenv

- **`seckit import env`** or **`seckit migrate dotenv`** per [USAGE.md](USAGE.md) pointers and [EXAMPLES.md](EXAMPLES.md).  
- Prefer rewriting dotenv to placeholders after import when consolidating on `seckit run`.

## Daemon and transport inspection

- **`seckit daemon status`** checks whether the local daemon is reachable and reports runtime metadata.
- **`seckit daemon ping`** round-trips through the Unix socket and prints `pong` when reachable.
- **`seckit status`** summarizes daemon reachability, datastore posture, transaction lifecycle counts, envelope lifecycle counts, peer eligibility, and recent synchronization timestamps.
- **`seckit envelope list`** and **`seckit envelope show <envelope_id>`** inspect persisted outbound delivery artifacts.
- **`seckit transaction list`** and **`seckit transaction show <transaction_id>`** inspect recorded SQLite transactions without replaying, repairing, or starting the daemon.

## Backend diagnostics

- **`seckit doctor`** for JSON posture.  
- **`seckit status`** for current operational health and lifecycle counts.
- **`seckit info`** for version, defaults, and backend status.
- **`seckit envelope ...`** and **`seckit transaction ...`** for read-only SQLite transport/history inspection.

## Legacy Keychain migration

- On macOS, `seckit migrate keychain --service SERVICE --account ACCOUNT` performs an explicit dry-run inventory without retrieving secret values; it can run before SQLite initialization. Review the inventory, initialize an encrypted SQLite target if needed without recreating an existing database, then repeat with `--apply`. Only known, unambiguous legacy records are supported; unsupported or ambiguous records fail closed. Original Keychain records and existing SQLite data are preserved. Migrated values are local-only unless synchronization is separately authorized; a later authorization can queue existing migrated transactions without rewriting their values. See [SECURITY_MODEL.md](SECURITY_MODEL.md#legacy-keychain-migration).

- To revoke an admitted peer locally, run `seckit peer revoke NODE_ID`. This records revocation through the transaction pipeline and denies future inbound transactions, new outbound envelopes, queued delivery, and reconnection at this node. Revocation is local to this node and cannot retract a payload already handed to the transport. `seckit peer reject NODE_ID` remains for pending admission requests.

## Browse vocabulary (types, kinds, tags)

Inspect what the store knows before `set` / import:

```bash
seckit taxonomy list
seckit taxonomy list --kinds
seckit taxonomy show entry_kind api_key
```

Add custom kinds (for example `jwt`, `oauth_refresh_token`) with seed JSON and `seckit taxonomy install`. See [TAXONOMY.md](TAXONOMY.md).

## Store an API key with provider metadata

Use kind `api_key`, not the provider name as kind:

```bash
seckit set --name OPENAI_API_KEY --stdin \
  --kind api_key --meta provider=openai \
  --service my-stack --account local-dev
```

Field definitions come from the schema registry (`builtin.secret.api_key`). List schemas with `seckit schema list`. See [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md).

---

## Appendix: Common operator flow categories

Use this map when deciding where to read first:

| Category                      | Primary commands / docs                                |
| ----------------------------- | ------------------------------------------------------ |
| Local development             | `set`, `list`, `run`, [QUICKSTART.md](QUICKSTART.md)   |
| CI/CD injection               | `run`, [CONCEPTS.md](CONCEPTS.md)                      |
| Backup / export               | `export`, encrypted JSON artifacts you move explicitly |
| Dotenv migration              | `import`, `migrate dotenv`                             |
| Daemon / transport inspection | `daemon`, `envelope`, `transaction`                    |
| Backend diagnostics           | `doctor`, `info`, `envelope`, `transaction`            |
| Legacy Keychain migration     | `migrate keychain` on macOS with an explicit scope     |
