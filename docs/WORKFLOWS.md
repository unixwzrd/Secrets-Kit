# Workflows — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-07-16

Task-oriented recipes. Command taxonomy and flags: [CLI_REFERENCE.md](CLI_REFERENCE.md). Concepts: [CONCEPTS.md](CONCEPTS.md).

- [Workflows — Secrets Kit](#workflows--secrets-kit)
  - [Local development (macOS + Keychain)](#local-development-macos--keychain)
  - [CI/CD runtime injection](#cicd-runtime-injection)
  - [Backup / export](#backup--export)
  - [Migration from dotenv](#migration-from-dotenv)
  - [Daemon and transport inspection](#daemon-and-transport-inspection)
  - [Backend diagnostics](#backend-diagnostics)
  - [Disposable testing keychains](#disposable-testing-keychains)
  - [Browse vocabulary (types, kinds, tags)](#browse-vocabulary-types-kinds-tags)
  - [Store an API key with provider metadata](#store-an-api-key-with-provider-metadata)
  - [Appendix: Common operator flow categories](#appendix-common-operator-flow-categories)

## Local development (macOS + Keychain)

1. `seckit info` and `seckit unlock` if needed (unlock is **macOS** Keychain only).  
2. `echo 'value' \| seckit set --name KEY --stdin --service my-stack --account local-dev …`  
3. `seckit list --service my-stack --account local-dev`  
4. `seckit run --service my-stack --account local-dev -- your-command`

SQLite local-storage loop: use **`--backend sqlite`** and optionally `SECKIT_SQLITE_PATH` per [DEFAULTS.md](DEFAULTS.md).

## CI/CD runtime injection

- Prefer **`seckit run`** so secrets **materialize** in the **child** process environment: **injection** is a **runtime-scoped materialization path** that **transfers plaintext into another execution context** (may propagate via env inheritance).  
- Avoid **`get --raw`** in shared logs; scope with **`--service` / `--account` / `--names`**.  
- For automation, prefer **`--json`** on commands that support it over scraping tables.

## Backup / export

- **Encrypted JSON:** `seckit export … --format encrypted-json --out backup.json` (materialization into a file you protect).  
- **Cross-host today:** combine encrypted export/import with your own file transfer. The current source also contains local daemon/envelope synchronization and local lab orchestration for isolated localhost peers, but that daemon implementation is under architectural boundary review. Cross-host P2P, peer discovery, RSS synchronization, and peer-bundle operator commands are not current CLI workflows.

## Migration from dotenv

- **`seckit import env`** or **`seckit migrate dotenv`** per [USAGE.md](USAGE.md) pointers and [EXAMPLES.md](EXAMPLES.md).  
- Prefer rewriting dotenv to placeholders after import when consolidating on `seckit run`.

## Daemon and transport inspection

- **`seckit daemon status`** checks whether the local daemon is reachable and reports runtime metadata.
- **`seckit daemon ping`** round-trips through the Unix socket and prints `pong` when reachable.
- **`seckit status`** asks the local daemon for current operational health, including identity, endpoint, daemon lifecycle, peer authorization/reachability, routing gaps, transaction/envelope counters, and synchronization timestamps. It never reads SQLite directly.
- **`seckit envelope list`** and **`seckit envelope show <envelope_id>`** inspect persisted outbound delivery artifacts.
- **`seckit transaction list`** and **`seckit transaction show <transaction_id>`** inspect recorded SQLite transactions without replaying, repairing, or starting the daemon.

## Backend diagnostics

- **`seckit doctor`** for JSON posture.  
- **`seckit status`** for current operational health and lifecycle counts from the daemon.
- **`seckit info`** for version, defaults, and backend status.
- **`seckit envelope ...`** and **`seckit transaction ...`** for read-only SQLite transport/history inspection.

## Disposable testing keychains

- Tests and operators may use temporary keychains; see test fixtures and scripts under `scripts/`.

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
| Disposable keychains          | test fixtures and scripts under `scripts/`             |
