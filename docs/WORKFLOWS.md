# Workflows — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-05-05

Task-oriented recipes. Command taxonomy and flags: [CLI_REFERENCE.md](CLI_REFERENCE.md). Concepts: [CONCEPTS.md](CONCEPTS.md).

## Local development (macOS + Keychain)

1. `seckit keychain-status` and `seckit unlock` if needed.  
2. `echo 'value' \| seckit set --name KEY --stdin --service my-stack --account local-dev …`  
3. `seckit list --service my-stack --account local-dev`  
4. `seckit run --service my-stack --account local-dev -- your-command`

SQLite portable loop: set **`--backend sqlite`** and passphrase / unlock env per [DEFAULTS.md](DEFAULTS.md).

## CI/CD runtime injection

- Prefer **`seckit run`** so secrets **materialize** in the **child** process environment: **injection** is a **runtime-scoped materialization path** that **transfers plaintext into another execution context** (may propagate via env inheritance).  
- Avoid **`get --raw`** in shared logs; scope with **`--service` / `--account` / `--names`**.  
- For automation, prefer **`--json`** on commands that support it over scraping tables. See [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Backup / export

- **Encrypted JSON:** `seckit export … --format encrypted-json --out backup.json` (materialization into a file you protect).  
- **Cross-host:** combine encrypted export with your file transfer; see [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md).

## Migration from dotenv

- **`seckit import env`** or **`seckit migrate dotenv`** per [USAGE.md](USAGE.md) pointers and [EXAMPLES.md](EXAMPLES.md).  
- Prefer rewriting dotenv to placeholders after import when consolidating on `seckit run`.

## Peer sync

- **`seckit identity init`**, **`peer add`**, **`sync export` / `sync import`**. Full story: [PEER_SYNC.md](PEER_SYNC.md).

## Recovery after registry loss

- Secrets still in backend: **`seckit recover`** (or **`migrate recover-registry`**).  
- Preview: **`--dry-run`**; machine report: **`--json`**.  
- See [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) for what rebuild means vs authority.

## Backend diagnostics

- **`seckit doctor`** for JSON posture.  
- **`seckit backend-index`** for **decrypt-safe** index rows (diagnostic, not secrets).  
- **`seckit rebuild-index`** when SQLite index repair is required.

## Disposable testing keychains

- Tests and operators may use temporary keychains; patterns in [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) and scripts under `scripts/`.

---

## Appendix: Common operator flow categories

Use this map when deciding where to read first:

| Category | Primary commands / docs |
|----------|-------------------------|
| Local development | `set`, `list`, `run`, [QUICKSTART.md](QUICKSTART.md) |
| CI/CD injection | `run`, [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) (materialization) |
| Backup / export | `export`, [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) |
| Dotenv migration | `import`, `migrate dotenv` |
| Peer sync | `identity`, `peer`, `sync`, [PEER_SYNC.md](PEER_SYNC.md) |
| Registry recovery | `recover`, `migrate recover-registry` |
| Backend diagnostics | `doctor`, `backend-index`, `rebuild-index` |
| Disposable keychains | [CROSS_HOST_CHECKLIST.md](CROSS_HOST_CHECKLIST.md), validation docs |
