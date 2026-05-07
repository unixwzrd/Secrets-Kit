# Defaults

- [Defaults](#defaults)
  - [Environment defaults](#environment-defaults)
    - [SQLite backend environment (`--backend sqlite`)](#sqlite-backend-environment---backend-sqlite)
    - [Where the SQLite file lives](#where-the-sqlite-file-lives)
  - [Config file defaults](#config-file-defaults)
  - [CLI: `seckit config`](#cli-seckit-config)
  - [Notes](#notes)


Defaults are here to make repeated daily use less noisy. If you are always working in the same local scope, you should not have to type `--service` and `--account` every time.

Resolution order:

1. Explicit CLI flags
2. `SECKIT_DEFAULT_*` environment variables
3. `~/.config/seckit/defaults.json`
4. current OS user for `account` only

**Legacy `~/.config/seckit/config.json`:** merged after `defaults.json` only for keys missing from `defaults.json`. If `backend` is an old **`icloud`** / **`icloud-helper`** value, Secrets-Kit rewrites that file to **`secure`** on read when permissions allow (same for `defaults.json`).

**`seckit list`:** lists entries in **`registry.json`**, not every generic password in Keychain Access. Items must have been created/registered through seckit (or metadata imported) to appear.

## Environment defaults

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
export SECKIT_DEFAULT_TYPE=secret
export SECKIT_DEFAULT_KIND=api_key
export SECKIT_DEFAULT_TAGS=primary
export SECKIT_DEFAULT_ROTATION_DAYS=90
export SECKIT_DEFAULT_ROTATION_WARN_DAYS=14
export SECKIT_DEFAULT_BACKEND=secure
```

Then:

```bash
seckit list
seckit run -- python3 app.py
```

That is usually the best fit for an interactive shell session or a one-off runtime launch.

### SQLite backend environment (`--backend sqlite`)

Secret **values** are encrypted with **PyNaCl** (libsodium). Set a **passphrase** (non-interactive automation):

```bash
export SECKIT_SQLITE_PASSPHRASE='your-strong-passphrase'
```

Optional **database path** (default `~/.config/seckit/secrets.db` if unset):

```bash
export SECKIT_SQLITE_DB=/path/to/secrets.db
```

**Unlock mode** (how the SQLite master key is obtained):

- **`SECKIT_SQLITE_UNLOCK=passphrase`** (default): Argon2id KDF from `SECKIT_SQLITE_PASSPHRASE` (classic vault rows with no wrapped DEK).
- **`SECKIT_SQLITE_UNLOCK=keychain`** (macOS): KEK stored as a generic password in the Keychain; vault metadata holds a wrapped DEK. Set **`SECKIT_SQLITE_KEK_KEYCHAIN`** to a keychain file, or use **`seckit ... --backend sqlite --keychain /path/to.keychain-db`** (same flag as secure, different meaning: KEK keychain, not the DB path).

Optional **origin host** stored on each write (default: machine hostname):

```bash
export SECKIT_ORIGIN_HOST=my-laptop
```

The SQLite file is **local only**—no sync, daemon, or relay is provided by this tool.

### Where the SQLite file lives

| What | Path or source |
|------|----------------|
| **Default file** | `~/.config/seckit/secrets.db` (same directory as `registry.json` and `defaults.json`) |
| **Override order** | `--db` → **`SECKIT_SQLITE_DB`** → **`sqlite_db`** in `defaults.json` → default path above |

The directory `~/.config/seckit` is created on demand with restricted permissions when you first write registry or defaults.

**Development / throwaway vault:** run **`bash scripts/sqlite_dev_seed.sh --force`**. It imports **`fixtures/synthetic-sample.env`** (fake data only) into **`~/.config/seckit/secrets-dev.db`** with passphrase **`seckit-dev-synthetic-vault`** unless you set **`SECKIT_SQLITE_PASSPHRASE`**. **`--account`** defaults to your OS login; **`--service`** defaults to **`synthetic`**.

**iCloud / synced folders:** moving **`secrets.db`** through Drive or iCloud is not supported; you risk corruption or conflicting writes. Prefer explicit **export/import** or [PEER_SYNC.md](PEER_SYNC.md) bundles for cross-machine transfer.

## Config file defaults

Create `~/.config/seckit/defaults.json`:

```json
{
  "service": "my-stack",
  "account": "local-dev",
  "type": "secret",
  "kind": "api_key",
  "tags": "primary",
  "default_rotation_days": 90,
  "rotation_warn_days": 14,
  "backend": "secure",
  "sqlite_db": "/path/to/secrets.db"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## CLI: `seckit config`

Write the same keys without editing JSON by hand:

```bash
seckit config path
seckit config show
seckit config set backend secure
seckit config set service my-stack
seckit config unset backend
```

Merged view (defaults file + legacy `config.json` + `SECKIT_DEFAULT_*` env):

```bash
seckit config show --effective
```

Allowed keys: `service`, `account`, `backend`, `sqlite_db`, `type`, `kind`, `tags`, `default_rotation_days`, `rotation_warn_days`. See `seckit config set -h`.

Passphrases and raw secrets **must not** be stored in `defaults.json`; use `SECKIT_SQLITE_PASSPHRASE` or an interactive prompt for the SQLite backend.

## Notes

- Defaults are optional.
- Secrets never belong in the config file.
- `service` must be explicit or configured when a command needs a service scope.
- `account` falls back to the current OS user when it is not explicit or configured.
- `backend` selects the storage backend: **`secure`** (alias **`local`**, macOS **`security`** CLI) or **`sqlite`** (encrypted local file). For cross-host moves use **`secure`** or **`sqlite`** plus **export/import** or [PEER_SYNC.md](PEER_SYNC.md) bundles—not live Keychain replication.
- Use defaults for repeated scope information, not for raw secret values.

[Back to README](../README.md)

**Updated**: 2026-05-07
