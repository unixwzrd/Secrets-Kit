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

**`~/.config/seckit/config.json`:** merged after `defaults.json` only for keys missing from `defaults.json`. Unsupported `backend` values are **not** rewritten automatically—`seckit` fails during defaults application until you set `backend` to `keychain` or `sqlite` (or use `seckit doctor --fix-defaults` to remove an invalid `backend` key from `defaults.json` only).

**`seckit list`:** lists entries in `registry.json`, not every generic password in Keychain Access. Items must have been created/registered through seckit (or metadata imported) to appear.

## Environment defaults

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
export SECKIT_DEFAULT_TYPE=secret
export SECKIT_DEFAULT_KIND=api_key
export SECKIT_DEFAULT_TAGS=primary
export SECKIT_DEFAULT_ROTATION_DAYS=90
export SECKIT_DEFAULT_ROTATION_WARN_DAYS=14
export SECKIT_DEFAULT_BACKEND=keychain
```

Then:

```bash
seckit list
seckit run -- python3 app.py
```

That is usually the best fit for an interactive shell session or a one-off runtime launch.

### SQLite backend environment (`--backend sqlite`)

Current SQLite support is development-oriented local storage only.

SQLite encryption-at-rest is **not implemented yet**.

Using SQLite currently requires explicit developer-mode acknowledgement:

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1
```

`SECKIT_SQLITE_PLAINTEXT_DEBUG=1` remains accepted for test/debug compatibility.

or:

```bash
seckit set --backend sqlite --sqlite-dev-mode ...
```

SQLite developer mode requires `--sqlite-dev-mode` or `SECKIT_SQLITE_DEVELOPER_MODE=1` (no legacy alias flags).

When SQLite developer mode is enabled, `seckit` emits one warning per process because secret material is not yet encrypted at rest.

Optional SQLite database location override:

```bash
export SECKIT_SQLITE_PATH=/path/to/seckit.sqlite
```

The SQLite backend is currently:
- local-only
- single-process/single-writer oriented
- standalone
- independent from daemon/P2P/RSS behavior

Future encryption design is intentionally undecided and must not assume:
- environment-variable passphrases
- vault-password workflows
- Keychain-managed wrapping keys
- daemon-managed unlock semantics
- transport-coupled encryption

### Where the SQLite file lives

| What | Path or source |
|------|----------------|
| Default file | `~/.config/seckit/seckit.sqlite` |
| Override order | `SECKIT_SQLITE_PATH` → `sqlite_path` in `defaults.json` → default path above |

The directory `~/.config/seckit` is created on demand with restricted permissions when registry/defaults/SQLite state is first written.

SQLite files are intended for local standalone operation. Directly syncing live SQLite databases through cloud file sync, network shares, or similar tooling is not supported and may corrupt the database or create conflicting writes.

Cross-machine movement should use explicit export/import flows or future synchronization tooling.

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
  "backend": "keychain",
  "sqlite_path": "/path/to/seckit.sqlite"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## CLI: `seckit config`

Write the same keys without editing JSON by hand:

```bash
seckit config path
seckit config show
seckit config set backend keychain
seckit config set service my-stack
seckit config unset backend
```

Merged view (`defaults.json` + `config.json` + `SECKIT_DEFAULT_*` env):

```bash
seckit config show --effective
```

Allowed keys: `service`, `account`, `backend`, `sqlite_path`, `type`, `kind`, `tags`, `default_rotation_days`, `rotation_warn_days`.

See:

```bash
seckit config set -h
```

Secrets and raw secret material must never be stored in `defaults.json`.

## Notes

- Defaults are optional.
- Secrets never belong in config files or shell defaults.
- `service` must be explicit or configured when a command needs a service scope.
- `account` falls back to the current OS user when not explicit or configured.
- Backend identity is separate from security posture.
- Canonical storage backends are:
  - `keychain`
  - `sqlite`
- Current Keychain backend uses the macOS `security` CLI and platform Keychain storage.
- Current SQLite backend requires explicit developer-mode acknowledgement until encryption-at-rest lands.
- Future P2P/RSS work represents synchronization/transport layers over local storage, not authoritative remote secret stores.
- Use defaults for repeated operational scope information, not for secret material.

[Back to README](../README.md)

**Updated**: 2026-05-25
