# Defaults

Defaults are here to make repeated daily use less noisy. If you are always working in the same local scope, you should not have to type `--service` and `--account` every time.

Resolution order:

1. Explicit CLI flags
2. `SECKIT_DEFAULT_*` environment variables
3. `~/.config/seckit/defaults.json`
4. current OS user for `account` only

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
  "backend": "secure"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## CLI: `seckit config`

Write the same keys without editing JSON by hand:

```bash
seckit config path
seckit config show
seckit config set backend icloud-helper
seckit config set service my-stack
seckit config unset backend
```

Merged view (defaults file + legacy `config.json` + `SECKIT_DEFAULT_*` env):

```bash
seckit config show --effective
```

Allowed keys: `service`, `account`, `backend`, `type`, `kind`, `tags`, `default_rotation_days`, `rotation_warn_days`. See `seckit config set -h`.

## Notes

- Defaults are optional.
- Secrets never belong in the config file.
- `service` must be explicit or configured when a command needs a service scope.
- `account` falls back to the current OS user when it is not explicit or configured.
- `backend` selects the secret backend. **`secure`** (alias **`local`**) uses the macOS **`security`** CLI (including custom `--keychain` paths). **`icloud-helper`** (alias **`icloud`**) uses the entitled native helper for synchronizable Keychain items.
- The **`seckit`** CLI does not compile the helper; release builds use **`scripts/build_bundled_helper_for_wheel.sh`** (see [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md)).
- Ad-hoc or wrongly signed binaries that carry `keychain-access-groups` may be killed by macOS; use published wheels or a maintainer-signed helper.
- Use defaults for repeated scope information, not for raw secret values.

[Back to README](../README.md)

**Updated**: 2026-05-02
