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
export SECKIT_DEFAULT_BACKEND=local
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
  "backend": "local"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## Notes

- Defaults are optional.
- Secrets never belong in the config file.
- `service` must be explicit or configured when a command needs a service scope.
- `account` falls back to the current OS user when it is not explicit or configured.
- `backend` selects the active secret backend. Use `local` for the normal macOS keychain path.
- `icloud` uses the native Swift helper and synchronizable Keychain item APIs.
- `seckit helper install-local` builds the universal helper for both Apple Silicon and Intel macOS.
- `seckit helper install-icloud` remains as a compatibility alias, but `install-local` is the canonical helper install command.
- Use defaults for repeated scope information, not for raw secret values.

[Back to README](../README.md)

**Updated**: 2026-04-28
