# Defaults

Defaults are here to make repeated daily use less noisy. If you are always working in the same local scope, you should not have to type `--service` and `--account` every time.

Resolution order:

1. Explicit CLI flags
2. `SECKIT_DEFAULT_*` environment variables
3. `~/.config/seckit/config.json`

## Environment defaults

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
export SECKIT_DEFAULT_TYPE=secret
export SECKIT_DEFAULT_KIND=api_key
export SECKIT_DEFAULT_TAGS=primary
```

Then:

```bash
seckit list
seckit export --format shell --all
```

That is usually the best fit for an interactive shell session or a one-off runtime launch.

## Config file defaults

Create `~/.config/seckit/config.json`:

```json
{
  "service": "my-stack",
  "account": "local-dev",
  "type": "secret",
  "kind": "api_key",
  "tags": "primary"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## Notes

- Defaults are optional.
- Secrets never belong in the config file.
- Use defaults for repeated scope information, not for raw secret values.

[Back to README](../README.md)
