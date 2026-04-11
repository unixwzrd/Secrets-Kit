# Defaults

**Created**: 2026-04-11  
**Updated**: 2026-04-11

Defaults reduce command length for common operations.

Resolution order:

1. Explicit CLI flags
2. `SECKIT_DEFAULT_*` environment variables
3. `~/.config/seckit/config.json`

## Environment defaults

```bash
export SECKIT_DEFAULT_SERVICE=openclaw
export SECKIT_DEFAULT_ACCOUNT=miafour
export SECKIT_DEFAULT_TYPE=secret
export SECKIT_DEFAULT_KIND=api_key
export SECKIT_DEFAULT_TAGS=prod,primary
```

Then:

```bash
seckit list
seckit export --format shell --all
```

## Config file defaults

Create `~/.config/seckit/config.json`:

```json
{
  "service": "openclaw",
  "account": "miafour",
  "type": "secret",
  "kind": "api_key",
  "tags": "prod,primary"
}
```

## Notes

- Defaults are optional.
- Secrets never belong in the config file.

[Back to README](../README.md)
