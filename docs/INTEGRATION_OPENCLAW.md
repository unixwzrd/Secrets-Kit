# OpenClaw Integration

**Created**: 2026-03-01  
**Updated**: 2026-03-01

## Recommended flow

```bash
eval "$(secrets-kit export --format shell --service openclaw --account miafour --all)"
~/bin/openclaw-stack restart all
```

## Migration from dotenv

```bash
secrets-kit migrate dotenv --dotenv ~/.openclaw/.env --service openclaw --account miafour --yes --archive ~/.openclaw/.env.bak
```

This imports values into Keychain and rewrites `.env` values to `${VAR}` placeholders.

[Back to README](../README.md)
