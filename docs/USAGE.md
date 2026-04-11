# Usage & Workflows

**Created**: 2026-04-11  
**Updated**: 2026-04-11

This guide shows the most common workflows without OpenClaw-specific assumptions.

## Store a secret

```bash
echo 'sk-live' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service openclaw --account miafour
```

## Read a secret (redacted)

```bash
seckit get --name OPENAI_API_KEY --service openclaw --account miafour
```

## Read a secret (raw)

```bash
seckit get --name OPENAI_API_KEY --raw --service openclaw --account miafour
```

## List inventory

```bash
seckit list --service openclaw --account miafour
```

Filter stale entries (older than 90 days):

```bash
seckit list --service openclaw --account miafour --stale 90
```

## Export for runtime

```bash
eval "$(seckit export --format shell --service openclaw --account miafour --all)"
```

## Import from dotenv

```bash
seckit import env --dotenv ~/.openclaw/.env --service openclaw --account miafour --allow-overwrite
```

## Migrate dotenv and rewrite placeholders

```bash
seckit migrate dotenv --dotenv ~/.openclaw/.env --service openclaw --account miafour --yes --archive ~/.openclaw/.env.bak
```

## Explain an entry (metadata only)

```bash
seckit explain --name OPENAI_API_KEY --service openclaw --account miafour
```

[Back to README](../README.md)
