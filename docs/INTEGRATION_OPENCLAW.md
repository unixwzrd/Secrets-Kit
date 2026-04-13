# OpenClaw Integration (Legacy Example)

- [OpenClaw Integration (Legacy Example)](#openclaw-integration-legacy-example)

This page is kept for people who were already looking for the older OpenClaw-specific guidance.

Secrets Kit is no longer documented as an OpenClaw-first tool. The generalized guidance now lives here:

- [Integrations](INTEGRATIONS.md)
- [Usage & Workflows](USAGE.md)
- [Defaults](DEFAULTS.md)

If you are using OpenClaw specifically, the basic handoff still looks like this:

```bash
eval "$(seckit export --format shell --service openclaw --account local-dev --all)"
~/bin/openclaw-stack restart all
```

If you are migrating away from an OpenClaw `.env` file:

```bash
seckit migrate dotenv --dotenv ~/.openclaw/.env --service openclaw --account local-dev --yes --archive ~/.openclaw/.env.bak
```

That imports the values into Keychain and rewrites the dotenv file to placeholders so the raw values are no longer sitting there in plain text.

For current day-to-day usage, prefer the generalized integration guide rather than treating this page as the primary documentation.

[Back to README](../README.md)

**Created**: 2026-03-01  
**Updated**: 2026-04-12