# Examples

- [Examples](#examples)
  - [A generic export example](#a-generic-export-example)
  - [A generic dotenv migration example](#a-generic-dotenv-migration-example)
  - [Back to README](#back-to-readme)

The `docs/examples/` directory contains short shell examples you can copy and adapt.

Current examples:

- `seckit_export_openclaw.sh`
- `seckit_export_hermes.sh`
- `seckit_migrate_dotenv.sh`

Those are meant to be starting points, not rigid templates. In most cases you only need to change the service name, account name, dotenv path, or startup command.

## A generic export example

Even without the sample scripts, the basic pattern is:

```bash
eval "$(seckit export --format shell --service my-stack --account local-dev --all)"
./start-my-stack.sh
```

## A generic dotenv migration example

```bash
seckit migrate dotenv \
  --dotenv ~/.config/my-stack/.env \
  --service my-stack \
  --account local-dev \
  --yes \
  --archive ~/.config/my-stack/.env.bak
```

That is often the fastest path away from plain-text secrets living in a project directory.

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-04-12