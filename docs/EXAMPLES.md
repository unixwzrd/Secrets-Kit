# Examples

- [Examples](#examples)
  - [A generic run example](#a-generic-run-example)
  - [A generic dotenv migration example](#a-generic-dotenv-migration-example)
  - [An encrypted backup example](#an-encrypted-backup-example)
  - [Cross-host validation helpers](#cross-host-validation-helpers)
  - [Back to README](#back-to-readme)

The `docs/examples/` directory contains short shell examples you can copy and adapt.

Current examples:

- `seckit_run_openclaw.sh`
- `seckit_run_hermes.sh`
- `seckit_migrate_dotenv.sh`
- `seckit_export_encrypted.sh`
- `../scripts/seckit_cross_host_prepare.sh`
- `../scripts/seckit_cross_host_verify.sh`
- `../scripts/seckit_cross_host_transport_localhost.sh`
- `../scripts/sqlite_dev_seed.sh` — **SQLite** demo import of `fixtures/synthetic-sample.env` (throwaway DB + fixed passphrase).
- `../scripts/keychain_dev_seed.sh` — same fixture into the **login Keychain** (`--backend secure`); use when you are logged in interactively. Set `SECKIT_PYTHON` if `python3` has no PyNaCl.

Those are meant to be starting points, not rigid templates. In most cases you only need to change the service name, account name, dotenv path, or startup command.

## A generic run example

Even without the sample scripts, the basic process-launch pattern is:

```bash
seckit run --service my-stack --account local-dev -- ./start-my-stack.sh
```

Use shell export only when the current interactive shell needs the values. Use `seckit run` when launching a process.

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

## An encrypted backup example

```bash
seckit export --format encrypted-json --service my-stack --account local-dev --all --out backup.json
```

## Cross-host validation helpers

Prepare the disposable source and destination keychains:

```bash
./scripts/seckit_cross_host_prepare.sh --service sync-test --account local --reset
```

Run the direct disposable-keychain export/import verification:

```bash
./scripts/seckit_cross_host_verify.sh --service sync-test --account local
```

Optionally run the same flow through `ssh localhost`:

```bash
./scripts/seckit_cross_host_transport_localhost.sh --service sync-test --account local
```

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-05-07
