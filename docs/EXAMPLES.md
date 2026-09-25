# Examples

- [Examples](#examples)
  - [A generic run example](#a-generic-run-example)
  - [PostgreSQL, Redis and batch applications](#postgresql-redis-and-batch-applications)
  - [A generic dotenv migration example](#a-generic-dotenv-migration-example)
  - [An encrypted backup example](#an-encrypted-backup-example)
  - [Back to README](#back-to-readme)

The `docs/examples/` directory contains short shell examples you can copy and adapt.

Current examples:

- `seckit_run_openclaw.sh`
- `seckit_run_hermes.sh`
- `seckit_migrate_dotenv.sh`
- `seckit_export_encrypted.sh`
- `../scripts/sqlite_dev_seed.sh` — **SQLite** demo import of `fixtures/synthetic-sample.env` (throwaway DB + fixed passphrase).
- `../scripts/keychain_dev_seed.sh` — same fixture into the **login Keychain** (`--backend keychain`); use when you are logged in interactively. Set `SECKIT_PYTHON` if `python3` has no PyNaCl.

Those are meant to be starting points, not rigid templates. In most cases you only need to change the service name, account name, dotenv path, or startup command.

## A generic run example

Even without the sample scripts, the basic process-launch pattern is:

```bash
seckit run --service my-stack --account local-dev -- ./start-my-stack.sh
```

Use shell export only when the current interactive shell needs the values. Use `seckit run` when launching a process.

## PostgreSQL, Redis and batch applications

These are application-launch examples, not alternative Secrets Kit datastore backends. Install and configure the application separately. Start with disposable local database credentials, never production credentials for beta testing. No MCP server or agent is required.

Store a password through a hidden Bash prompt and stdin, keeping it out of arguments and history. Change the scope/name for the application you are testing:

```bash
set +x
IFS= read -r -s -p 'Disposable PostgreSQL password: ' seckit_example_password
printf '\n'
printf '%s' "$seckit_example_password" | seckit set --service postgres --account development --name PGPASSWORD --stdin
unset seckit_example_password
seckit run --service postgres --account development --names PGPASSWORD -- psql -h localhost -U app -d appdb -c 'SELECT 1;'
```

Use `psql`, not `pgsql`. The password must match the existing database account; Secrets Kit does not create or rotate the database account for you. `pg_dump` and other libpq clients use the same environment pattern. PostgreSQL warns that some systems expose process environments and recommends its password-file interface instead of `PGPASSWORD` where appropriate. See [libpq environment variables](https://www.postgresql.org/docs/current/libpq-envars.html).

For an existing owner-only PostgreSQL password file, store its path as `PGPASSFILE` and select that name instead:

```bash
printf '%s' "$HOME/.pgpass" | seckit set --service postgres --account development --name PGPASSFILE --stdin
seckit run --service postgres --account development --names PGPASSFILE -- psql -h localhost -U app -d appdb -c 'SELECT 1;'
```

The referenced file must already exist in PostgreSQL's `hostname:port:database:username:password` format, with correct escaping and mode `0600`. This stores only a path, not the file contents; it does not eliminate plaintext credentials in that file or copy it to another machine. Ensure a stale inherited `PGPASSWORD` does not override the intended file. Follow [PostgreSQL password-file rules](https://www.postgresql.org/docs/current/libpq-pgpass.html). Automatic temporary password-file creation is not a current `seckit run` feature.

For Redis, use the same hidden-prompt/stdin pattern to store the existing Redis password as `REDISCLI_AUTH` under service `redis`, account `development`, then:

```bash
seckit run --service redis --account development --names REDISCLI_AUTH -- redis-cli -h localhost PING
```

Expected: `PONG` from your configured test server. For ACL accounts, add the non-secret `--user` argument. Configure TLS and certificate verification for remote connections according to your server policy. Redis documents [REDISCLI_AUTH](https://redis.io/docs/latest/develop/tools/cli/) instead of passing passwords with `-a`.

For an application or scheduled job that reads `API_TOKEN` directly from its environment:

```bash
seckit run --service batch --account development --names API_TOKEN -- ./nightly-job.sh
```

Use absolute launcher/script paths in scheduled jobs. Store `API_TOKEN` first using stdin or a reviewed dotenv import. Do not expand it into a downstream command argument. `seckit run` inherits the parent environment and adds selected stored entries; it is not an environment sandbox. Same-user/root inspection, crash dumps and application logs can still expose credentials. Applications that only read hard-coded files must be configured or adapted to a supported credential input; no generic transparent conversion is provided.

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

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-09-16
