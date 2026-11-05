> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# Quickstart

**Created**: 2026-04-12

**Updated**: 2026-11-03

Next steps after this page: [CONCEPTS.md](CONCEPTS.md) (mental model), [CLI_REFERENCE.md](CLI_REFERENCE.md) (all commands), [WORKFLOWS.md](WORKFLOWS.md) (recipes).

- [Quickstart](#quickstart)
  - [1. Install it](#1-install-it)
  - [2. Check encrypted SQLite](#2-check-encrypted-sqlite)
  - [3. Store a couple of values](#3-store-a-couple-of-values)
  - [4. Check what is stored](#4-check-what-is-stored)
  - [5. Run a command with those values](#5-run-a-command-with-those-values)
  - [6. Protect the local account and back up](#6-protect-the-local-account-and-back-up)
  - [Development protocol lab](#development-protocol-lab)
  - [What this quickstart is trying to accomplish](#what-this-quickstart-is-trying-to-accomplish)
  - [Back to README](#back-to-readme)


This is the shortest practical path to using Secrets Kit on a local macOS or Linux machine without turning the setup into a packaging tutorial.

## 1. Install it

See [INSTALL.md](INSTALL.md) for the operator install command, upgrade path, and troubleshooting.

After install, verify:

```bash
seckit doctor --install-check
seckit status --json
seckit --version
```


**Development checkout** (editable, from a clone):

```bash
cd ~/projects/Secrets-Kit
make install-dev
```

That installs the CLI plus **ruff** and **basedpyright** for `make lint`. The installer provisions an isolated uv runtime under `~/.local/share/seckit` and a launcher at `~/.local/bin/seckit`.

## 2. Check encrypted SQLite

```bash
seckit info
seckit doctor
```

Confirm that `seckit info` reports SQLite with encrypted storage. The managed installer initializes a fresh store; do not run `seckit init` over an existing database. On macOS, existing Secrets Kit Keychain records require a separate, explicitly invoked migration; see [the security model](SECURITY_MODEL.md#legacy-keychain-migration).

## 3. Store a couple of values

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
echo 'hunter2' | seckit set --name ADMIN_PASSWORD --stdin --kind password --service my-stack --account local-dev
```

## 4. Check what is stored

```bash
seckit list --service my-stack --account local-dev
```

That output stays redacted by default. It is meant to confirm that the entries exist without printing the values back to your screen.

Example:

```text
NAME               TYPE    KIND      SERVICE   ACCOUNT    TAGS  STATUS  UPDATED_AT
OPENAI_API_KEY     secret  api_key   my-stack  local-dev  -     ok      2026-04-12T01:04:34Z
ADMIN_PASSWORD     secret  password  my-stack  local-dev  -     ok      2026-04-12T01:04:34Z
```

## 5. Run a command with those values

```bash
seckit run --service my-stack --account local-dev -- python3 -c 'import os; print("selected variables present:", all(name in os.environ for name in ("OPENAI_API_KEY", "ADMIN_PASSWORD")))'
```

Use the same pattern for your actual runtime:

```bash
seckit run --service my-stack --account local-dev -- python3 app.py
```

`seckit run` resolves the selected secrets in the parent process, overlays them into the child environment, and does not put secret values on the command line.

If you need a dotenv file for a runtime but want no plaintext secrets, export placeholders:

```bash
seckit export --format dotenv --service my-stack --account local-dev --all > ~/.config/my-stack/.env
```

If you do this repeatedly, set defaults so the service and account do not have to be repeated on every command:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
```

Then the launch becomes:

```bash
seckit run -- python3 app.py
```

## 6. Protect the local account and back up

SQLite does not use a Keychain lock/unlock workflow. Protect the local account, database, and local storage key together. For a portable encrypted backup, follow [the backup workflow](WORKFLOWS.md#backup--export); retain the backup password separately.

## What this quickstart is trying to accomplish

The point is not to create a perfect secret-management system in one command. The point is to move from loose plain-text files to a cleaner local workflow:

- secret values and authoritative metadata in encrypted SQLite
- registry as a local schema/catalog for metadata validation
- runtime launch through `seckit run` when a process needs secrets
- defaults for the scopes you use all the time

For fuller workflows, see:

- [CLI Reference](CLI_REFERENCE.md)
- [Workflows](WORKFLOWS.md)
- [Integrations](INTEGRATIONS.md)
- [Defaults](DEFAULTS.md)

## [Back to README](../README.md)

**Created**: 2026-03-01  
**Updated**: 2026-11-03
