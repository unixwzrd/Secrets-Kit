# Quickstart

- [Quickstart](#quickstart)
  - [1. Install it](#1-install-it)
  - [2. Make sure Keychain access works](#2-make-sure-keychain-access-works)
  - [3. Store a couple of values](#3-store-a-couple-of-values)
  - [4. Check what is stored](#4-check-what-is-stored)
  - [5. Export values into the current shell](#5-export-values-into-the-current-shell)
  - [6. Relock when you are done](#6-relock-when-you-are-done)
  - [What this quickstart is trying to accomplish](#what-this-quickstart-is-trying-to-accomplish)
  - [Back to README](#back-to-readme)


This is the shortest practical path to using Secrets Kit on a local macOS machine without turning the setup into a packaging tutorial.

## 1. Install it

If you already have a working Python environment:

```bash
python -m pip install .
```

If you want an isolated local environment first:

```bash
cd ~/projects/Secrets-Kit
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Use `python -m pip install -e .` only if you are actively developing on Secrets Kit.

## 2. Make sure Keychain access works

```bash
seckit keychain-status
seckit unlock
```

Expected unlock flow, with identifying details redacted:

```text
$ seckit unlock

********************************************************************************

About to run:

  security unlock-keychain /Users/example/Library/Keychains/login.keychain-db

This will prompt macOS for the keychain password if needed.
Secrets-Kit does not read, capture, or store that password.
********************************************************************************

Proceed with unlocking /Users/example/Library/Keychains/login.keychain-db? [y/N]: y
password to unlock /Users/example/Library/Keychains/login.keychain-db:
unlocked: /Users/example/Library/Keychains/login.keychain-db
```

If the status output warns that the login Keychain never times out, you can tighten the policy:

```bash
seckit unlock --harden
```

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
NAME                     TYPE    KIND      SERVICE   ACCOUNT    TAGS  UPDATED_AT
OPENAI_API_KEY           secret  api_key   my-stack  local-dev  -     2026-04-12T01:04:34Z
ADMIN_PASSWORD           secret  password  my-stack  local-dev  -     2026-04-12T01:04:34Z
```

## 5. Export values into the current shell

```bash
eval "$(seckit export --format shell --service my-stack --account local-dev --all)"
```

At that point, the current shell can launch whatever local tool needs those variables.

If you do this repeatedly, set defaults so the service and account do not have to be repeated on every command:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
```

Then the export becomes:

```bash
eval "$(seckit export --format shell --all)"
```

## 6. Relock when you are done

```bash
seckit lock
```

## What this quickstart is trying to accomplish

The point is not to create a perfect secret-management system in one command. The point is to move from loose plain-text files to a cleaner local workflow:

- secret values in Keychain
- metadata in a local registry
- runtime export only when needed
- defaults for the scopes you use all the time

For fuller workflows, see:

- [Usage & Workflows](USAGE.md)
- [Integrations](INTEGRATIONS.md)
- [Defaults](DEFAULTS.md)

## [Back to README](../README.md)

**Created**: 2026-03-01  
**Updated**: 2026-04-12
