# Quickstart

- [Quickstart](#quickstart)
  - [1. Install it](#1-install-it)
  - [2. Make sure Keychain access works](#2-make-sure-keychain-access-works)
  - [3. Store a couple of values](#3-store-a-couple-of-values)
  - [4. Check what is stored](#4-check-what-is-stored)
  - [5. Run a command with those values](#5-run-a-command-with-those-values)
  - [6. Relock when you are done](#6-relock-when-you-are-done)
  - [What this quickstart is trying to accomplish](#what-this-quickstart-is-trying-to-accomplish)
  - [Back to README](#back-to-readme)


This is the shortest practical path to using Secrets Kit on a local macOS machine without turning the setup into a packaging tutorial.

## 1. Install it

Preferred path, install the tagged release directly from GitHub:

```bash
pip install "git+https://github.com/unixwzrd/Secrets-Kit.git@v1.0.0"
```

If you explicitly want the current branch tip instead of the tagged release:

```bash
pip install "git+https://github.com/unixwzrd/Secrets-Kit.git"
```

If you want an isolated editable local checkout for development:

```bash
cd ~/projects/Secrets-Kit
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

If `pip` is not installed or is not on your `PATH`, use `python3 -m pip` instead.

Optional extras from the tagged release:

```bash
pip install "git+https://github.com/unixwzrd/Secrets-Kit.git@v1.0.0#egg=seckit[yaml]"
```

Check the installed version:

```bash
seckit version
```

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
NAME               TYPE    KIND      SERVICE   ACCOUNT    TAGS  STATUS  UPDATED_AT
OPENAI_API_KEY     secret  api_key   my-stack  local-dev  -     ok      2026-04-12T01:04:34Z
ADMIN_PASSWORD     secret  password  my-stack  local-dev  -     ok      2026-04-12T01:04:34Z
```

## 5. Run a command with those values

```bash
seckit run --service my-stack --account local-dev -- /usr/bin/env | grep -E '^(OPENAI_API_KEY|ADMIN_PASSWORD)='
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

## 6. Relock when you are done

```bash
seckit lock
```

## What this quickstart is trying to accomplish

The point is not to create a perfect secret-management system in one command. The point is to move from loose plain-text files to a cleaner local workflow:

- secret values in Keychain
- authoritative metadata in the keychain comment JSON
- registry as a local inventory and recovery index
- runtime launch through `seckit run` when a process needs secrets
- defaults for the scopes you use all the time

For fuller workflows, see:

- [Usage & Workflows](USAGE.md)
- [Integrations](INTEGRATIONS.md)
- [Defaults](DEFAULTS.md)

## [Back to README](../README.md)

**Created**: 2026-03-01  
**Updated**: 2026-04-28
