# Usage & Workflows

- [Usage \& Workflows](#usage--workflows)
  - [Store a secret](#store-a-secret)
  - [Read a secret safely](#read-a-secret-safely)
  - [Read the raw value](#read-the-raw-value)
  - [List inventory](#list-inventory)
- [Export for a local runtime](#export-for-a-local-runtime)
  - [Export placeholder dotenv](#export-placeholder-dotenv)
  - [Export encrypted backup](#export-encrypted-backup)
  - [Import an existing dotenv file](#import-an-existing-dotenv-file)
  - [Import encrypted backup](#import-encrypted-backup)
  - [Migrate a dotenv file and replace inline values](#migrate-a-dotenv-file-and-replace-inline-values)
  - [Explain an entry without revealing the secret](#explain-an-entry-without-revealing-the-secret)
  - [A simple everyday pattern](#a-simple-everyday-pattern)
  - [Back to README](#back-to-readme)


This guide shows the everyday commands people actually need once Secrets Kit is installed.

The examples use a neutral scope of `my-stack` and `local-dev` first. Replace those with whatever makes sense for your own runtime, environment, or account naming.

## Store a secret

```bash
echo 'sk-live' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
```

Add a comment to record why a key exists:

```bash
echo 'sk-live' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --comment "primary llm provider" --service my-stack --account local-dev
```

Add renewal and rotation metadata at the same time:

```bash
echo 'sk-live' | seckit set \
  --name OPENAI_API_KEY \
  --stdin \
  --kind api_key \
  --service my-stack \
  --account local-dev \
  --comment "primary llm provider" \
  --source-label "OpenAI dashboard" \
  --source-url "https://platform.openai.com/api-keys" \
  --rotation-days 90 \
  --rotation-warn-days 14 \
  --domain openai \
  --domain production \
  --meta owner=ops
```

## Read a secret safely

```bash
seckit get --name OPENAI_API_KEY --service my-stack --account local-dev
```

Normal output is redacted. That is the safer default when you only need to confirm the entry exists.

## Read the raw value

```bash
seckit get --name OPENAI_API_KEY --raw --service my-stack --account local-dev
```

Use that only when you genuinely need the value printed.

## List inventory

```bash
seckit list --service my-stack --account local-dev
```

Filter for stale entries:

```bash
seckit list --service my-stack --account local-dev --stale 90
```

`list` now includes a `STATUS` column so upcoming rotation or expiry issues are visible without exposing the value.

## Export for a local runtime

```bash
eval "$(seckit export --format shell --service my-stack --account local-dev --all)"
```

That pattern works for CLIs, local web apps, agent runtimes, and scripts that expect environment variables in the current shell.

## Export placeholder dotenv

```bash
seckit export --format dotenv --service my-stack --account local-dev --all > ~/.config/my-stack/.env
```

## Export encrypted backup

```bash
seckit export --format encrypted-json --service my-stack --account local-dev --all --out backup.json
```

## Import encrypted backup

```bash
seckit import encrypted-json --file backup.json
```

## Import an existing dotenv file

```bash
seckit import env --dotenv ~/.config/my-stack/.env --service my-stack --account local-dev --allow-overwrite
```

## Migrate a dotenv file and replace inline values

```bash
seckit migrate dotenv --dotenv ~/.config/my-stack/.env --service my-stack --account local-dev --yes --archive ~/.config/my-stack/.env.bak
```

This is the practical “stop leaving raw secrets in `.env`” workflow. It imports the values, then rewrites the file to use placeholders.

## Explain an entry without revealing the secret

```bash
seckit explain --name OPENAI_API_KEY --service my-stack --account local-dev
```

`explain` resolves metadata from the keychain comment first and shows:

- effective metadata
- status warnings
- whether registry fallback was needed
- raw keychain fields that were readable through the CLI

## Migrate older registry-only metadata into the keychain

```bash
seckit migrate metadata --service my-stack --account local-dev
```

Use `--dry-run` first if you want to see how many items would be updated without writing anything.

## A simple everyday pattern

One reasonable local workflow looks like this:

1. keep values in Keychain
2. use `list` or `explain` to inspect inventory safely
3. use `export` only in the shell that is about to launch the runtime
4. lock the Keychain again when the session is over

That does not eliminate risk, but it is materially better than sprinkling secrets across plain-text files and shell startup scripts.

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-04-14
