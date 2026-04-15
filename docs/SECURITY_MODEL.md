# Security Model

- [Security Model](#security-model)
  - [Where values live](#where-values-live)
  - [How entries are identified](#how-entries-are-identified)
  - [What the redaction rules do](#what-the-redaction-rules-do)
  - [What this protects against](#what-this-protects-against)
  - [What this does not protect against](#what-this-does-not-protect-against)
  - [Permissions and drift](#permissions-and-drift)
  - [Practical takeaway](#practical-takeaway)
  - [Back to README](#back-to-readme)


Secrets Kit is a local workflow improvement, not a promise of perfect protection.

If you understand that up front, the tool makes more sense and is easier to use safely.

## Where values live

- secret values are stored in the macOS login Keychain
- authoritative managed metadata is stored in the keychain item comment as structured JSON
- `~/.config/seckit/registry.json` remains a local index and recovery aid
- operator defaults live in `~/.config/seckit/defaults.json`

If iCloud Keychain sync is enabled, values can sync across your Apple devices. For non-iCloud hosts, use encrypted export/import as the fallback.

The registry exists so the tool can track inventory locally without becoming the source of truth for metadata across hosts.

## How entries are identified

Each entry is defined by three fields:

- `service`
- `account`
- `name`

That lets you keep the same environment-variable-style name in different scopes without collisions.

## What the redaction rules do

Normal output is redacted by default. You have to explicitly ask for raw values with commands like `get --raw` or by exporting them into the current shell.

That default helps prevent casual leaks into terminal history, screenshots, or copied command output.

## What this protects against

Secrets Kit helps with a very common local problem:

- too many `.env` files
- secrets copied into shell rc files
- raw tokens committed by mistake
- values left behind in project directories and archives

Moving those values into Keychain and exporting them only when needed is a meaningful improvement over plain-text sprawl.

## What this does not protect against

Secrets Kit does not make a compromised local machine safe.

If malware, a hostile script, or an already-compromised shell session can access the Keychain or the exported process environment, Secrets Kit cannot override that reality. It also is not a remote secret service, policy engine, or multi-host trust system.

## Permissions and drift

- the registry directory is enforced at `0700`
- the registry file is enforced at `0600`
- the defaults file is enforced at `0600`
- `doctor` can report drift between the local index and the Keychain
- `doctor`, `list`, and `explain` can surface rotation and expiry warnings

## Keychain fields and limits

The macOS `security` CLI supports a limited generic-password field set:

- native lookup/identity fields:
  - account
  - service
  - label
  - comment
- readable raw timestamps may be exposed by the CLI, but not in a stable high-level format suitable for authoritative metadata

What it does not provide is a rich custom schema. Secrets-Kit therefore stores extensible metadata as compact JSON in the keychain comment field. That is where fields like:

- `source_url`
- `source_label`
- `rotation_days`
- `rotation_warn_days`
- `domains`
- `custom`

are carried.

The practical size limit for comment JSON is determined by what macOS will store and return reliably for a generic-password item. Treat it as small structured metadata, not an unlimited document store.

## Sync behavior

iCloud Keychain synchronization is Apple-managed, not toolkit-managed.

- Secrets-Kit writes normal keychain items.
- Whether those items sync, how quickly they sync, and which fields survive intact must be validated empirically in your environment.
- Manual VM or second-host validation is the right test for add, change, delete, and metadata preservation.

That helps keep local metadata sane, but it is still operational hygiene, not a hard security boundary.

## Practical takeaway

Use Secrets Kit when you want a more disciplined local workflow for tokens, passwords, API keys, and PII on macOS. Do not use it as an excuse to stop thinking about process isolation, machine trust, or downstream runtime behavior.

## [Back to README](../README.md)

**Created**: 2026-03-01  
**Updated**: 2026-04-14
