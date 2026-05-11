# Security Model

**Created**: 2026-03-10  
**Updated**: 2026-05-12
  - [Three layers (contract)](#three-layers-contract)
  - [Where values live](#where-values-live)
  - [How entries are identified](#how-entries-are-identified)
  - [What the redaction rules do](#what-the-redaction-rules-do)
  - [What this protects against](#what-this-protects-against)
  - [What this does not protect against](#what-this-does-not-protect-against)
  - [launchd and unattended services](#launchd-and-unattended-services)
  - [Permissions and drift](#permissions-and-drift)
  - [Keychain fields and limits](#keychain-fields-and-limits)
  - [Sync behavior](#sync-behavior)
  - [Practical takeaway](#practical-takeaway)
  - [Back to README](#back-to-readme)


Secrets Kit is a local workflow improvement, not a promise of perfect protection.

If you understand that up front, the tool makes more sense and is easier to use safely.

## Three layers (contract)

```text
CLI / tooling
    → typed API (secrets, EntryMetadata, IndexRow, BackendCapabilities, BackendSecurityPosture)
BackendStore protocol (adapters: macOS Keychain, encrypted SQLite, …)
    → payload encryption, row layout, Keychain comment wire format (adapter-internal only)
```

Operator commands **`seckit backend-index`** and **`seckit doctor`** can surface honest **capability** and **posture** flags without deserializing ciphertext.

## Where values live

- secret values are stored in macOS Keychain generic-password items
- the default local backend uses the login Keychain, while `--keychain PATH` targets a specific local keychain file
- authoritative managed metadata is stored in the keychain item comment as structured JSON
- `~/.config/seckit/registry.json` remains a local index and recovery aid
- operator defaults live in `~/.config/seckit/defaults.json`

The registry exists so the tool can track inventory locally without becoming the source of truth for metadata across hosts.

## SQLite plaintext debug mode (non-production)

When **`SECKIT_SQLITE_PLAINTEXT_DEBUG=1`**, the SQLite backend writes joint payload bytes **without** NaCl `SecretBox` encryption (rows use `crypto_version=0`). This mode is for **development, automated tests, and forensic inspection** on **disposable** database files only. **Do not** point it at production vaults. A warning is printed on first store open. See [plans/SECKITD_PHASE5.md](plans/SECKITD_PHASE5.md) (Phase 5D).

## How entries are identified

Each entry is defined by three fields:

- `service`
- `account`
- `name`

That lets you keep the same environment-variable-style name in different scopes without collisions.

## What the redaction rules do

Normal output is redacted by default. You have to explicitly ask for raw values with commands like `get --raw`, export them for a shell session, or launch a child process with `seckit run`.

That default helps prevent casual leaks into terminal history, screenshots, or copied command output.

## Protected authority handling (summary)

See [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) for definitions of **resolve**, **materialize**, **inject**, and **exported** exposure. **Resolved-within-handling** may include plaintext in process memory before it **crosses** to operators, child processes, filesystems, or IPC. **Injection** (today: `seckit run`) is a **runtime-scoped materialization path** that **transfers plaintext into another execution context**, and may propagate via **environment inheritance** unless constrained.

Treat **helpers**, **`repr`**, **loggers**, and **tracebacks** as high risk: they must not **implicitly** surface plaintext outside explicit materialization commands. **Exposure levels** in the ADR are **descriptive** vocabulary only, not compliance tiers.

## What this protects against

Secrets Kit helps with a very common local problem:

- too many `.env` files
- secrets copied into shell rc files
- raw tokens committed by mistake
- values left behind in project directories and archives

Moving those values into Keychain and launching processes through `seckit run` is a meaningful improvement over plain-text sprawl. Shell export remains available for interactive sessions, but it should not be the default process-launch pattern.

## What this does not protect against

Secrets Kit does not make a compromised local machine safe.

If malware, a hostile script, or an already-compromised shell session can access the Keychain or a launched process environment, Secrets Kit cannot override that reality. Child processes launched with `seckit run` can read every selected variable they inherit. Secrets Kit also is not a remote secret service, policy engine, or multi-host trust system.

## launchd and unattended services

The login keychain is a user-session credential store. It is appropriate for interactive user tools and LaunchAgents that run while the user is logged in and the login keychain is accessible. It is not a reliable storage backend for unattended services that must keep running after logout or start after reboot before user login.

For unattended launchd services, use a dedicated service keychain:

- user-owned background service: LaunchAgent plus `~/Library/Keychains/seckit-service.keychain-db`
- machine service: LaunchDaemon plus `/Library/Application Support/SecretsKit/seckit-service.keychain-db`

The service keychain is still encrypted. Reboot-safe daemon mode requires unlock material. Secrets-Kit's smoke-test model stores a random service-keychain password in a root-owned `0600` file for LaunchDaemon mode. That file is sensitive service credential material and must be protected like an API token.

A dedicated service keychain is not a security bypass. It is an explicit service credential store for cases where the operational requirement is "run without a logged-in desktop user."

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

**Supported cross-host workflow:** **encrypted export** and **import** ([CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md)) with **`--backend secure`**.

**Optional — peer identity bundles:** **`seckit identity`**, **`peer`**, and **`sync`** implement **signed, encrypted JSON files** for targeted exchange with pre-registered public keys ([PEER_SYNC.md](PEER_SYNC.md)). This is **not** a live multi-master sync; transport is manual file copy.

Secrets-Kit does **not** implement Apple-managed Keychain replication. Cross-host work is **your** artifact (export, import, or peer bundle)—not OS sync of Keychain items.

**Resilience, noisy export, uninstall:** Peer sync is the **primary** resilience path; full plaintext export is **explicit and high-friction**, not a default backup. Uninstall is **manual per host** with **no dark patterns**. See [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md).

## Practical takeaway

Use Secrets Kit when you want a more disciplined local workflow for tokens, passwords, API keys, and PII on macOS. Do not use it as an excuse to stop thinking about process isolation, machine trust, or downstream runtime behavior.

## [Back to README](../README.md)
