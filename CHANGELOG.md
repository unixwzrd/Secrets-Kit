# Secrets-Kit Changelog

**Created**: 2026-03-10  
**Updated**: 2026-04-15

All notable changes to Secrets-Kit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### 2026-04-15 — Reverted iCloud backend to the single-helper design

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`
- **Category:** `cli`, `native-helper`, `documentation`
- **What changed:**
  - Removed the separate signed-iCloud-agent discovery and capability model from the Python layer.
  - Restored `backend=icloud` to use the installed `seckit-keychain-helper` directly.
  - Kept `seckit helper install-local` as the real helper install path and turned `seckit helper install-icloud` into an alias for that flow.
  - Updated the Swift helper so synchronizable reads, deletes, and metadata queries match with `kSecAttrSynchronizableAny`.
  - Removed `kSecUseDataProtectionKeychain` from the helper queries and cleared the helper entitlements plist back to an empty file.
  - Kept helper-backed local operations opt-in via `SECKIT_USE_LOCAL_HELPER=1`, while the default local backend remains the `security` CLI path.
- **Why:**
  - The signed-agent split added complexity and broke the intended single-helper install model.
  - The simpler experiment is to use the existing helper plus synchronizable Keychain APIs before revisiting a heavier app/agent architecture.

### 2026-04-15 — Native helper groundwork, backend selection, and validation flow updates

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/scripts/`, `Secrets-Kit/docs/`
- **Category:** `cli`, `testing`, `documentation`
- **What changed:**
  - Added `--keychain PATH` support across normal data operations, including import, export, explain, doctor, and metadata migration.
  - Added active backend selection via defaults/env/CLI with `local` and `icloud`.
  - Added a SwiftPM-native local helper scaffold plus `seckit helper status`, `seckit helper install-local`, a universal local-helper build for Apple Silicon and Intel, and a signed-agent requirement for `backend=icloud`.
  - Added disposable-keychain integration coverage for direct transfer and locked-destination failure.
  - Replaced the earlier login-keychain SSH validation helpers with disposable-keychain helpers, plus an optional `ssh localhost` transport helper.
  - Reworked the cross-host and iCloud docs to split automated disposable-keychain validation from manual login-keychain and iCloud validation.
  - Added a repo-local validation script and wired CI to use the same CI-safe validation path.
  - Hard-failed unsigned `backend=icloud` usage after confirming Apple entitlement requirements block synchronizable writes from the plain helper.
  - Expanded the checklist to separate automated validation, future helper-install checks, and manual-only login-keychain and iCloud sync work.
- **Why:**
  - Make transfer regression testing stable and automatable without relying on macOS GUI keychain session state.
  - Keep iCloud and login-keychain checks explicit and manual where Apple session behavior controls the outcome.

### 2026-04-14 — Keychain-first metadata, defaults.json, and regression hardening

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `Secrets-Kit/pyproject.toml`
- **Category:** `cli`, `security`, `testing`, `documentation`
- **What changed:**
  - Moved authoritative metadata reads to the keychain item comment, stored as structured JSON.
  - Expanded entry metadata to include schema version, renewal source fields, rotation policy, expiry, domains, and custom metadata.
  - Added `~/.config/seckit/defaults.json` as the persistent defaults file, while keeping legacy config compatibility.
  - Added `seckit migrate metadata` for backfilling older registry-first entries into keychain comment metadata.
  - Added status warnings for rotation and expiry in `list`, `explain`, and `doctor`.
  - Added isolated temporary keychain regression coverage for CRUD plus metadata handling.
  - Added cross-host validation helpers and live markdown checklists for SSH transfer and iCloud sync testing.
  - Aligned package version target to `v1.0.0`.
- **Why:**
  - Reduce host-to-host metadata drift by making the keychain item the primary metadata carrier.
  - Keep inventory and recovery support without relying on the local registry as the source of truth.
  - Prepare the project for manual iCloud sync validation and a tighter `v1.0.0` release.

### 2026-04-13 — Encrypted export, placeholder dotenv, comments

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `.pre-commit-config.yaml`
- **Category:** `cli`, `security`, `documentation`
- **What changed:**
  - Added encrypted export/import (`--format encrypted-json`) with optional `cryptography` extra.
  - Added placeholder dotenv export (`--format dotenv`).
  - Added optional metadata `comment` field.
  - Added warn-only pre-commit secret scan hook.
- **Why:**
  - Enable cross-host recovery without plaintext secrets.
  - Provide safe placeholder `.env` generation.
  - Improve metadata clarity and prevent accidental leaks.

### 2026-03-31 — Keychain relock command

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `cli`, `documentation`, `testing`
- **What changed:**
  - Added `seckit lock` as a wrapper around the backend relock flow for the configured macOS keychain.
  - Added backend support for `security lock-keychain`.
  - Added CLI coverage for dry-run and successful keychain relock flows.
  - Documented the normal unlock/lock lifecycle in the README and quickstart docs.
- **Why:**
  - Give operators an explicit, symmetric way to relock the login keychain after a session instead of relying only on timeout policy or external tooling.

### 2026-04-11 — Defaults, examples, and CLI UX polish

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`
- **Category:** `cli`, `documentation`
- **What changed:**
  - Added CLI defaults via env vars and `~/.config/seckit/config.json` to shorten common commands.
  - Added `seckit explain` for metadata-only inspection.
  - Added `seckit list --stale` for age-based filtering.
  - Expanded docs with integrations, usage, defaults, and runnable examples.
  - Generalized integration guidance beyond OpenClaw.
  - Added macOS GitHub Actions CI matrix and optional pre-commit hooks.
- **Why:**
  - Make Secrets-Kit release-ready for general operators, not just one stack.
  - Reduce friction for day-to-day use without changing the security model.

### 2026-03-12 — Keychain UX and policy visibility

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `runtime`, `documentation`, `integration`
- **What changed:**
  - Added `seckit unlock` as a wrapper around the backend unlock flow, with visible command output and no password capture inside `seckit`.
  - Added `seckit keychain-status` to report keychain accessibility and current lock-policy posture.
  - Added `--version` / `version` and improved command help output.
  - Added optional keychain hardening guidance for long-lived unlocked sessions.
- **Why:**
  - Make keychain interaction clearer and safer for typical operators.
  - Warn users when their macOS keychain posture is too relaxed for long-lived secret access.

### 2026-03-10 — Core hardening, Keychain workflow clarity, and LLM-Ops integration support

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `runtime`, `documentation`, `integration`
- **What changed:**
  - Added metadata/keychain drift detection to `doctor`.
  - Added a backend helper for checking whether a managed secret exists in Keychain.
  - Added test coverage for doctor drift reporting and command behavior.
  - Clarified the identity model and namespace semantics:
    - `service`
    - `account`
    - `name`
  - Documented the v1 trust model more explicitly:
    - macOS-only backend
    - login Keychain usage
    - unlocked Keychain requirement
    - shell export as runtime handoff
  - Added explicit quickstart guidance for unlocking the login Keychain when macOS blocks interaction.
  - Separated internal planning/security TODO work into `docs/internal/`.
  - Aligned project naming and install docs with the public repo name `Secrets-Kit` while keeping the CLI command as `seckit`.
- **Why:**
  - Make the v1 Keychain-backed workflow understandable and safer to operate.
  - Support optional runtime secret loading from `LLM-Ops-Kit` without pretending this is a generic cross-host secret manager yet.
