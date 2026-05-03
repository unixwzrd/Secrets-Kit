# Secrets-Kit Changelog

**Created**: 2026-03-10  
**Updated**: 2026-05-03

All notable changes to Secrets-Kit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### 2026-05-03 — Release hygiene: `.gitignore`, local validation, subprocess `HOME` test

- **Scope:** `.gitignore`, `scripts/run_local_validation.sh`, `tests/test_disposable_keychain_flow.py`, `docs/CROSS_HOST_VALIDATION.md`
- **What changed:** Restored **`!scripts/`** / **`!scripts/**`** under Virtualenv’s `[Ss]cripts` rule so new files under `scripts/` are not ignored. **`run_local_validation.sh`** requires a `PYTHON`/`python3` that can `import yaml` (hint: `pip install -e .`). Disposable-keychain **`seckit run`** test now appends the **real user-site** path to **`PYTHONPATH`** when **`HOME`** is overridden (fixes `ModuleNotFoundError: yaml` with Apple `python3` + `--user` installs). Doc note: **iCloud Drive** file sync vs **iCloud Keychain** + encrypted export path.

### 2026-05-02 — Docs: SIGKILL (-9) and MDM / taskgated / AMFI -413 on managed Macs

- **Scope:** `docs/ICLOUD_SYNC_VALIDATION.md`
- **What changed:** Documented that **`helper was terminated by SIGKILL (-9)`** can be **ManagedClient / taskgated** (*no eligible provisioning profiles*) with **AMFI -413**, which **notarization does not override**; points readers at org IT vs non-managed testing.

### 2026-05-02 — `notarize_bundled_helper.sh`: treat stapler Error 73 as OK for bare Mach-O

- **Scope:** `scripts/notarize_bundled_helper.sh`, `docs/GITHUB_RELEASE_BUILD.md`
- **What changed:** Apple **`stapler`** cannot embed notary tickets in **standalone Mach-O** files (only `.app` / `.dmg` / `.pkg`). **`notarytool` Accepted** still applies; script continues after Error 73 with an explanatory note. Docs clarify online Gatekeeper lookup.

### 2026-05-02 — Restore release scripts + `setup.cfg`

- **Scope:** `scripts/build_bundled_helper_for_wheel.sh`, `scripts/package_release_wheels.sh`, `setup.cfg`, `docs/GITHUB_RELEASE_BUILD.md`
- **What changed:** Re-added maintainer flow: universal helper build → optional notarize/staple → wheels/sdist; `[bdist_wheel] plat_name` for `macosx_13_0_universal2`. Documented in GITHUB release doc.

### 2026-05-02 — Restore `docs/GITHUB_RELEASE_BUILD.md` and `scripts/notarize_bundled_helper.sh`

- **Scope:** docs, scripts, README documentation index
- **What changed:** Re-added release workflow + PyPI notes, notarization / `spctl` / AMFI context, and a standalone `notarize_bundled_helper.sh` (keychain profile, API key, or Apple ID + app-specific password). Linked from README under validation docs.

### 2026-05-02 — v1.1.0 launchd runtime validation and release workflow

- **Scope:** `Secrets-Kit/scripts/`, `Secrets-Kit/docs/`, `Secrets-Kit/tests/`, `Secrets-Kit/.github/workflows/`, `Secrets-Kit/src/secrets_kit/`
- **Category:** `launchd`, `runtime`, `testing`, `documentation`, `release`
- **What changed:**
  - Added a multi-mode launchd smoke workflow for user LaunchAgents, dedicated service-keychain LaunchAgents, and service-keychain LaunchDaemons.
  - Added a standalone `scripts/seckit_launchd_agent_simulator.py` child process so validation proves `seckit run` launches another process with secrets in its environment.
  - Added explicit launchd cleanup verification after normal smoke-test runs.
  - Added CI/local validation and release workflow support for repeatable pre-release checks.
  - Updated launchd, security-model, quickstart, usage, integration, and validation documentation around the supported runtime-launch paths.
- **Why:**
  - Make Secrets Kit release-ready for real agent/service launch workflows where secrets must be injected into child processes without exposing values on the command line.

### 2026-04-18 — Parent-side `seckit run` env injection for child processes

- **Scope:** `Secrets-Kit/src/secrets_kit/cli.py`, `Secrets-Kit/tests/test_cli_commands.py`
- **Category:** `cli`, `integration`, `testing`
- **What changed:**
  - Added `seckit run` so selected or filtered secrets can be resolved in the parent process, injected into a child environment map, and then handed off with `exec`.
  - Added explicit child-command parsing and validation so runtime wrappers can use `seckit run -- <command>` safely from non-interactive launch paths.
  - Added regression coverage to confirm that requested secrets are injected into the child env and that a missing target command fails clearly.
- **Why:**
  - Support application launch workflows that need parent-side secret injection instead of relying on child-side `.env` rereads or shell-eval export patterns.

### 2026-04-16 — Cross-host validation expansion, helper packaging, and backend plumbing follow-through

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `Secrets-Kit/.github/workflows/ci.yml`, `Secrets-Kit/.gitignore`, `Secrets-Kit/pyproject.toml`
- **Category:** `cli`, `native-helper`, `testing`, `documentation`
- **What changed:**
  - Expanded the native-helper packaging and installation groundwork, including helper source layout, helper bridge code, helper-focused tests, and backend-resolution coverage.
  - Added repo-local cross-host validation docs and disposable-keychain oriented test coverage to make transfer and helper flows easier to verify outside a live login-keychain session.
  - Added crypto/helper plumbing and CLI/default handling refinements needed to support the newer export/import and backend-selection paths cleanly.
  - Tightened pre-release docs, examples, defaults, and ignore/CI configuration around those validation workflows.
- **Why:**
  - Make pre-release validation more reproducible and keep the helper-backed backend work coherent enough to test before a broader release.

### 2026-04-15 — Reverted iCloud backend to the single-helper design

- **Update 2026-05-02:** `seckit helper install-icloud` now keeps the single-helper executable model but signs that executable with synchronizable Keychain entitlements instead of acting as an `install-local` alias. Local/ad-hoc entitlement signing was tested and macOS terminates that helper with `SIGKILL`; synchronizable Keychain support therefore requires a project-distributed signed helper or developer validation with an Apple signing identity.

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`
- **Category:** `cli`, `native-helper`, `documentation`
- **What changed:**
  - Removed the separate signed-iCloud-agent discovery and capability model from the Python layer.
  - Restored `backend=icloud` to use the installed `seckit-keychain-helper` directly.
  - Kept `seckit helper install-local` as the ad-hoc local helper path and restored `seckit helper install-icloud` as the entitlement-signing path for synchronizable Keychain validation.
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
