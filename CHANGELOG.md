# Secrets-Kit Changelog

**Created**: 2026-03-10  
**Updated**: 2026-03-12

All notable changes to Secrets-Kit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
