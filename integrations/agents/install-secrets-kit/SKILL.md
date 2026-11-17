---
name: install-secrets-kit
description: Install, upgrade, recover, or uninstall same-user Secrets Kit and migrate approved local credentials in or out. Use for application cutover and protected exit exports, not routine credential retrieval or release publication.
license: MIT
---

# Install, upgrade, or uninstall Secrets Kit for an agent

Install under the Unix account that runs the application. Preserve existing stores, keys, peer authorization, RSS enrollment, and unrelated application configuration. This skill does not authorize root access, billing changes, provider-key rotation, or deletion of source credentials.

## Establish the inputs

Identify the actual host, Unix account, application home, executable paths, intended service/account scope, and any active managed services. An embedded agent, terminal tool, and gateway can run in different processes or environments; do not assume they share an interpreter or startup environment.

Use an owner-approved published release tag and repository. If the owner authorizes selecting the latest stable release, resolve it once from the publisher's release metadata and record the exact tag; do not execute a moving branch or source checkout. Require the independently supplied installer SHA-256 before unattended execution. If it is unavailable, establish the download trust with the owner rather than inventing a checksum. A digest downloaded beside the installer detects corruption but is not independent authentication.

Obtain application-specific integration files from an approved immutable revision. Installation permission does not grant permission to read every credential file: identify approved source paths, selected names, import precedence, model-visible retrieval names, and cutover/archive scope before migration.

## Choose the path before changing state

| Observed state | Action |
| --- | --- |
| No datastore, identity, enrollment, or prior user state | Fresh installation; initialize once after verifying the software. |
| Existing working installation and datastore | Preserving upgrade; never initialize or automatically reimport old dotenv files. |
| Interrupted software installation, missing launcher, or failed candidate | Preserve customer state; reinstall the verified software with `--no-init`. Do not invent receipts or move the runtime tree. |
| Verified empty failed store, or explicitly designated disposable test state | Follow the recovery reference, archive consistently, then initialize once. |
| Populated, unreadable, inconsistent, or uncertain state | Preserve it and stop for a recovery decision. A schema mismatch is not permission to reset. |

Inspect all scopes and existing identity/enrollment metadata when assessing emptiness. A missing daemon, an empty `list`, or a failed `get` does not establish an empty database. Conflicting evidence blocks automatic reset.

Use this process-local wrapper for CLI examples in this skill; it creates no file and does not change the application's global environment. Define it in each terminal invocation that uses it: separate agent tool calls may not share shell functions or variables.

```bash
seckit_local() {
  /usr/bin/env -u PYTHONPATH -u PYTHONHOME -u VIRTUAL_ENV "$HOME/.local/bin/seckit" "$@"
}
```

For an existing installation, record `seckit_local --version`, `seckit_local info`, `seckit_local doctor --install-check`, and managed service status. Installation checks alone do not establish database health or credential completeness. Keep reports value-free.

## Fresh or incomplete software installation

Use the published single-file release `install.sh`, not the repository's network-fetch engine or GitHub's Source code archive. Download to a newly created owner-private directory. Set these non-secret variables to the approved inputs before running the example:

- `SECKIT_TAG`: exact published tag, including `v`.
- `SECKIT_INSTALLER_URL`: that repository/tag's HTTPS release-asset URL ending in `/install.sh`.
- `SECKIT_INSTALLER_SHA256`: independently supplied lowercase SHA-256.

```bash
: "${SECKIT_TAG:?set the approved exact tag}"
: "${SECKIT_INSTALLER_URL:?set its approved release asset URL}"
: "${SECKIT_INSTALLER_SHA256:?set the independently supplied installer hash}"
(
  set -eu
  umask 077
  SECKIT_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/seckit-agent-install.XXXXXXXX")
  cd "$SECKIT_STAGE"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SECKIT_INSTALLER_URL" -o install.sh
  else
    wget -q "$SECKIT_INSTALLER_URL" -O install.sh
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf '%s  install.sh\n' "$SECKIT_INSTALLER_SHA256" | shasum -a 256 -c -
  else
    printf '%s  install.sh\n' "$SECKIT_INSTALLER_SHA256" | sha256sum -c -
  fi
  /usr/bin/env -u PYTHONPATH -u PYTHONHOME -u VIRTUAL_ENV bash ./install.sh --verify-only
  /usr/bin/env -u PYTHONPATH -u PYTHONHOME -u VIRTUAL_ENV bash ./install.sh --ref "$SECKIT_TAG" --yes --no-init --no-shell-profile
  seckit_local --version
  seckit_local doctor --install-check
)
```

The installer provisions its managed Python and dependencies; system Python, pip, Git, and GitHub CLI are not installation prerequisites. The published installer records its repository/channel: do not force `prerelease` for a stable installation or substitute environment URLs. Private artifacts require authorized download access.

For a verified fresh account only, run `seckit_local init` once. Do not use `--yes` to erase an existing-state warning. Run `seckit_local daemon service install` and `seckit_local daemon service status` when managed local use is in scope. If Linux reports disabled lingering, explain the resulting logout limitation; do not claim an unattended service has passed or attempt privilege escalation.

If native-library validation fails, retain the failed candidate and sanitized error. Do not patch dependencies, change library search paths, or retry with verification disabled. Process-local Python cleanup does not prove that an automated application helper or MCP launch has the same protection.

## Upgrade an existing installation

```bash
: "${SECKIT_TAG:?set the approved exact non-older tag}"
seckit_local upgrade --check
seckit_local upgrade --ref "$SECKIT_TAG"
seckit_local --version
seckit_local daemon service status
```

Record a failed check/upgrade before using an approved fallback. If the old downloader is unusable, use the independently verified exact installer with `--upgrade --no-init --no-shell-profile --ref "$SECKIT_TAG"`; do not delete or reinitialize the store. Use `--yes` only for owner-approved unattended maintenance.

Confirm existing identity, scopes, authorized peers, RSS connection ID if configured, and historical data remain intact. Restart the approved application/MCP processes so they use the new runtime, and repeat application verification. Do not automatically rerun imports or replace policy/integration files during an upgrade. No intentional downgrade is supported.

## Import, cut over, and recover

Read [credential migration and recovery](references/migration-and-recovery.md) before importing credentials, archiving source files, or resetting disposable failed state. For removal, follow [export credentials and uninstall](references/migration-and-recovery.md#export-credentials-and-uninstall) before disabling the application integration or removing software. This reference contains the acceptance gates and rollback boundaries; do not improvise cleanup commands.

For Hermes, also read the repository's `integrations/hermes/install-secrets-kit-for-hermes/SKILL.md` from the verified integration revision. The Hermes adapter configures the application; it does not replace the installation-state decision above.

## Handoff and skill availability

This folder is the installation skill; copy the entire folder, including `references/`, into the agent host's documented skill directory if persistent discovery is wanted. Install only for the selected account and do not overwrite an existing skill without reviewing its revision. Skill installation and MCP server registration are separate steps.

The companion `use-secrets-kit` skill covers routine operation. Obtain both from the same approved repository revision. A copied skill may refer to the source repository for application-specific integration files; keep that verified source available rather than assuming links outside the copied folder exist.

Report the exact installed release, installation path taken, preserved state, imported-name count, daemon/application/MCP results, archive location and confidentiality level, and any unpassed gate. Do not include secret values, per-secret hashes, environment dumps, or private keys.
