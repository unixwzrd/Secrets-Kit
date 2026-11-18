---
name: install-secrets-kit-for-hermes
description: Install or upgrade Secrets Kit for the local Hermes account and configure scoped environment and MCP access.
license: Apache-2.0
metadata:
  hermes:
    version: 0.1.0
    author: Secrets Kit maintainers
    platforms: [macos, linux]
    tags: [secrets, mcp, security]
    category: security
---

# Install Secrets Kit for Hermes

Install a pinned Secrets Kit release under the Unix account that runs Hermes. Import only explicitly approved dotenv names. Hermes exchanges MCP messages with its local `seckit-mcp` subprocess over stdio; `seckit-mcp` reaches the same-user Secrets Kit daemon through an owner-only Unix domain socket. The controller's default MCP policy is read-only; a separately authorized version 2 policy can grant exact-name writes. Do not modify Hermes core, delete `.env`, expose a network MCP listener, publish artifacts or enable live billing.

## Required inputs

- The approved exact release tag for this installation; beta qualification does not imply a stable production release.
- The release repository, downloaded asset directory and independently trusted manifest checksum.
- The integration directory from a separately verified immutable source revision or integration bundle. A skill file alone is not the scripts and references it links to.
- The absolute Hermes executable path and existing `HERMES_HOME`.
- The owner-controlled dotenv file (mode `0600` or stricter) and explicit environment-name allowlist.
- An owner-approved `--account` and `--service` dedicated to this Hermes integration. The installer imports only the approved names into that pair and pins MCP to the same pair; do not select a database, administrator, or other service used by the same Unix account.
- Do not include reserved `PYTHON*`, `CONDA_*`, `DYLD_*`, `LD_*`, `OPENSSL_*`, or `VIRTUAL_ENV` names in the allowlist; these can alter runtime loading rather than represent application credentials.
- Separate owner approval for any model-visible MCP retrieval names; these must be a subset of the environment allowlist.

Read [security boundaries](references/security-boundaries.md) before acting. Never execute unverified scripts, use an unpinned branch, print credential files, or trust a checksum merely because it is included in the same download.

## Install from the GitHub artifacts

The current GitHub release layout contains `install.sh`, `source-commit.txt`, `manifest.sha256`, `installer-pins.sha256`, `release-origin.json`, the versioned client wheel and source archive, and the pinned dependency artifacts. It does not contain the old controller's `release-id` file.

Supply the exact tag and a manifest SHA-256 obtained through an independent trusted channel. The controller checks every manifest entry, dependency pin, source commit, repository, version, release tag, and channel before invoking the installer. It removes inherited Python, Conda and native-loader overrides from installer subprocesses. Do not fabricate provenance files or edit a published manifest.

1. Show a sanitized installation plan and obtain approval before changing state.
2. Run the controller as the Hermes user, without `sudo`; use Python 3.10 or newer for preflight/install:

```bash
: "${SECKIT_APPROVED_TAG:?set the exact independently approved release tag}"
: "${SECKIT_MANIFEST_SHA256:?set the independently verified manifest SHA-256}"
python3.12 -I /absolute/path/to/integration/scripts/hermes_secrets_kit.py preflight \
  --bundle /absolute/path/to/verified-release-assets \
  --release-ref "$SECKIT_APPROVED_TAG" \
  --manifest-sha256 "$SECKIT_MANIFEST_SHA256" \
  --hermes-command /absolute/path/to/hermes
python3.12 -I /absolute/path/to/integration/scripts/hermes_secrets_kit.py install \
  --bundle /absolute/path/to/verified-release-assets \
  --release-ref "$SECKIT_APPROVED_TAG" \
  --manifest-sha256 "$SECKIT_MANIFEST_SHA256" \
  --hermes-command /absolute/path/to/hermes
"$HOME/.local/bin/seckit" --version
"$HOME/.local/bin/seckit" doctor --install-check
```

Use the installer supplied by the verified release bundle; it provisions UV and the managed runtime. The controller preserves an existing datastore and initializes encrypted SQLite only when no default database exists. Do not use this flow to reset or reinitialize an existing datastore. Private GitHub downloads require authenticated access; release artifacts already present locally need no GitHub CLI.

For an account where no datastore exists, the controller initializes the encrypted store once. Confirm the account and data path before installation; do not initialize a second store to work around a failed verification.

```bash
"$HOME/.local/bin/seckit" daemon service status
```

## Configure and verify

Use the installed runtime's Python and the absolute verified integration path. The commands below contain placeholders for user-supplied paths; resolve them before execution.

```bash
"$HOME/.local/share/seckit/runtime/current/bin/python" -I -B /absolute/path/to/integration/scripts/hermes_secrets_kit.py configure \
  --hermes-command /absolute/path/to/hermes \
  --dotenv /absolute/path/to/.env \
  --account hermes --service hermes-agent \
  --names OPENROUTER_API_KEY,ELEVENLABS_API_KEY

"$HOME/.local/share/seckit/runtime/current/bin/python" -I -B /absolute/path/to/integration/scripts/hermes_secrets_kit.py verify \
  --hermes-command /absolute/path/to/hermes
"$HOME/.local/bin/seckit" daemon service status
```

Configuration backs up Hermes configuration and integration files, performs a redacted import of only the allowlisted names, installs the same-user managed daemon, configures the existing `secrets.command` source and creates an owner-only fixed-scope MCP policy. Retrieval is denied by default. Add `--mcp-retrieval-names NAME_ONE` only with explicit owner authorization for that model-visible value. The helper and MCP launchers use the installed runtime Python in isolated mode; the helper also clears selected names before `seckit run`, so it cannot succeed by echoing inherited dotenv variables. The MCP registration is stored in Hermes `config.yaml` under `mcp_servers` and is restored by the rollback manifest.

The datastore derives a distinct service-group ID from the approved account/service pair. The group name and policy path are not secrets: the boundary is the server's fixed scope and exact-name grants. The MCP launcher pins the generated policy path, and `verify` rejects policy/helper scope or allowlist drift. Review the resulting policy before enabling MCP. This policy limits MCP tool calls; it does not prevent an agent running as the same Unix user from reading that user's other files or invoking the ordinary `seckit` CLI. Retained `.env` values remain directly readable to that same user. Run `make test-mcp` in the Secrets Kit source checkout to check multi-service MCP isolation without starting Hermes.

Restart Hermes and repeat verification. Preserve unrelated MCP servers. Leave `.env` unchanged: `override_existing: false` preserves existing environment values, so the verifier removes the selected names from the helper subprocess environment to confirm that helper obtains them from Secrets Kit. Its `helper_dotenv_fallback: not_used` result applies only to that helper subprocess; it does not claim that Hermes or other environment sources have no fallback. Never capture the helper's value-bearing output in an agent transcript or diagnostic report.

## Upgrade an existing installation

```bash
: "${SECKIT_APPROVED_TAG:?set the exact independently approved release tag}"
"$HOME/.local/bin/seckit" upgrade --check
"$HOME/.local/bin/seckit" upgrade --ref "$SECKIT_APPROVED_TAG"
"$HOME/.local/bin/seckit" daemon service status
```

Use the newly approved tag for later upgrades; do not assume that a moving branch identifies a release. `seckit upgrade` without `--ref` selects a newer release in the recorded channel. It requires confirmation; use `--yes` only after the owner approves unattended maintenance. It preserves the datastore, enrollment and configuration and restarts installed user supervision. It does not update Hermes or replace the integration scripts.

After upgrade, rerun the controller's `verify` action and restart Hermes/MCP so already-running processes use the new runtime. Do not rerun dotenv import or `configure` automatically; review a newly pinned integration bundle separately if it changes.

Optional same-user daily availability checks:

```bash
"$HOME/.local/bin/seckit" upgrade service install
"$HOME/.local/bin/seckit" upgrade service status
"$HOME/.local/bin/seckit" upgrade service uninstall
```

The checker never installs automatically and stores no credentials. Private checks without available authentication report unavailable. No intentional application downgrade is supported.

## Failure and recovery

Stop on failed checksum, ownership, version, layout, daemon or MCP checks. Preserve the reported configuration backup manifest. The controller's `rollback --manifest PATH` restores backed-up Hermes configuration/integration files; it is not a Secrets Kit version rollback and does not undo imported secrets. Do not uninstall or delete customer state merely to repair an integration.

Require value-free verification of healthy supervision, the three default MCP tools, scoped metadata, denied unapproved retrieval, and unchanged owner-controlled `.env`. An owner-enabled version 2 policy may add exact-name write tools; verify their grants separately. Treat `WAITING FOR PEERS` separately from daemon health. RSS enrollment and customer-controlled peer admission are separate from local Hermes integration.

## Export credentials and uninstall

When leaving Secrets Kit, follow the [generic installation skill](../../agents/install-secrets-kit/SKILL.md) and its [export and uninstall procedure](../../agents/install-secrets-kit/references/migration-and-recovery.md#export-credentials-and-uninstall) under the Hermes Unix account. Select the exact credential names and service/account scope, create a protected value-bearing `.env` with `--format dotenv-values --out PATH`, and verify it with Hermes' actual loader before cutover. Plain `export --format dotenv` contains placeholders; protected shell export is a separate recovery format.

Remove only Hermes' selected `secrets.command` source and Secrets Kit MCP registration after backing up configuration; preserve other sources and servers. Restart the selected Hermes processes and prove a fresh start works without Secrets Kit or stale dotenv fallback. Review `seckit uninstall --dry-run --archive PATH`, then use the reference's data-preserving removal command only after the replacement source passes. Uninstall does not cancel RSS billing or revoke provider credentials, and the state archive is sensitive.
