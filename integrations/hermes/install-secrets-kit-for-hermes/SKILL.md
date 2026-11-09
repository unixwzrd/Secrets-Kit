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

Install a pinned Secrets Kit release under the Unix account that runs Hermes. Import only explicitly approved dotenv names and register read-only stdio MCP. Do not modify Hermes core, delete `.env`, expose a network MCP listener, publish artifacts or enable live billing.

## Required inputs

- The approved exact release tag for this installation; beta qualification does not imply a stable production release.
- The release repository, downloaded asset directory and independently trusted manifest checksum.
- The integration directory from a separately verified immutable source revision or integration bundle. A skill file alone is not the scripts and references it links to.
- The absolute Hermes executable path and existing `HERMES_HOME`.
- The owner-controlled dotenv file (mode `0600` or stricter) and explicit environment-name allowlist.
- Separate owner approval for any model-visible MCP retrieval names; these must be a subset of the environment allowlist.

Read [security boundaries](references/security-boundaries.md) before acting. Never execute unverified scripts, use an unpinned branch, print credential files, or trust a checksum merely because it is included in the same download.

## Install from the GitHub artifacts

The current GitHub release layout contains `install.sh`, `source-commit.txt`, `manifest.sha256`, a client wheel, a pinned libp2p companion wheel and a source archive. It does not contain the legacy controller's `release-id` layout.

Do not run the controller's legacy `preflight` or `install` actions against these assets, fabricate `release-id`, or rewrite the release manifest to satisfy them. Use the supported artifact installer below, then the controller's `configure` and `verify` actions. Legacy bundle-adapter modernization is separate from this documented path.

1. Verify the manifest hash against the independently supplied value, then every manifest entry. Use `sha256sum` on Linux when `shasum` is absent.
2. Show a sanitized installation/configuration plan and obtain approval before changing state.
3. Set `SECKIT_GITHUB_REPO` to the supplied owner/repository and `SECKIT_RELEASE_CHANNEL=prerelease`. Private downloads require authenticated access; collaborator access is not anonymous.
4. Run from the verified asset directory as the Hermes user, without sudo:

```bash
shasum -a 256 manifest.sha256
shasum -a 256 -c manifest.sha256
: "${SECKIT_APPROVED_TAG:?set the exact independently approved release tag}"
wheel="seckit-${SECKIT_APPROVED_TAG#v}-py3-none-any.whl"
test -f "$wheel"
SECKIT_WHEEL_URL="file://$PWD/$wheel" bash ./install.sh --ref "$SECKIT_APPROVED_TAG" --yes --no-init --no-shell-profile
"$HOME/.local/bin/seckit" --version
"$HOME/.local/bin/seckit" doctor --install-check
```

Keep the companion wheel beside the installer. The installer provisions UV and Python; do not require system Python or GitHub CLI. For a genuinely empty account, initialize the encrypted store once:

```bash
"$HOME/.local/bin/seckit" init
```

Do not reinitialize an existing datastore or use `--yes` to suppress an existing-state warning.

## Configure and verify

Use the installed runtime's Python and the absolute verified integration path. The commands below contain placeholders for user-supplied paths; resolve them before execution.

```bash
"$HOME/.local/share/seckit/runtime/current/bin/python" -B /absolute/path/to/integration/scripts/hermes_secrets_kit.py configure \
  --hermes-command /absolute/path/to/hermes \
  --dotenv /absolute/path/to/.env \
  --account hermes --service hermes-agent \
  --names OPENROUTER_API_KEY,ELEVENLABS_API_KEY

"$HOME/.local/share/seckit/runtime/current/bin/python" -B /absolute/path/to/integration/scripts/hermes_secrets_kit.py verify \
  --hermes-command /absolute/path/to/hermes
"$HOME/.local/bin/seckit" daemon service status
```

Configuration backs up Hermes configuration, performs a redacted import of only the allowlisted names, installs the same-user managed daemon, configures the existing `secrets.command` source and creates an owner-only fixed-scope MCP policy. Retrieval is denied by default. Add `--mcp-retrieval-names NAME_ONE` only with explicit owner authorization for that model-visible value.

Restart Hermes and repeat verification. Preserve unrelated MCP servers. Leave `.env` unchanged: `override_existing: false` means existing environment values may take precedence until the owner explicitly approves cutover. Never capture the helper's value-bearing output in an agent transcript or diagnostic report.

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

Require value-free verification of healthy supervision, exactly three read-only MCP tools, scoped metadata, denied unapproved retrieval, and unchanged owner-controlled `.env`. Treat `WAITING FOR PEERS` separately from daemon health. RSS enrollment and customer-controlled peer admission are separate from local Hermes integration.
