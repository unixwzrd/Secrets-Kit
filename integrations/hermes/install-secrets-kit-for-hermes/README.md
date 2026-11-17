# Secrets Kit integration for Hermes

Read [SKILL.md](SKILL.md) and [security boundaries](references/security-boundaries.md) before running the integration scripts.

For agent-managed installation, use the [generic installation skill](../../agents/install-secrets-kit/SKILL.md) and [usage skill](../../agents/use-secrets-kit/SKILL.md) from the same approved revision. To leave Secrets Kit, follow the [protected credential export and uninstall procedure](../../agents/install-secrets-kit/references/migration-and-recovery.md#export-credentials-and-uninstall) and the [Hermes-specific cutover steps](SKILL.md#export-credentials-and-uninstall). Verify the replacement credential source on a fresh Hermes start before removing the runtime; plain `dotenv` export contains placeholders, while `dotenv-values --out` writes actual values.

Use the exact qualified client tag supplied for this installation; the skill metadata's `0.1.0` identifies the integration package, not the client version. Obtain this directory from a verified immutable integration revision supplied by the operator; documentation fixes after a tag are not retroactively present in that tag.

The GitHub release asset bundle and this integration directory are separate inputs. The controller's `preflight` and `install` actions accept the current release layout (`source-commit.txt`, `installer-pins.sha256`, `release-origin.json`, client/source artifacts and manifest), verify the full manifest against an independently supplied SHA-256, and check the selected tag and source provenance. They do not require the retired `release-id` file. Follow [SKILL.md](SKILL.md) for the exact command and safe configure/verify workflow.

## Agent handoff prompt

Copy this prompt and supply the inputs below:

> Read the complete pinned Secrets Kit Hermes skill and its security-boundaries reference before acting. Validate the independently supplied release manifest checksum and all artifacts. Show a sanitized change plan. Install or upgrade Secrets Kit only under the Hermes Unix account, using the supported release installer or seckit upgrade; never reinitialize an existing datastore. Use the installed runtime's Python for the integration controller. Back up Hermes configuration, preserve unrelated MCP servers, leave .env unchanged and import only explicitly approved names. Keep MCP retrieval denied unless the owner separately approves exact names. Verify the managed daemon and integration, restart Hermes/MCP after an upgrade, and repeat value-free verification. Stop on any checksum, ownership, version, layout, daemon or MCP failure. Never print secret values, RETs, private keys, environment dumps or credential files. Configuration rollback is not an application downgrade.

Supply:

- Exact release tag, repository and artifact directory.
- Independently trusted manifest checksum.
- Verified immutable integration directory/revision.
- Absolute Hermes command path and `HERMES_HOME`.
- Dotenv path and explicit environment-variable allowlist.
- Separately approved MCP retrieval names, if any.
- RSS enrollment/peer-admission instructions only if remote synchronization is in scope.

## Existing installation

Use `seckit upgrade --check`, then an owner-approved `seckit upgrade` or exact non-older `--ref`. This preserves customer state and does not update the integration files. Follow the skill's post-upgrade verification and restart steps. Optional daily checks never install automatically.

Migration leaves `.env` intact and uses `override_existing: false`; existing values may still take precedence until explicitly authorized cutover. Do not confuse a working fallback with proof that Hermes read the new secret source.
