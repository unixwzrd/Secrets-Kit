# Integrations

## Table of Contents

- [Integrations](#integrations)
  - [Generic local stack](#generic-local-stack)
  - [Local UI or web application](#local-ui-or-web-application)
  - [Agent runtime or automation script](#agent-runtime-or-automation-script)
  - [Hermes example](#hermes-example)
  - [Hermes MCP access](#hermes-mcp-access)
  - [Hermes secret-source compatibility](#hermes-secret-source-compatibility)
    - [Human installation](#human-installation)
    - [Agentic installation](#agentic-installation)
  - [Hermes on another machine](#hermes-on-another-machine)
  - [OpenClaw example](#openclaw-example)
  - [What not to assume](#what-not-to-assume)
  - [Back to README](#back-to-readme)

---

Secrets Kit is not tied to one framework, agent, or stack. The preferred process-launch pattern is simple:

1. **Keep the values in encrypted SQLite**
2. **Run the target process through `seckit run`**
3. **Let the child process inherit only the selected environment variables**

If a tool can read environment variables from the shell that launches it, it can work with Secrets Kit.

For agent-managed setup, use the [installation skill](../integrations/agents/install-secrets-kit/SKILL.md), then the [usage skill](../integrations/agents/use-secrets-kit/SKILL.md). The [migration and recovery reference](../integrations/agents/install-secrets-kit/references/migration-and-recovery.md) covers selected credential export, verified `.env` cutover, and data-preserving uninstall. The default MCP policy is read-only; an owner-controlled version 2 policy may grant exact-name writes in its fixed service/account scope.

---

## Generic Local Stack

```bash
seckit run --service my-stack --account local-dev -- ./start-my-stack.sh
```

If you run that stack often, define defaults first:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
```

Then the handoff becomes shorter:

```bash
seckit run -- ./start-my-stack.sh
```

---

## Local UI or Web Application

```bash
seckit run --service my-ui -- npm run dev
```

This is a good fit when a development server expects tokens or API keys in the current shell but you do not want them sitting in a checked-in `.env` file.

---

## Agent Runtime or Automation Script

```bash
seckit run --service agents --account local-dev -- ./run-agents.sh
```

That model works for local agent runners, orchestrators, and shell-based automation that load credentials from environment variables at startup.

---

## Hermes Example

```bash
seckit run --service hermes --account local-dev -- ~/bin/hermes-stack restart all
```

If you keep separate environments, use separate scopes:

```bash
seckit list --service hermes --account prod
```

---

## Hermes MCP Access

Install Secrets Kit under the same Unix account that runs Hermes and install that account's managed daemon service with `seckit daemon service install`. The verified integration controller creates an isolated MCP launcher at `~/.local/libexec/seckit-hermes-mcp` and registers that launcher in Hermes `config.yaml`:

```yaml
mcp_servers:
  secrets_kit:
    command: /absolute/path/to/.local/libexec/seckit-hermes-mcp
    enabled: true
    supports_parallel_tool_calls: false
    tools:
      include:
        - seckit_status
        - seckit_list_secrets
        - seckit_get_secret
```

The MCP client exchanges messages with its local `seckit-mcp` subprocess over stdio. `seckit-mcp` uses an owner-only Unix domain socket to reach `seckitd` and does not open an MCP network port. MCP tool arguments and results remain visible to the agent host regardless of local transport; grant retrieval only when model-visible values are intended. It requires an owner-controlled policy at `~/.config/seckit/mcp-policy.json` by default; `--policy PATH` selects another owner-only policy. The policy file and its directory must belong to the current Unix account, the file must be mode `0400` or `0600`, and unsafe ownership, permissions, symlinks, unknown fields, versions, or scopes fail closed.

```json
{
  "version": 1,
  "backend": "sqlite",
  "service": "hermes-agent",
  "account": "hermes",
  "metadata_names": ["OPENROUTER_API_KEY", "ELEVENLABS_API_KEY"],
  "retrieval_names": []
}
```

Version 1 policies are read-only and fix the backend, service, account, metadata allowlist, and separate explicit-retrieval allowlist. Version 2 is an opt-in SQLite policy that adds exact `create_names`, `update_names`, and `delete_names` grants; all write names must also appear in `metadata_names`, and updates/deletes require the opaque current revision from authorized metadata. The MCP process enforces its policy before forwarding requests; the same-user daemon runtime does not receive that policy, so this boundary does not constrain other processes running as the same Unix account. Keep `retrieval_names` empty for normal provider environment injection. Adding a name explicitly authorizes `seckit_get_secret` to materialize that value into model-visible output. A value sent as a create/update tool argument is also visible to the MCP host and may be visible to its agent or model. Secret values remain prohibited from tool descriptions, logs, diagnostics, metrics, exception text, and metadata responses.

### MCP service-group best practices

Pin the MCP process in Secrets Kit's `~/.config/seckit/mcp-policy.json`, not in an instruction to the agent. The required `service` and `account` fields identify one SQLite service group: Secrets Kit derives its `service_group_id` from that pair. The server uses those fixed fields for every metadata, retrieval, and permitted write request; a tool caller cannot select another service, account, or group. Keep one authoritative pair in the policy rather than adding a second group identifier that could disagree with it. Hermes' `config.yaml` selects the MCP launcher and exposed tools but does not grant datastore scope.

Use a dedicated service/account pair for the agent and grant only the names it needs in `metadata_names`. Leave `retrieval_names` empty unless the owner intends the model to receive those exact values; restrict each optional version 2 write list to exact names. The integration controller generates a version 1 policy with retrieval denied by default. Review the resulting file before enabling the MCP server, especially after importing many environment variables. Store no secret values in the policy. Keep its directory owned by the running Unix user and not group- or world-writable, and keep the file owner-only at mode `0400` or `0600`. Reconnect the MCP server after an authorized policy change so the new process loads it.

The policy is an MCP tool boundary, not a sandbox for other processes under the same Unix account. An agent with unrestricted file or shell access as that user can read or replace the policy and may access Secrets Kit through the CLI or daemon. Run a less-trusted agent under a separate Unix identity if it must be prevented from exercising the human user's authority. Treat MCP session exports as sensitive whenever retrieval or write values were exposed to the model; use host-side startup injection when the model does not need a value.

---

## Hermes Secret-Source Compatibility

Hermes PR [#59498](https://github.com/NousResearch/hermes-agent/pull/59498) establishes a pluggable, read-only `SecretSource` interface for startup-time environment resolution. Current Hermes builds also provide a generic `secrets.command` source. A Secrets Kit integration can use that existing source with a fast, non-interactive helper that:

1. Selects an explicit allowlist of Hermes variables.
2. Invokes installed `seckit run` against the local Hermes service/account.
3. Emits only those selected single-line `KEY=VALUE` records on stdout.
4. Never emits values to logs, diagnostics, or stderr.

This follows Hermes' existing precedence, conflict-warning, provenance, and bounded-fetch behavior without adding Secrets Kit to Hermes core. Keep `override_existing: false` during migration so an existing `.env` remains the deterministic fallback until qualification passes. Do not invoke `/usr/bin/env` directly: it would expose and import unrelated process variables.

Process startup resolution and MCP retrieval are separate boundaries. Startup resolution supplies provider variables without turning them into model tool results. MCP retrieval is an intentional, model-visible operation.

### Human installation

1. Under the Hermes Unix account, follow the exact pinned-artifact `preflight` and `install` commands in the [Hermes integration skill](../integrations/hermes/install-secrets-kit-for-hermes/SKILL.md). Verify the release manifest against an independently trusted checksum.
2. Review the explicit dotenv name allowlist, then run the skill's `configure` command. It backs up Hermes configuration, performs a redacted import into encrypted SQLite, installs the same-user daemon, creates the isolated helper and MCP launchers, and registers the MCP launcher with retrieval denied by default. Leave `.env` unchanged.
3. Run the skill's `verify` command, restart Hermes, and repeat verification. `WAITING FOR PEERS` describes peer discovery and does not mean the local daemon is unavailable; check daemon health separately.
4. During migration, `.env` may still take precedence because `override_existing: false` is deliberate. Delete or securely archive `.env` only after separate owner authorization and a successful credential-rotation test; a successful import alone does not prove Hermes sources those variables from Secrets Kit.

### Agentic installation

The integration directory under `integrations/hermes/install-secrets-kit-for-hermes/` contains the agent skill, controller and security reference. The controller's `preflight` and `install` actions accept the current GitHub release asset layout, including `source-commit.txt`, `installer-pins.sha256`, and `release-origin.json`; they require an independently trusted manifest checksum. After installation, run `configure` and `verify` with the installed runtime's Python. Never fabricate a receipt or rewrite a release manifest to bypass verification. Configuration preserves unrelated Hermes state, imports only approved names, installs same-user supervision and denies MCP retrieval unless separately authorized.

Agents must use a pinned release tag and verified bundle. Unpinned `main`, unverified raw scripts, and `curl | sh` are prohibited.

---

### Upgrading Secrets Kit for Hermes

Run `seckit upgrade --check`, then an owner-approved `seckit upgrade` or `seckit upgrade --ref TAG` with the exact qualified non-older tag supplied for this installation. Keep the repository/channel recorded at installation; private releases require authentication. Verify daemon health, rerun integration verification and restart Hermes/MCP after upgrade. Do not reinitialize the datastore or repeat dotenv import automatically. This updates Secrets Kit, not Hermes or the separately pinned integration files. Optional `seckit upgrade service install` enables daily checks only. The controller's `rollback` restores Hermes configuration, not an older Secrets Kit runtime.

## Hermes on Another Machine

Secrets Kit is local-first. If Hermes runs on another machine, install and run Secrets Kit on that Hermes host under the Hermes Unix account. The MCP process, daemon socket, protected RSS identity, and SQLite state must all be local to that account. Do not point a remote Hermes process at a developer machine's SQLite database or same-user daemon socket.

Use RSS synchronization to deliver encrypted secret state to the Hermes host, then let Hermes read its synchronized local state through `seckit run` and `seckit-mcp`.

---

## OpenClaw Example

```bash
seckit run --service openclaw --account local-dev -- ~/bin/openclaw-stack restart all
```

If you need to create a new service scope from an existing one:

```bash
seckit service copy --from-service openclaw --to-service hermes --dry-run
seckit service copy --from-service openclaw --to-service hermes
```

If you use wrappers that already know how to pull from Secrets Kit, keep those wrappers as the integration point and let them handle `run` during startup.

---

## What Not to Assume

Secrets Kit does not change the security model of the runtime you start afterward. Once a process inherits secrets in its environment, that process can access what it needs to access. Secrets Kit is about reducing secret sprawl and improving local hygiene, **not** about creating a hardened isolation boundary around every downstream tool.

---

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-11-03
