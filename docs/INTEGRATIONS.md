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

1. **Keep the values in Keychain**
2. **Run the target process through `seckit run`**
3. **Let the child process inherit only the selected environment variables**

If a tool can read environment variables from the shell that launches it, it can work with Secrets Kit.

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

Install Secrets Kit under the same Unix account that runs Hermes, install that account's managed daemon service with `seckit daemon service install`, and register the installed absolute `seckit-mcp` path in Hermes `config.yaml`:

```yaml
mcp_servers:
  secrets_kit:
    command: /absolute/path/to/.local/bin/seckit-mcp
    enabled: true
    supports_parallel_tool_calls: false
    tools:
      include:
        - seckit_status
        - seckit_list_secrets
        - seckit_get_secret
```

`seckit-mcp` uses stdio and does not open a localhost network port. It requires an owner-controlled policy at `~/.config/seckit/mcp-policy.json` by default; `--policy PATH` selects another owner-only policy. The policy file and its directory must belong to the current Unix account, the file must be mode `0400` or `0600`, and unsafe ownership, permissions, symlinks, unknown fields, versions, or scopes fail closed.

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

The policy fixes the backend, service, account, metadata allowlist, and separate explicit-retrieval allowlist. The MCP caller cannot select another datastore scope. Keep `retrieval_names` empty for normal provider environment injection. Adding a name explicitly authorizes `seckit_get_secret` to materialize that value into model-visible output. Secret values remain prohibited from tool descriptions, logs, diagnostics, metrics, exception text, and metadata responses.

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

1. Install a pinned, verified Secrets Kit artifact under the Hermes Unix account.
2. Back up Hermes `config.yaml` and leave `.env` unchanged.
3. Run `seckit import env --dotenv /absolute/path/to/.env --names NAME_ONE,NAME_TWO --dry-run` and confirm every value is redacted and only the explicitly allowlisted names appear.
4. Import the same exact allowlist into encrypted SQLite, create the owner-only MCP policy with an empty retrieval allowlist, then run `seckit daemon service install` and verify `seckit daemon service status` reports a healthy managed service.
5. Configure `secrets.command` with the installed allowlist helper and keep `override_existing: false` during migration.
6. Register MCP through the supported command:

   ```bash
   printf 'y\n' | /absolute/path/to/hermes mcp add secrets_kit \
     --command /absolute/path/to/.local/bin/seckit-mcp
   /absolute/path/to/hermes mcp test secrets_kit
   ```

7. Restart Hermes and verify startup-source application plus MCP discovery. `WAITING FOR PEERS` describes peer discovery and does not mean the local daemon is unavailable; verify the separate daemon-health field.
8. During migration, `.env` still takes precedence because `override_existing: false` is deliberate. Delete or securely archive `.env` only after separate owner authorization and a successful credential-rotation test; until that cutover, a successful Secrets Kit import does not prove Hermes is sourcing those variables from Secrets Kit.

### Agentic installation

The integration directory under `integrations/hermes/install-secrets-kit-for-hermes/` contains the agent skill, controller and security reference. For a9 GitHub assets, install through the verified release installer, then use the controller's `configure` and `verify` actions with the installed runtime's Python. The controller's legacy `preflight`/`install` adapter expects a different `release-id` manifest layout and must not be used with unmodified GitHub assets. Never fabricate a receipt or rewrite a release manifest to bypass that check. Configuration preserves unrelated Hermes state, imports only approved names, installs same-user supervision and denies MCP retrieval unless separately authorized.

Agents must use a pinned release tag and verified bundle. Unpinned `main`, unverified raw scripts, and `curl | sh` are prohibited.

---

### Upgrading Secrets Kit for Hermes

Run `seckit upgrade --check`, then an owner-approved `seckit upgrade` or `seckit upgrade --ref v2.0.1b11`. Keep the repository/channel recorded at installation; private releases require authentication. Verify daemon health, rerun integration verification and restart Hermes/MCP after upgrade. Do not reinitialize the datastore or repeat dotenv import automatically. This updates Secrets Kit, not Hermes or the separately pinned integration files. Optional `seckit upgrade service install` enables daily checks only. The controller's `rollback` restores Hermes configuration, not an older Secrets Kit runtime.

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
**Updated**: 2026-08-14
