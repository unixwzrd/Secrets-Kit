---
name: use-secrets-kit
description: Use an installed Secrets Kit MCP server and scoped environment injection for agent credentials. Use for authorized discovery, retrieval, and credential-maintenance requests; installation and recovery are separate.
license: MIT
---

# Manage access credentials with Secrets Kit

Use Secrets Kit as the local credential store belonging to the application's Unix account. Respect its owner-controlled service/account scope and allowed names. Skill installation does not grant credential access or register the MCP server.

## Check capability, not assumptions

Connect to the approved absolute `seckit-mcp` executable using the host's stdio MCP configuration. The same-user managed daemon must already be healthy; MCP must not silently initialize a store or start a replacement daemon. No network MCP listener is required.

Version 1 MCP policies are read-only. A version 2 policy may expose exact-name write tools; inspect the installed server's catalog before acting:

| Tool | Arguments | Result |
| --- | --- | --- |
| `seckit_status` | `{}` | Local runtime status; no credential values. |
| `seckit_list_secrets` | `{}` | Policy-allowed metadata; not a complete inventory of every scope. |
| `seckit_get_secret` | `{"name":"APP_API_KEY"}` | One explicitly authorized value, visible to the model/tool host. |

Use the connected server's `tools/list` schemas and the installed release's documentation. Do not guess additional tool names or fields. An error result or `isError` is not a retrieved value. When unavailable/denied, report that distinction without interpreting it as an empty store, resetting anything, or widening permissions.

Status can report waiting for peers while local use is healthy. No peers is not a reason to enroll in paid RSS or change networking for local application access.

## Prefer supplying credentials to the application

Use the application's approved startup integration or `seckit run` when a program needs a credential but the model does not. This keeps the value out of MCP tool results:

```bash
/usr/bin/env -u PYTHONPATH -u PYTHONHOME -u VIRTUAL_ENV "$HOME/.local/bin/seckit" run --service my-agent --account local --names APP_API_KEY -- /absolute/path/to/application
```

The command uses example scope/name selectors; replace them with the approved selectors and application command. Do not wrap a process that dumps its environment or logs supplied credentials. Existing environment values and dotenv fallback can mask a broken integration, so installation cutover must be tested separately.

## Retrieve only when the task needs the value

1. Call `seckit_status` to establish availability, then list authorized metadata if discovery is needed.
2. Select a name justified by the task and permitted by policy. Do not fetch the whole allowlist just to test connectivity.
3. Call `seckit_get_secret` only if the owner has authorized model-visible retrieval for that name. The policy's `retrieval_names` is separate from `metadata_names`.
4. Use the value only for the approved operation and destination. Do not repeat it in prose, retain it in memory, write it into commands/configuration, include it in diagnostics, or forward it to another service merely because it is readable.
5. If retrieval is denied, request the exact missing permission through the owner. Do not edit the policy, try another backend/account, or use CLI retrieval as an automatic bypass.

Model-visible retrieval is not end-to-end secret hiding: the MCP host may retain arguments and results. Avoid such retrieval where startup injection or a local file import meets the task.

## Add, update, rotate, or delete credentials

The current server can expose `seckit_create_secret`, `seckit_update_secret`, and `seckit_delete_secret` only under an owner-controlled version 2 policy with exact `create_names`, `update_names`, and `delete_names` grants in one fixed service/account scope. Version 1 policies and version 2 policies without those grants remain read-only. Use the installed `tools/list` schemas; do not invent fields, change policy, or fall back to unrestricted terminal access. Create refuses an existing name. Update and delete require the current opaque revision from authorized metadata and reject a stale revision. Confirm the exact name and intended operation before mutation; deletion cannot be inferred from a missing value in one source file. Tool results contain no credential value, but a value submitted to create/update can be retained by the MCP host or exposed to the model. Prefer an approved local file import when model-visible values are unnecessary.

There is no provider-rotation tool: changing a stored credential does not rotate or revoke it at the external provider. If the installed policy does not expose the required write, explain the missing permission. A separately authorized local CLI operation must follow its documented `set --stdin`, `import env --dotenv`, or scoped `delete` path; do not use it to bypass an MCP denial automatically.

Do not change Secrets Kit's own storage/identity keys, peer admission, RSS device credentials, billing-owner credentials, or authorization policy as ordinary application-credential maintenance.

## Verification and failures

For a permitted read, consume the returned value without echoing it. For startup injection, use application health/functional checks and a synthetic canary; do not dump the environment or print all retrieved values. A local verifier can report equality/counts without recording values or per-secret hashes.

When software updates, restart the approved MCP connection/application and verify the reported version and catalog again. Do not reinitialize or rerun old imports. If installation, policy registration, recovery, credential exit export, or uninstall is needed, use the companion `install-secrets-kit` skill from the same approved repository revision. Export and verify the replacement application source before removing software; uninstall is not credential deletion or subscription cancellation.

Copy this entire skill folder into the host's documented user skill directory for persistent discovery if wanted. Keep the installation skill and verified source integration available separately; a skill is instructions, not an installer or access grant.
