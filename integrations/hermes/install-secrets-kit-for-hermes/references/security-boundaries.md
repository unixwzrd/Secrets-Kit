# Hermes Integration Security Boundaries

- Secrets Kit remains local-first. Install it under the Hermes Unix account.
- RSS synchronizes encrypted state to that local account; it is not exposed to Hermes and is not an application datastore.
- Startup environment resolution uses Hermes' existing `secrets.command` source. Keep `override_existing: false` while `.env` remains the fallback.
- The command helper may emit only explicitly allowlisted single-line values.
- The dotenv import must use the same exact allowlist and fail closed if any requested name is absent.
- Configuration installs a same-user managed daemon service. MCP remains fail-closed and must not silently spawn the daemon.
- `WAITING FOR PEERS` is a peer-discovery state; daemon availability is reported separately.
- MCP status and listing return metadata only. `seckit_get_secret` is the only intentional model-visible materialization boundary.
- MCP uses stdio only and must not expose an HTTP or TCP listener. Its owner-only policy fixes the backend, service, account, metadata allowlist, and a separate retrieval allowlist that defaults empty.
- Never write secret values to logs, metrics, exceptions, manifests, command arguments, tool descriptions, or retained qualification evidence.
- Back up `config.yaml`, `.env` metadata, and any replaced integration file before mutation. Do not delete customer-controlled `.env` automatically.
- Reject unpinned releases, checksum mismatches, unexpected bundle layouts, symlinks, writable release artifacts, unknown architectures, and wrong file ownership.
