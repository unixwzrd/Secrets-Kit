# Hermes Integration Security Boundaries

- Secrets Kit remains local-first. Install it under the Hermes Unix account.
- RSS synchronizes encrypted state to that local account; it is not exposed to Hermes and is not an application datastore.
- Startup environment resolution uses Hermes' existing `secrets.command` source. Keep `override_existing: false` while `.env` remains the fallback.
- The command helper may emit only explicitly allowlisted single-line values.
- Hermes helper and MCP launchers invoke the installed Secrets Kit runtime Python with isolated mode and remove inherited Conda/native-loader overrides before launch; the helper also clears each selected variable before `seckit run`, so it cannot silently fall back to an inherited dotenv value.
- The dotenv import must use the same exact allowlist and fail closed if any requested name is absent.
- Reject `PYTHON*`, `CONDA_*`, `DYLD_*`, `LD_*`, `OPENSSL_*`, and `VIRTUAL_ENV` from that allowlist; credentials must not override interpreter or native-library loading.
- Configuration installs a same-user managed daemon service. MCP remains fail-closed and must not silently spawn the daemon.
- `WAITING FOR PEERS` is a peer-discovery state; daemon availability is reported separately.
- MCP status and listing return metadata only. `seckit_get_secret` is the only intentional model-visible materialization boundary.
- Hermes talks to its local `seckit-mcp` subprocess over stdio. That subprocess talks to the same-user daemon over an owner-only Unix domain socket; it does not expose an MCP HTTP or TCP listener. The owner-only MCP policy fixes the backend, service, account, metadata allowlist, and a separate retrieval allowlist that defaults empty. Transport choice does not hide MCP tool arguments or results from Hermes or its model; leave retrieval ungranted unless model-visible values are explicitly intended.
- The v1 integration verifier requires exactly `seckit_status`, `seckit_list_secrets`, and `seckit_get_secret`, all marked read-only and non-destructive. A later policy version that adds writes must update this expected tool and permission contract explicitly.
- Never write secret values to logs, metrics, exceptions, manifests, command arguments, tool descriptions, or retained qualification evidence.
- Back up `config.yaml`, `.env` metadata, and any replaced integration file before mutation. Do not delete customer-controlled `.env` automatically.
- Hermes MCP registrations are stored in `config.yaml` under `mcp_servers`; the integration rollback restores that backed-up file together with its generated launchers and policy.
- Reject unpinned releases, checksum mismatches, unexpected bundle layouts, symlinks, writable release artifacts, unknown architectures, and wrong file ownership.
