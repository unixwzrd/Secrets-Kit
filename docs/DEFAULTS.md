# Defaults

New installations default to encrypted SQLite on macOS and Linux with ordinary `seckit init`. Existing configured backend choices, including Keychain, remain authoritative; upgrading does not migrate secrets or change the configured backend. Ordinary commands do not need `--backend`.

- [Defaults](#defaults)
  - [Environment defaults](#environment-defaults)
    - [SQLite backend environment (`--backend sqlite`)](#sqlite-backend-environment---backend-sqlite)
    - [Where the SQLite file lives](#where-the-sqlite-file-lives)
    - [Daemon runtime environment](#daemon-runtime-environment)
  - [Config file defaults](#config-file-defaults)
  - [CLI: `seckit config`](#cli-seckit-config)
  - [Notes](#notes)

Defaults are here to make repeated daily use less noisy. If you are always working in the same local scope, you should not have to type `--service` and `--account` every time.

Resolution order:

1. Explicit CLI flags
2. `SECKIT_DEFAULT_*` environment variables
3. `~/.config/seckit/defaults.json`
4. current OS user for `account` only

**`~/.config/seckit/config.json`:** merged after `defaults.json` only for ordinary CLI defaults missing from `defaults.json`. The daemon also reads `daemon_tcp_port` and `daemon_peers` from this file. Unsupported `backend` values are **not** rewritten automatically—`seckit` fails during defaults application until you set `backend` to `keychain` or `sqlite`.

**`seckit list`:** lists metadata entries from the configured backend. It does not enumerate arbitrary generic passwords from Keychain Access.

## Environment defaults

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
export SECKIT_DEFAULT_TYPE=secret
export SECKIT_DEFAULT_KIND=api_key
export SECKIT_DEFAULT_TAGS=primary
export SECKIT_DEFAULT_ROTATION_DAYS=90
export SECKIT_DEFAULT_ROTATION_WARN_DAYS=14
export SECKIT_DEFAULT_BACKEND=keychain
```

Then:

```bash
seckit list
seckit run -- python3 app.py
```

That is usually the best fit for an interactive shell session or a one-off runtime launch.

### SQLite backend environment (`--backend sqlite`)

Current SQLite support is development-oriented local storage. Use `--backend sqlite` to select it.

Optional SQLite database location override:

```bash
export SECKIT_SQLITE_PATH=/path/to/seckit.sqlite
```

The SQLite backend is currently:
- local-only
- single-process/single-writer oriented
- standalone
- usable without starting `seckitd`

SQLite encryption design is intentionally unspecified and must not assume:
- environment-variable passphrases
- vault-password workflows
- Keychain-managed wrapping keys
- daemon-managed unlock semantics
- transport-coupled encryption

### Where the SQLite file lives

| What           | Path or source                            |
| -------------- | ----------------------------------------- |
| Default file   | `~/.config/seckit/seckit.sqlite`          |
| Override order | `SECKIT_SQLITE_PATH` → default path above |

The directory `~/.config/seckit` is created on demand with restricted permissions when registry/defaults/SQLite state is first written.

SQLite files are intended for local standalone operation. Directly syncing live SQLite databases through cloud file sync, network shares, or similar tooling is not supported and may corrupt the database or create conflicting writes.

The daemon selects the `libp2p` adapter by default. It uses Ed25519 identity and Noise only; SECIO, plaintext libp2p, and TLS fallback are excluded. Local discovery and bootstrap values locate endpoints only and do not authorize peers. Direct TCP remains a compatibility transport only when explicitly selected. Failure to start the selected adapter is fatal and never causes an automatic downgrade.
Relay reservations, AutoNAT, DCUtR, RSS synchronization, and production cross-host qualification remain separate capabilities.

### Daemon runtime environment

The local daemon uses runtime state separate from `defaults.json`.

| Setting           | Source                                                                               |
| ----------------- | ------------------------------------------------------------------------------------ |
| Runtime directory | `SECKIT_DAEMON_RUNTIME_DIR` → `SECKIT_RUNTIME_DIR` → `~/.local/share/seckit/runtime` |
| Metadata file     | `<runtime-dir>/seckitd.json`                                                         |
| Unix socket       | `<runtime-dir>/seckitd.sock`                                                         |
| Startup lock      | `<runtime-dir>/seckitd.start.lock`                                                   |
| Default TCP host  | libp2p resolves the unspecified host to the selected LAN IPv4 address; loopback-only while no eligible LAN is available, never a wildcard/VPN fallback |
| TCP host override | `SECKIT_DAEMON_TCP_HOST` or `daemon_tcp_host` in `~/.config/seckit/config.json`      |
| Requested TCP port | `0` for an automatically assigned endpoint; an explicit configured value remains supported |
| TCP port request override | `SECKIT_DAEMON_TCP_PORT` or `daemon_tcp_port` in `~/.config/seckit/config.json` |
| Advertised endpoint override | `SECKIT_DAEMON_ADVERTISED_ENDPOINT` (optional; use when the bind address is not externally reachable) |
| Transport substrate | `SECKIT_DAEMON_TRANSPORT` (`libp2p` by default; `direct_tcp` requires the explicit unsafe test override `SECKIT_UNSAFE_TEST_DIRECT_TCP=1`) |
| Local discovery | enabled for libp2p on one active IPv4 LAN default-route interface, excluding point-to-point VPN interfaces; `SECKIT_DAEMON_DISCOVERY=0` disables it |
| Bootstrap peers | `SECKIT_DAEMON_BOOTSTRAP` comma-separated libp2p multiaddrs |
| Relay peers | `SECKIT_DAEMON_RELAY_PEERS` comma-separated relay multiaddrs; client reservations use libp2p when configured |
| Configured peers  | `SECKIT_DAEMON_PEERS` or `daemon_peers` in `~/.config/seckit/config.json`            |
| Operational libp2p identity | owner-only `libp2p-identity.key` in the daemon runtime directory; retained across restart |

Local discovery advertises the current dynamically allocated listener port. It selects an active broadcast/multicast LAN interface from the operating system's IPv4 default routes, excluding loopback and point-to-point interfaces, and refreshes membership when the selected address changes. If no eligible LAN default route exists, it waits for one instead of advertising a VPN address. It does not discover all secondary network interfaces simultaneously or bypass a firewall. Announcements supply untrusted endpoints only: signed peer admission and service-group authorization still control synchronization. RSS routing is independent of this LAN discovery choice. The pinned shared-library repair supports concurrent Unix users on one explicit LAN interface; complete installed synchronization qualification is tracked separately.

Peer entries use `host:port`, `node_id@host:port`, or
`node_id@/ip4/.../tcp/.../p2p/...`. These settings configure transport bootstrap hints only. The daemon selects and publishes its active endpoint at runtime; the endpoint may change after restart or host-network changes. Endpoint data is not node identity, durable application state, peer authorization, discovery authority, RSS synchronization, hosted routing, or remote authority. Failed delivery attempts are reported by `seckit status` and envelope inspection commands. Wildcard listener addresses are bind state only and are not eligible peer routes.

## Config file defaults

Create `~/.config/seckit/defaults.json`:

```json
{
  "service": "my-stack",
  "account": "local-dev",
  "type": "secret",
  "kind": "api_key",
  "tags": "primary",
  "default_rotation_days": 90,
  "rotation_warn_days": 14,
  "backend": "keychain"
}
```

That is the better choice when you want stable defaults across shells and reboots.

## CLI: `seckit config`

Write the same keys without editing JSON by hand:

```bash
seckit config path
seckit config show
seckit config set backend keychain
seckit config set service my-stack
seckit config unset backend
```

Merged view (`defaults.json` + `config.json` + `SECKIT_DEFAULT_*` env):

```bash
seckit config show --effective
```

Allowed `seckit config set` keys: `service`, `account`, `backend`, `type`, `kind`, `tags`, `default_rotation_days`, `rotation_warn_days`.

Daemon-only keys such as `daemon_tcp_host`, `daemon_tcp_port`, and `daemon_peers` are read from `~/.config/seckit/config.json` if present, but are not managed by `seckit config set`.

See:

```bash
seckit config set -h
```

Secrets and raw secret material must never be stored in `defaults.json`.

## Notes

- Defaults are optional.
- Secrets never belong in config files or shell defaults.
- `service` must be explicit or configured when a command needs a service scope.
- `account` falls back to the current OS user when not explicit or configured.
- Backend identity is separate from security posture.
- Canonical storage backends are:
  - `keychain`
  - `sqlite`
- Current Keychain backend uses the macOS `security` CLI and platform Keychain storage.
- SQLite is a local storage backend selected with `--backend sqlite`.
- `seckitd` runtime state is informational/transport state, not backend authority.
- Cross-host P2P, peer discovery, and RSS synchronization are not current operator CLI workflows.
- Use defaults for repeated operational scope information, not for secret material.

[Back to README](../README.md)

**Updated**: 2026-06-07
