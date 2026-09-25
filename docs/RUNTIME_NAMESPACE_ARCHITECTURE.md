# Runtime Namespace Architecture

Status: design target; current source implements a smaller daemon runtime surface.

Current source note: `seckitd` uses `SECKIT_DAEMON_RUNTIME_DIR` or `SECKIT_RUNTIME_DIR`, otherwise `~/.local/share/seckit/runtime`; writes `seckitd.json`; listens on `seckitd.sock`; and binds localhost TCP using the configured port only as a request before probing for an available port. The selected endpoint is daemon operational state and may change after restart; durable endpoint lifecycle is recorded by the runtime Peer Registry. The namespace shape below is not a complete description of current runtime files.

This document describes the local peer/runtime namespace used by `seckitd` and shared runtime helpers. It is public peer-local architecture, not remote synchronization transport architecture.
- [Runtime Namespace Architecture](#runtime-namespace-architecture)
  - [Runtime Storage Policy](#runtime-storage-policy)
  - [Namespace Shape](#namespace-shape)
  - [Safety Rules](#safety-rules)
  - [Registry Behavior](#registry-behavior)
  - [Current Status](#current-status)

## Runtime Storage Policy

Runtime artifacts are ephemeral only:

- Unix sockets
- pid files
- lock files
- transient runtime registry
- temporary telemetry state
- runtime coordination state

They must not silently fall back to persistent user configuration or application-data directories. Persistent directories remain appropriate for keys, certificates, durable databases, operator configuration, and audit logs.

Target resolution order:

- Linux: `$SECKIT_RUNTIME_DIR`, then `$XDG_RUNTIME_DIR/seckit/<instance>/`, then `/run/user/<uid>/seckit/<instance>/`.
- macOS: `$SECKIT_RUNTIME_DIR`, then a per-user temp/runtime directory from stdlib APIs. `/tmp/seckit-<uid>/` requires explicit opt-in.

If no safe ephemeral runtime directory can be allocated, daemon startup fails loudly with the path, uid, permissions, and remediation hint.

## Namespace Shape

Target runtime namespace shape:

```text
<runtime-root>/<instance>/
  registry.json
  sockets/
  pids/
  locks/
  logs/
```

Default instance: `default`.

Default socket:

```text
sockets/<agent_id>.sock
```

Current daemon source uses a per-user runtime directory, a fixed socket filename inside that directory, and a localhost TCP listener whose requested port defaults to `19777` and probes upward when unavailable. The TCP port is not a stable node endpoint. Endpoint discovery and active binding update the daemon-owned routing cache; durable endpoint registration and replacement are runtime Peer Registry projections and never become node identity or authorization authority.

## Safety Rules

Runtime roots and the `sockets/`, `pids/`, and `locks/` directories must be owned by the effective uid, mode `0700`, not symlinks, and not below unsafe world-writable parents unless sticky-bit semantics and ownership validation pass.

Sockets are mode `0600`. Same-host clients are checked with Unix peer credentials where the platform supports it.

## Registry Behavior

`registry.json` is transient runtime discovery state, not durable authority. It belongs to the operating-system user that owns the daemon and must not be used as a privileged cross-user broker or as a substitute for Peer Registry authorization.

After restart, registry state is reconstructed from live runtime artifacts and endpoint re-registration. Stale entries are discarded when the pid is dead, the socket cannot be connected to, or ownership does not match the current effective uid.

The registry is useful for shell inspection and local discovery. It is not identity truth and not remote synchronization session persistence.

## Current Status

Implemented in the narrower current daemon/runtime source:

- daemon runtime directory resolution
- daemon metadata file
- daemon Unix socket path
- daemon startup lock
- localhost TCP listener with upward port probing

Partial:

- broader instance namespace and endpoint registry design

Not implemented:

- systemd/launchd socket activation
- durable runtime history
- remote synchronization session persistence
- cross-user IPC
