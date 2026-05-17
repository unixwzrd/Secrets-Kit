# Runtime Namespace Architecture

Status: partially implemented.

This document describes the local peer/runtime namespace used by `seckitd` and shared runtime helpers. It is public peer-local architecture, not hosted relay architecture.

## Runtime Storage Policy

Runtime artifacts are ephemeral only:

- Unix sockets
- pid files
- lock files
- transient runtime registry
- temporary telemetry state
- runtime coordination state

They must not silently fall back to persistent user configuration or application-data directories. Persistent directories remain appropriate for keys, certificates, durable databases, operator configuration, and audit logs.

Resolution order:

- Linux: `$SECKIT_RUNTIME_DIR`, then `$XDG_RUNTIME_DIR/seckit/<instance>/`, then `/run/user/<uid>/seckit/<instance>/`.
- macOS: `$SECKIT_RUNTIME_DIR`, then a per-user temp/runtime directory from stdlib APIs. `/tmp/seckit-<uid>/` requires explicit opt-in.

If no safe ephemeral runtime directory can be allocated, daemon startup fails loudly with the path, uid, permissions, and remediation hint.

## Namespace Shape

Each runtime instance has this shape:

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

There is no machine-global socket and no fixed localhost port.

## Safety Rules

Runtime roots and the `sockets/`, `pids/`, and `locks/` directories must be owned by the effective uid, mode `0700`, not symlinks, and not below unsafe world-writable parents unless sticky-bit semantics and ownership validation pass.

Sockets are mode `0600`. Same-host clients are checked with Unix peer credentials where the platform supports it.

## Registry Behavior

`registry.json` is transient runtime discovery state, not durable authority.

After restart, registry state is reconstructed from live runtime artifacts and endpoint re-registration. Stale entries are discarded when the pid is dead, the socket cannot be connected to, or ownership does not match the current effective uid.

The registry is useful for shell inspection and local discovery. It is not identity truth and not relay session persistence.

## Implemented / Partial / Deferred

Implemented:

- instance-aware runtime path helpers
- fail-fast runtime directory allocation
- local socket naming by agent id
- transient endpoint registration helpers
- stale endpoint cleanup helpers

Partial:

- `seckitd` still carries provisional local runtime operations
- runtime telemetry is local and in-memory

Deferred:

- systemd/launchd socket activation
- durable runtime history
- hosted relay session persistence
- cross-user IPC

