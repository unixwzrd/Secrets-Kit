# CLI architecture — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-08-20

How the `seckit` CLI relates to **registry**, **backends**, **diagnostics**, **authority**, and **materialization**. This is operator-facing architecture, not Python module layout. Current parser registration lives under `src/secrets_kit/cli/parsers/`; command handlers live under `src/secrets_kit/cli/commands/`. Normative terms: [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

- [CLI architecture — Secrets Kit](#cli-architecture--secrets-kit)
  - [Authority vs catalog](#authority-vs-catalog)
  - [Diagnostics and inspection](#diagnostics-and-inspection)
  - [`list` semantics (capability-driven)](#list-semantics-capability-driven)
  - [Safe output policy](#safe-output-policy)
  - [Daemon / Machine API Scope](#daemon--machine-api-scope)
  - [Process and supervision lifecycle](#process-and-supervision-lifecycle)
  - [Command Hierarchy Compatibility](#command-hierarchy-compatibility)
  - [Related docs](#related-docs)

## Authority vs catalog

- **Authority** — Secret payload and rich metadata as stored in the backend (Keychain item + comment JSON, or SQLite ciphertext + row metadata), resolved via backend APIs.
- **Registry** (`registry.json`) — local schema/catalog definitions for metadata fields, defaults, validation, and type/kind relationships. It is not an inventory or metadata authority. See [METADATA_REGISTRY.md](METADATA_REGISTRY.md).
- **Operational status** — `seckit status` asks the local daemon for a unified current view of transport, runtime, routing, peer, and synchronization health. The CLI formats that response and does not inspect SQLite or daemon implementation files.

Canonical semantics: [OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md](OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md). Current operator metadata-schema behavior: [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md).

## Diagnostics and inspection

- **`doctor`** reports backend posture, catalog checks, and backend metadata validation.
- **`status`** requests operational state from the local daemon. It is not an audit report, database dump, or alternate runtime API.
- **`info`** reports version, defaults, and backend status.
- **`envelope list/show`** inspects persisted delivery artifacts.
- **`transaction list/show`** inspects persisted SQLite transaction history.
- Diagnostic and inspection commands are **not** materialization paths and must not print secret plaintext.

## `list` semantics (capability-driven)

`list` is **inventory**, not “ dump everything cheaply” by definition.

- It uses **safe enumeration paths** appropriate to **backend capabilities**. It must not use `registry.json` as inventory.
- **Selective authority resolve** happens **only when needed** (e.g. filters such as type, kind, tag, stale) and when the backend supports it (`supports_selective_resolve`).
- **Do not treat today’s implementation as the normative long-term contract** for prose or tests—wording tracks **policy and capabilities**, not frozen implementation detail (same maturity applies elsewhere).

## Safe output policy

- Inventory-oriented commands default to **redaction** and **minimal disclosure**.
- **`get --raw`**, **`export`**, and **`run`** are **materialization** paths and must be explicit.
- **`explain`** resolves **without** materializing the secret into normal stdout.

## Daemon / Machine API Scope

`seckitd` is a transport adapter with local Unix-socket control and a daemon-owned transport substrate. **The runtime owns state; the daemon owns movement.** The default substrate is py-libp2p behind the daemon transport abstraction; a direct TCP compatibility adapter may be selected or used when libp2p is unavailable. The daemon owns transport-control messages such as status, health, and graceful shutdown. `seckit status` is the supported local operational interface: the daemon gathers state through the internal runtime interface and the CLI only formats the response. Application protocol messages are owned by the runtime, not by the daemon command namespace. The daemon does not import protocol, cryptographic, SQLite, transaction, or Peer Registry authorities.

Any `seckit` API or daemon behavior must reuse the ADR meanings of **resolve**, **materialize**, **inject**, and **exported** — extending transport only, not redefining those terms. Prefer **local-first** authority; **no implicit remote trust** for secret material. **Lease**, **policy**, and **audit** semantics are not specified here. See [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Process and supervision lifecycle

`seckit` is a transient command-line client. It connects to the same-user Unix-domain socket for daemon control and operational requests; it does not remain resident and it does not use standard input/output as the daemon IPC channel.

`seckitd` is the long-running same-user process. A managed installation uses a user LaunchAgent on macOS or a systemd user service on Linux. The macOS LaunchAgent starts when that user's graphical session is loaded; the Linux user service can start without login only when an administrator has enabled lingering for that user. The service manager starts it, restarts it after failure, and prevents ordinary CLI commands from creating a duplicate daemon. Successful RSS enrollment, RSS configuration, or RSS identity import installs the managed service automatically. Without a managed service, `seckit daemon start` retains the detached-process fallback.

`seckit-mcp` is a separate transient process started by its agent parent. Standard input/output belongs exclusively to the MCP session between that parent and `seckit-mcp`; the MCP process then connects to `seckitd` through the same-user Unix-domain socket. It opens no TCP listener and does not start the daemon implicitly.

The daemon may launch a bounded hidden `seckit internal ...` runtime worker when an opaque transport request requires protected runtime or datastore authority. In that internal subprocess only, stdin/stdout carries the bounded worker request and response. This is not recursive invocation of the public CLI, is not the MCP channel, and does not make the daemon a datastore or protocol authority.

## Command Hierarchy Compatibility

Command hierarchy changes (e.g. `seckit backend unlock`) must:

- Preserve **scripting compatibility** where possible.
- Keep **aliases** during migration windows.
- Avoid casual renames of **high-frequency** operator commands.

Shared argparse helpers **must not** force **identical semantics** across commands where behavior differs—see [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Related docs

- [CONCEPTS.md](CONCEPTS.md) — mental model and resolve vs materialize  
- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — protected authority handling and crossings  
- [CLI_REFERENCE.md](CLI_REFERENCE.md) — per-command reference  
- [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) — help wording, JSON stability, errors  
