# ADR: IPC and local peer transport semantics

**Created**: 2026-05-08
**Updated**: 2026-05-13

Normative public semantics for local IPC and peer-side `seckitd` plumbing. This document covers local, peer-valid behavior only. Hosted relay topology, managed relay operations, customer/tenant workflows, and private deployment runbooks are outside the public repository.

Materialization terms come from [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md). Session and ownership language comes from [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md).

## Purpose / scope guard

The purpose of this ADR is to keep local IPC small, inspectable, and peer-oriented. `seckitd` is not classified as relay infrastructure by name; it may remain public when it supports local peer communication without hosted operational assumptions.

This public ADR does not define managed relay services, remote authentication, customer routing, deployment automation, hosted topology, durable queues, or operational telemetry.

## Related documents

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md)
- [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)

## Local IPC role

- `seckitd` is peer-side/local runtime plumbing that works with the `seckit` CLI.
- `seckitd` is not authoritative over `BackendStore`; storage, merge, and import authority stay in the CLI/tooling and backend layers.
- Local IPC may carry authorized transient plaintext to a same-user consumer. That is a materialization crossing and must follow the authority ADR redaction and logging rules.
- Local peer messages may also carry opaque encrypted artifacts. Public docs describe this as peer behavior without assuming hosted relay infrastructure.

## Same-host authority

Secret authority resolution stays same-host and same-user by default. Remote peers or transports may move encrypted artifacts, but they do not become owners of local secret state.

## Plumbing matrix

| Role | Public responsibility |
|------|-----------------------|
| `seckitd` | Same-user peer/local transport mediator; minimal business logic; not storage or merge authority |
| `seckit` | CLI operations, import, export, merge, verification |
| `BackendStore` | Local persistence and resolve primitives for this host |
| peer transport | Moves files or messages between peers without changing authority ownership |

## Trust boundary

- Local IPC that delivers secret plaintext to a process is a materialization crossing to that IPC consumer.
- Errors, logs, diagnostics, and traces must not implicitly embed secret plaintext.
- Default contract: client and server run under the same OS user for this local IPC profile.
- Cross-user or privileged mediation is out of public contract unless explicitly specified later.

## Unix / minimalist streams philosophy

- Prefer byte streams, stdin/stdout/subprocess patterns, and Unix domain sockets where local sockets are useful.
- Keep framing small and explicit.
- Avoid turning peer IPC into a broad RPC platform or hosted control plane.

## Fetch vs inject vs export

Definitions stay in [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

- **Fetch (IPC):** return plaintext to an authorized local consumer; this materializes to that consumer.
- **Inject:** transfer plaintext into another execution context, for example a child environment.
- **Export:** create an externalized artifact such as a file or bundle.

## Failure and redaction

- Failures must be deterministic and safe to log.
- Secret payloads must not appear in error text.
- Error labels may be documented for stable meaning, but that does not make the whole IPC shape a permanent compatibility contract.

## Non-goals

This public document does not define hosted relay behavior, customer or tenant routing, relay deployment, delivery queues, operational telemetry, NAT traversal architecture, or private relay protocols.
