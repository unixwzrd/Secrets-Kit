# ADR: Local runtime session semantics

**Created**: 2026-05-08
**Updated**: 2026-05-13

Normative public semantics for local runtime authority sessions, ownership, caching, propagation, and failure behavior. This ADR is local-first and peer-oriented. It does not define hosted relay operations.

Materialization vocabulary (**resolve**, **materialize**, **inject**, **exported**) remains defined in [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Purpose / scope guard

The purpose of this ADR is to constrain local implementation complexity and preserve Unix-oriented operational behavior. `seckitd` may remain public as peer-side/local runtime infrastructure when it stays transport-agnostic and does not expose hosted relay assumptions.

This public ADR does not define managed relay services, hosted topology, customer routing, durable delivery queues, deployment runbooks, or operational telemetry.

## Related documents

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — materialization, inject, protected authority handling
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) — local IPC and peer-side `seckitd`
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — operator posture
- [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) — CLI vs authority vs index

## Same-host authority principle

Secret authority resolution remains same-host and same-user by default. Other peers or transports may move encrypted artifacts, but they do not become authoritative runtime owners of local secret state.

## User-scoped daemon and session model

- Prefer one runtime daemon / session scope per OS user where a local daemon is used.
- No privilege escalation and no cross-user impersonation. OS account boundaries are the primary security boundary.
- A user-scoped `seckitd` is local peer/runtime plumbing for that user on that host, not a centralized authority service or hosted control plane.

## Plumbing roles

| Role | Session-relevant responsibility |
|------|--------------------------------|
| `seckitd` | Same-user local peer/runtime mediator; may participate in authorized materialization; not source-of-truth vs `BackendStore` |
| `seckit` | Operator commands, import/export, verification, and merge logic |
| `BackendStore` | Authoritative local persistence and resolve primitives for secrets on this host |
| peer transport | Moves encrypted artifacts or peer messages without acquiring local authority ownership |

## Authority session

An authority session is a logical scope covering:

- which OS user and host own the session;
- which backend identity is in scope;
- until when session state is considered valid before teardown or fail-closed invalidation.

Today, the CLI process lifetime plus per-invocation unlock state approximates a process-bound session.

A future user-scoped daemon may hold daemon-bound state, but handles must invalidate fail-closed on daemon restart unless an explicit re-handshake path is documented.

## Unlock persistence vs runtime session

- Store unlock follows OS and backend rules.
- The runtime session layer must not assume unlock survives arbitrary process or daemon restart without revalidation.
- Reconnect, re-resolve, and re-unlock are preferred over implicit authority persistence across restart.

## Authority ownership and propagation

- Authority ownership belongs to the user context running `seckit` and, under the same constraints, a same-user local mediator.
- No cross-user session sharing.
- `seckit run` is parent-mediated injection; daemon-mediated injection, if used later, must use the same inject definition from the authority ADR.
- IPC consumers receive materialized plaintext as a crossing; they do not acquire `BackendStore` ownership or unlock lineage.

Injection propagates materialized data, not unlock authority lineage.

## Session cache and residency

- Session state should be ephemeral.
- Plaintext residency should be minimal.
- No durable daemon-side plaintext cache by default.
- In-process caching of ciphertext or non-secret metadata may exist only as explicitly documented.

## Failure semantics

- Unlock failure means no materialization to consumers.
- Stale authority must re-resolve or fail deterministically.
- Corrupted session state must be discarded without partial plaintext output.
- Local mediator unavailability should produce a deterministic error, not a weaker fallback.
- Revoked peer trust affects peer sync/trust; do not conflate it with same-host store session.

## Invariants

1. Same-host, same-user authority by default.
2. No implicit escalation across users or hosts.
3. Injection carries materialized bytes, not unlock or `BackendStore` ownership.
4. Teardown drops session references; ambiguity fails closed.
5. Materialization crossings remain governed by [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Non-goals

This public document does not define hosted relay behavior, customer or tenant routing, remote APIs, distributed coordination, durable delivery queues, deployment orchestration, operational telemetry, or private relay protocols.
