# ADR: Runtime session semantics (pre-daemon)

**Created**: 2026-05-08  
**Updated**: 2026-05-08  

Normative semantics for **runtime authority sessions**, **ownership**, **caching**, **propagation**, and **failure** behavior **before** a production `seckitd` exists. This ADR is **contract-oriented**, **local-first**, and **transport-neutral** at the session layer; wire details live in [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md). Materialization vocabulary (**resolve**, **materialize**, **inject**, **exported**) remains defined in [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) and **must not** be redefined here.

## Purpose / scope guard

The purpose of this ADR (with [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md)) is to **constrain future implementation complexity** and preserve **local-first, Unix-oriented** operational behavior. Future daemon and runtime implementations should **emerge from** these semantics rather than **redefine** them retroactively.

**This phase does not** ship a production daemon, sockets, relay, networking, policy engine, **distributed consensus**, durable message brokers, or persistent runtime plaintext caches.

## Related documents

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — materialization, inject, protected authority handling  
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) — IPC trust boundary, `seckitd` vs `relayd`, relay appendix  
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — operator posture  
- [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) — CLI vs authority vs index  

## Same-host authority principle

> **Secret authority resolution remains same-host and same-user by default. Remote systems relay or transport encrypted artifacts but do not become authoritative runtime owners of local secret state.**

## User-scoped daemon and session model

- Prefer **one runtime daemon / session scope per OS user** (login session), using **user-owned** `launchd` / `systemd` (or equivalent) services where applicable.
- **No privilege escalation** and **no cross-user impersonation**. **OS account boundaries** are the **primary security boundary**.
- A future **user-scoped daemon** is a **runtime router** / **transport mediator** for **that user on that host** — **not** a centralized authority service, multi-tenant broker, or cluster control plane.

## Plumbing roles (session perspective)

| Role | Session-relevant responsibility |
|------|--------------------------------|
| **`relayd` routes** | Future optional: forwards **opaque ciphertext only** — see IPC ADR. **Never** authoritative for local secret state. |
| **`seckitd` transports** | Future optional: **same-user local** **transport mediator** — may participate in **authorized** materialization to consumers; **not** source-of-truth vs `BackendStore`; **minimal business logic**. |
| **`seckit` imports / merges** | Operator and merge logic stay in **seckit** (CLI / tools). |
| **`BackendStore` persists** | **Authoritative local persistence** and resolve primitives for secrets on **this host**. |

## Authority session (logical)

An **authority session** is a **logical** scope (not necessarily a single OS process today) covering:

- **which OS user** and **host** own the session;
- **which backend identity** (paths, keychains, profiles) is in scope;
- **until when** session state is considered valid before **teardown** or **fail-closed** invalidation.

**Today:** the **CLI process** lifetime plus per-invocation unlock state (passphrase env, Keychain unlock window) approximates a **process-bound** session.

**Future:** a **user-scoped daemon** may hold a **daemon-bound** session; **handles** must **invalidate fail-closed** on daemon restart unless an explicit, documented re-handshake path exists later.

## Unlock persistence vs runtime session

- **Store unlock** (DEK/KEK material, Keychain unlock) follows **OS and backend** rules.
- The **runtime session layer** **must not** assume unlock or session **survives arbitrary process/daemon restart** without **revalidation**.
- **Reconnect / re-resolve / re-unlock** is preferred over **implicit authority persistence** across restart.

## Authority ownership and propagation

- **Authority ownership** belongs to the **user context** running **seckit** and, under the same constraints, a **same-user** **runtime router** daemon.
- **No** cross-user session sharing.
- **`seckit run`** is **parent-mediated injection**; a future daemon-mediated injection path uses the **same** **inject** definition from the authority ADR — **plumbing only**.
- **IPC consumers** (future) receive **materialized plaintext** as a **crossing**; they **do not** acquire **`BackendStore`** ownership or unlock lineage.

> **Injection propagates materialized data, not unlock authority lineage.**

## Process-bound vs daemon-bound (summary)

| Aspect | Process-bound (today) | Daemon-bound (future) |
|--------|----------------------|------------------------|
| Unlock locus | CLI + OS/backend | Same user; mediator may cache **non-plaintext** session facts only as documented |
| Restart | New CLI → new session | Daemon restart → **invalidate** session handles; **fail closed** |
| Mediator role | None required | **Transport mediator** only; **not** authority server |

## Session cache and residency (bias)

- **Ephemeral** session state; **minimal plaintext residency**.
- **No durable daemon-side plaintext cache** by default.
- In-process caching of ciphertext or non-secret metadata may exist **only** as explicitly documented in implementation; **default** remains conservative.
- **Routing** language in docs **must not** imply **durable message queues** or **broker durability** unless a **later** ADR adds them.

## Restart and expiration expectations

- Sessions **do not** imply cryptographic TTL until **lease** work exists elsewhere.
- **Operational** expectation: **restart** clears or invalidates **in-process / in-daemon** session continuity — callers **reconnect** and **re-validate** unlock as needed.
- **Unlock revalidation:** after sleep, re-lock, vault path changes, or detected drift — **fail closed** at materialization boundaries unless unlock succeeds again.

## Failure semantics (session-side)

- **Unlock failure** → **no materialization** to consumers.
- **Stale authority** → **re-resolve or fail** deterministically — no silent downgrade.
- **Corrupted session state** → discard session artifacts; **no partial plaintext** emit.
- **Mediator unavailable** (future) → **deterministic error** — no fallback that **weakens** materialization policy.
- **Revoked peer** affects **peer sync / trust** — **do not** conflate with **same-host** store session; scope errors accordingly.

## Invariants (summary)

1. **Same-host, same-user** authority by default (see quote above).  
2. **No implicit escalation** of scope across users or hosts.  
3. **Injection** carries **materialized bytes**, not **unlock** or **BackendStore** **ownership**.  
4. Teardown **drops** session references; **fail-closed** on ambiguity.  
5. Materialization crossings remain governed by [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).  

## Non-goals

No production **`seckitd`**, **relay** implementation, **networking** stack, **remote APIs**, **distributed coordination**, **distributed consensus / state coordination**, **async replication**, **MFA/policy engine** as part of this ADR, **persistent daemon plaintext cache** as default product behavior, **RPC platform**, **service mesh**, **generalized multi-tenant broker**, or **durable message queues** as implied scope.
