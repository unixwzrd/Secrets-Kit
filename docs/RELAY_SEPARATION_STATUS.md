# Relay separation status

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

**Scope:** Boundary analysis and **documentation only**. No code extraction. A future **`secrets-kit-relay`** repo should own **opaque transport relay** concerns; this repo remains **local authority**, **CLI**, and **peer-side `seckitd`** until [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md) and [DISTRIBUTED_VALIDATION_STATUS.md](DISTRIBUTED_VALIDATION_STATUS.md) justify extraction.

## Intended product split (3 runtimes)

| System | Owns | Must **not** own (relay repo) |
|--------|------|-------------------------------|
| **`seckit` (CLI)** | Operator UX, local `BackendStore` ops, registry/index maintenance, import/export, merge, peer *local* prep | Remote tenant routing, durable multi-tenant queues, centralized policy enforcement |
| **`seckitd` (local)** | Same-user UDS IPC, request framing, loopback/runtime orchestration hooks, subprocess tails per policy | Secret authority, registry authority, decryption of peer payloads for reconciliation |
| **`secrets-kit-relay` (future)** | Opaque relay, peer forwarding, delivery retry/reconnect **at transport layer** | **No** authority, **no** decryption, **no** reconciliation ownership |

Normative language already guardrails this in [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md), [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md), and [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md): public docs **exclude** hosted relay topology, customer routing, managed queues, and deployment runbooks.

## Runtime seams in *this* repository (local)

| Area | Path (indicative) | Stays local | Candidate relay-adjacent (future) |
|------|-------------------|------------|-------------------------------------|
| UDS server + framing | [`src/secrets_kit/seckitd/server.py`](../src/secrets_kit/seckitd/server.py), [`framing.py`](../src/secrets_kit/seckitd/framing.py), [`client.py`](../src/secrets_kit/seckitd/client.py) | Yes — same-host IPC | **Not** relay product; relay would use different network transport |
| Request dispatch | [`protocol.py`](../src/secrets_kit/seckitd/protocol.py) | Yes — dispatches to CLI helpers / sync import | Outbound queue *shape* might inform relay wire format; **behavior** stays peer/local |
| Loopback / transport abstraction | [`loopback_transport.py`](../src/secrets_kit/seckitd/loopback_transport.py) | Yes | Pattern for “pluggable transport” without merging relay code |
| Peer sync bundles / envelopes | [`src/secrets_kit/sync/`](../src/secrets_kit/sync/) | Authority + crypto + merge **local** | **Wire serialization** (opaque blobs) could become a **shared protocol package** consumed by relay |
| Identity / peers | [`src/secrets_kit/identity/`](../src/secrets_kit/identity/), CLI peer commands | Local trust and enrollment artifacts | Relay forwards opaque payloads only |
| Registry | [`src/secrets_kit/registry/`](../src/secrets_kit/registry/) | **Local index** | Relay must never treat registry as authoritative for secrets |

## Protocol / package candidates (pre-extraction)

When extraction is justified, prefer **thin shared packages** (names illustrative):

- **Framed opaque message** — length-prefixed JSON or CBOR **envelope** carrying peer payloads already encrypted; no keys, no registry.
- **Constants / op labels** — only if wire stability is required across repos; keep small.

**Do not** share: `BackendStore`, Keychain adapters, SQLite decrypt paths, or merge/reconcile implementations with relay.

## Extraction gate (must all be true)

1. [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md) shows **subprocess** and **multi-host** evidence for CLI + local daemon + peer sync transport assumptions.  
2. [DISTRIBUTED_VALIDATION_STATUS.md](DISTRIBUTED_VALIDATION_STATUS.md) has passing scenarios or explicit failure modes with repros.  
3. Operational blockers are triaged—no “big extract to fix confusion” without a failing workflow.

Until then: **document seams**, **stabilize local runtime**, **avoid** moving code into a relay repo.

## Related docs

- [ARCHITECTURE_RUNTIME_SURFACE.md](ARCHITECTURE_RUNTIME_SURFACE.md) — vocabulary: local vs hosted  
- [PEER_SYNC.md](PEER_SYNC.md) — manual transport; no assumption of public relay  
- [OPERATIONS_STATUS.md](OPERATIONS_STATUS.md) — what operators can rely on today  
