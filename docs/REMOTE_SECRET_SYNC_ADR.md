# ADR: Remote Secret Sync terminology and authority boundaries

**Created**: 2026-05-20
**Updated**: 2026-05-20

## Status

Draft proposal. This document clarifies terminology and boundaries only. It does not change wire fields, schema aliases, envelope semantics, reconciliation semantics, UUID/idempotency behavior, transport behavior, or runtime behavior.

## Decision

Use **RSS** / **Remote Secret Sync** as the preferred public term for optional remote synchronization assistance supporting peer-authoritative synchronization between peers.

Public peer synchronization remains peer-authoritative:

- peers own datastore authority;
- peers own reconciliation and merge decisions;
- peers own identity trust decisions;
- peers own decryption and materialization boundaries;
- peers own replay, UUID/idempotency, history, and tombstone interpretation.

RSS infrastructure is optional remote synchronization assistance. It may help peers exchange opaque signed/encrypted synchronization envelopes when an operator chooses a remote path. It is not required when peers can exchange artifacts through an operator-selected direct path.

## Definitions

**Remote Secret Sync (RSS):** the terminology family for remote peer synchronization support in Secrets Kit. RSS describes optional transport assistance around peer-authoritative synchronization, not a new authority model.

**Mutually reachable peers:** peers that can exchange synchronization artifacts or envelopes through an operator-controlled direct path without RSS infrastructure.

**Indirectly reachable peers:** peers that cannot currently exchange synchronization traffic directly, but can both reach optional transport assistance infrastructure that forwards opaque envelopes between them.

**Transport-assistance infrastructure:** optional infrastructure that helps move opaque synchronization envelopes between peers. It does not own secret state, merge state, identity truth, or durable synchronization history.

**RSS infrastructure:** non-authoritative transport infrastructure that can receive and forward opaque envelopes within explicit operator policy.

## RSS node non-authority

RSS infrastructure must not become:

- merge authority;
- datastore authority;
- decryption authority;
- reconciliation authority;
- identity authority;
- durable queue authority;
- synchronization history authority;
- plaintext materialization authority.

RSS infrastructure may observe only the metadata required for transport assistance and operational safety. It must not require payload plaintext, backend access, local registry authority, or reconciliation internals.

## Compatibility posture

Existing compatibility names are not renamed by this ADR. In particular:

- `relay_endpoints` remains a wire/schema compatibility alias for peer endpoint hints;
- `route_token` / `KEY_ROUTE_TOKEN` remain wire/schema compatibility names for forwarding hints;
- `relay_visible_routing_subset` remains a compatibility surface for the approved transport-visible routing slice.

New public prose should prefer RSS terminology, but compatibility names may remain in code, schemas, tests, changelog entries, and docs where they describe existing wire behavior or intentional compatibility obligations.

## Public boundary

Public `secrets-kit` may document peer-authoritative synchronization, transport-neutral envelopes, local runtime constraints, and RSS terminology needed to explain public contracts. Remote synchronization transport details are intentionally outside this public runtime document.

## Non-goals

This ADR does not introduce:

- a new protocol layer;
- a new wire format;
- a schema migration;
- broad mechanical renames;
- remote transport authority semantics;
- federation semantics;
- broker semantics;
- durable queue semantics;
- centralized identity or reconciliation services.

## Related documents

- [PEER_SYNC.md](PEER_SYNC.md)
- [PROTOCOL_TRANSPORT_ARCHITECTURE.md](PROTOCOL_TRANSPORT_ARCHITECTURE.md)
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md)
- [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md)
