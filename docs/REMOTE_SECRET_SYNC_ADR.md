# ADR: Remote Secret Sync terminology and authority boundaries

<!-- Derived from separation-governance/Secrets-Kit-Docs/REMOTE_SECRET_SYNC_ADR.md. -->

**Created**: 2026-05-20
**Updated**: 2026-09-07

## Status

The forwarding-only RSS direction, terminology, and local-first authority boundaries are frozen. This document describes the customer-facing contract, not a release-certification result. Existing peer envelope, reconciliation, UUID/idempotency, and datastore semantics remain unchanged.

- [ADR: Remote Secret Sync terminology and authority boundaries](#adr-remote-secret-sync-terminology-and-authority-boundaries)
  - [Status](#status)
  - [Decision](#decision)
  - [Definitions](#definitions)
  - [RSS node non-authority](#rss-node-non-authority)
  - [RSS enrollment and endpoint set](#rss-enrollment-and-endpoint-set)
  - [Compatibility posture](#compatibility-posture)
  - [Public boundary](#public-boundary)
  - [Non-goals](#non-goals)
  - [Related documents](#related-documents)

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

Configured RSS hostnames, ports, certificates, and bootstrap information are durable runtime configuration. Durable peer endpoint lifecycle records remain runtime-owned Peer Registry projections. Active RSS connections, transport endpoint bindings, heartbeats, and routing entries are ephemeral daemon transport state. Endpoint discovery or re-registration may locate a candidate but never authorizes it; the runtime and Peer Registry retain authorization authority.

## RSS enrollment and endpoint set

The one-time credential authorizing initial customer enrollment is the **RSS Enrollment Token** (`RET`). It is short-lived and single-use, not a durable customer or peer identity. The supported enrollment command obtains and handles it without requiring customers to construct tokens or copy internal identifiers. Treat enrollment material as sensitive; do not include it in support reports.

The client generates and retains its long-lived authentication private key locally. Enrollment is authorized by the operator service, not by an RSS node. Each RSS node independently enforces the operator's authorization; RSS nodes do not redeem RETs or propagate customer authority to each other. RSS service access does not by itself grant access to another peer's secrets: peer admission and service/account grants remain separate.

Enrollment supplies an ordered primary/secondary RSS endpoint set, stored in the protected client profile. The client authenticates the configured endpoints and can establish a circuit through the alternate when the preferred endpoint is unavailable. Discovery locates candidates; it never substitutes for authentication or peer authorization. Customer credentials and profiles must be used only with their intended service environment.

RSS forwards opaque encrypted envelopes between reachable authorized peers. It does not store customer secrets, provide a durable message queue, or replay/recover a peer datastore. Peer-local state controls retry and recovery after connectivity returns. See [RSS_CUSTOMER_GUIDE.md](RSS_CUSTOMER_GUIDE.md) for supported enrollment, identity transfer, reconnection, and credential-handling procedures.

## Compatibility posture

Existing compatibility names are not renamed by this ADR. In particular:

- `relay_endpoints` remains a wire/schema compatibility alias for peer endpoint hints;
- `route_token` / `KEY_ROUTE_TOKEN` remain wire/schema compatibility names for forwarding hints;
- `relay_visible_routing_subset` remains a compatibility surface for the approved transport-visible routing slice.

New public prose should prefer RSS terminology, but compatibility names may remain in code, schemas, tests, changelog entries, and docs where they describe existing wire behavior or intentional compatibility obligations.

## Public boundary

Public `secrets-kit` may document peer-authoritative synchronization, transport-neutral envelopes, local runtime constraints, and RSS terminology needed to explain public contracts. Remote synchronization transport details are intentionally outside this public runtime document.

The client uses its supported libp2p transport for direct and RSS-assisted peer communication. RSS remains forwarding-only and must not become datastore, identity, transaction, reconciliation, or synchronization authority. This architecture description is not evidence that a particular artifact or deployment has passed qualification.

Operator deployment topology, RET claim schemas, authorization-projection internals, customer/billing records, accounting implementation and private qualification evidence are outside this public document.

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

- [RSS_CUSTOMER_GUIDE.md](RSS_CUSTOMER_GUIDE.md)
- [PROTOCOL_TRANSPORT_ARCHITECTURE.md](PROTOCOL_TRANSPORT_ARCHITECTURE.md)
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md)
- [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md)
