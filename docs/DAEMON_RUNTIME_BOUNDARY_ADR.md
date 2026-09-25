# ADR: Daemon and runtime boundary

**Created**: 2026-07-19
**Updated**: 2026-07-30

## Status

Accepted and implemented for the current local transport path. This ADR remains the authority for future daemon/runtime work.

- [ADR: Daemon and runtime boundary](#adr-daemon-and-runtime-boundary)
  - [Status](#status)
  - [Decision](#decision)
  - [Current implementation](#current-implementation)
  - [Runtime ownership](#runtime-ownership)
  - [Daemon ownership](#daemon-ownership)
  - [Endpoint and observation ownership](#endpoint-and-observation-ownership)
  - [Operational status](#operational-status)
  - [Daemon and RSS symmetry](#daemon-and-rss-symmetry)
  - [Package boundary](#package-boundary)
  - [Rejected alternatives](#rejected-alternatives)
  - [Lessons from the previous implementation](#lessons-from-the-previous-implementation)
  - [Non-goals](#non-goals)
  - [Related documents](#related-documents)

## Decision

**The runtime owns state. The daemon owns movement.**

This is an architectural invariant. The daemon must never become a convenience location for protocol logic simply because it already processes transport events. Any feature requiring protocol knowledge belongs in the runtime.

The daemon is a transport adapter. It moves opaque payloads between local and peer transports. It is not the protocol engine, transaction engine, cryptographic engine, database engine, reconciliation engine, peer authorization authority, or synchronization authority.

The daemon owns a stable transport-adapter contract and a bounded built-in adapter registry. `PyLibP2PTransport` is the preferred production adapter and `DirectTCPTransport` is an explicitly selected compatibility adapter. The runtime boundary and opaque-payload contract are identical for every adapter.
Adapter startup fails closed; an unavailable selected adapter is never silently replaced by a less secure transport. Libp2p host lifecycle, discovery hooks, endpoint selection, relay-path support where enabled, and transport observations remain daemon responsibilities; no libp2p type may cross into runtime modules.

## Current implementation

The current daemon package contains transport paths, daemon lifecycle, transport-control parsing, UDS/TCP routing, bounded runtime-worker orchestration, and transport receipts. It does not import SQLite, the transaction engine, Peer Registry, canonical application-envelope parsing, payload codecs, signing, encryption, or reconciliation modules.

Inbound TCP bytes are supplied unchanged to the hidden runtime-owned `internal apply-envelope --stdin` operation. Due outbound envelopes are claimed, authorized, and transitioned by the hidden runtime-owned `internal deliver-pending` operation; the daemon may schedule one non-blocking worker but cannot inspect durable state.

The runtime-to-daemon delivery interface contains only the destination peer identity and opaque canonical envelope bytes. The daemon resolves the identity through an in-memory routing table and owns endpoint, transport, and path selection details. The local UDS route frame contains the peer identity and opaque payload bytes, not host names, ports, multiaddrs, or relay information.
A successful daemon handoff returns a transport delivery receipt. It is not a protocol acknowledgement and does not set `acknowledged_at`.

Current local automated acceptance proves the repaired boundary with two isolated peers, signed/encrypted destination-specific envelopes, offline retry, and convergence. The full integration suite also covers three-node fan-out. Cross-host P2P remains unproved.

## Runtime ownership

The runtime owns:

- SQLite and persistent state;
- transaction creation, validation, submission, application, and replay;
- protocol semantics;
- canonical envelope parsing and validation;
- cryptographic envelope processing;
- peer authorization and Peer Registry decisions;
- reconciliation;
- synchronization semantics;
- protocol acknowledgements and protocol responses.

The CLI is one interface to the runtime. The daemon is another. The runtime owns the work regardless of which interface invoked it.

Application payloads received by the daemon are supplied to the runtime through an internal runtime interface. The initial implementation may use standard input, but the architecture does not require stdin and may later use another internal mechanism without changing this ADR.

Inbound protocol processing must not be modeled as a daemon command namespace. Command names such as `seckit daemon ingest`, `seckit daemon stdin`, or `seckit daemon process-envelope` incorrectly imply that application envelope processing is a daemon responsibility.

## Daemon ownership

The daemon owns:

- local UDS availability;
- peer TCP listener availability;
- outbound peer TCP connection management;
- opaque payload routing between transports;
- transport retry and connection management;
- TLS/session management when implemented;
- basic routing metadata;
- transport-control messages such as health, status, and graceful shutdown.

The daemon must not:

- open or modify SQLite;
- create transactions;
- apply transactions;
- validate transactions;
- decrypt application envelopes;
- encrypt application envelopes;
- authorize peers at the protocol layer;
- perform reconciliation;
- interpret application protocol message types;
- generate protocol acknowledgements;
- implement synchronization semantics.

The daemon owns endpoint discovery, active endpoint binding, and its ephemeral routing cache. The runtime Peer Registry owns durable endpoint lifecycle records and canonical registration/replacement transactions. The daemon's registration handoff is transport activation, not identity or authorization.

Libp2p owns the secure transport handshake, transport PeerID, Identify exchange, signed peer records, address discovery, and peerstore. The daemon must use those facilities rather than duplicating them in a Secrets Kit protocol. Libp2p does not know the separate Secrets Kit typed node identity, so the daemon may carry a minimal post-Identify transport-control binding between the authenticated libp2p PeerID and a Secrets Kit `node:<uuid>`.

The binding uses a fresh challenge and a runtime-generated signature. The runtime signs local claims and validates remote claims against the admitted peer's public key. It treats transport identity as opaque input and returns a verified node identity or rejection. The daemon confirms that the claimed transport identity is the PeerID authenticated by the active connection and installs only ephemeral routing state. This does not authorize application synchronization: runtime delivery and inbound processing continue to enforce Peer Registry policy independently.

Transport identity and application identity remain separate authorities:

- transport adapters own and observe transport identities;
- the runtime owns Secrets Kit node identities and authorization;
- adapters must not generate, interpret, authorize, or persist Secrets Kit node identities;
- runtime code must not interpret PeerIDs, multiaddrs, sockets, endpoints, or transport-specific addressing.

The Secrets Kit py-libp2p profile uses Noise only. SECIO, plaintext libp2p, and TLS fallback are excluded. The preferred production dependency is an official upstream py-libp2p release with a Noise-only dependency graph. For beta, the installer may apply the approved exact dependency override and validate the installed native artifact before activating a new runtime generation. That installer-only operation does not give the daemon or runtime native-package authority.

## Endpoint and observation ownership

The runtime owns durable configuration and projections: the Peer Registry, node identities, authorization and service groups, relay configuration, configured bootstrap peers, cryptographic identities, and endpoint lifecycle records. The daemon owns ephemeral operational state: its current listener, active connections, connection quality, heartbeats, routing cache, and active transport bindings. The daemon may bind a different endpoint after restart, DHCP changes, or sleep/wake; endpoint data is never node identity or durable application authority.

The intended startup sequence is to load runtime configuration and the Peer Registry, load relay configuration, start the daemon, bind an available endpoint, register or announce it through the approved runtime/control path, start local libp2p discovery after the actual endpoint is known, attempt configured bootstrap peers, complete the built-in libp2p Identify exchange, validate the Secrets Kit node binding, build the routing cache, and begin normal transport operation. RSS remains a separate later path.

Transport observations are reported to the runtime through the internal runtime interface. The runtime decides whether they become durable projections or operator-visible state. Heartbeats are transport-health observations only; they are not synchronization or reconciliation. The daemon must not ask protocol questions about transactions or reconciliation.

## Operational status

Operational status is a control-plane request. It is not an application protocol message, not a datastore transaction, and not part of synchronization semantics.

A status request represents the operational state of an entire node. Status should present a unified view of transport, runtime, and service health rather than exposing separate, unrelated status mechanisms. The daemon may aggregate information from multiple sources, including transport state, runtime state, and service-manager state where applicable.

The runtime does not become a transport component merely because the daemon requests runtime status information. The supported operator path is `seckit status`: the CLI sends a local daemon control request, the daemon aggregates transport state with runtime status obtained through the internal runtime interface, and the CLI formats the returned view. The CLI does not inspect SQLite or daemon implementation metadata. Operational status and historical audit reporting remain separate capabilities.

This ADR defines ownership only. It does not specify the status collection mechanism.

## Daemon and RSS symmetry

The daemon and the future Remote Sync Service (RSS) follow the same transport-only philosophy:

```text
UDS  <->  daemon  <->  TCP
TCP  <->  RSS     <->  TCP
```

Both components move opaque payloads. Neither owns datastore authority, transaction authority, protocol authority, cryptographic authority, reconciliation authority, or synchronization authority.

The primary distinction is only the transports they bridge. Future implementation should preserve this symmetry.

## Package boundary

Package layout follows architectural ownership.

Runtime responsibilities must not remain inside daemon modules merely because they were historically implemented there. Existing package layout is not architectural authority.

Daemon modules should contain transport-adapter code. Runtime modules should contain protocol, persistence, cryptographic, authorization, reconciliation, acknowledgement, and transaction logic.

## Rejected alternatives

### Daemon as protocol engine

Rejected. It makes the long-running transport process interpret application semantics, which invites SQLite access, transaction application, crypto processing, authorization checks, and protocol acknowledgement generation inside the daemon.

### Daemon as transaction engine

Rejected. Transactions are runtime authority. The daemon may carry transaction envelopes as opaque payloads, but it must not create, validate, apply, or reconcile transactions.

### Daemon as database worker

Rejected. SQLite belongs exclusively to the runtime. A daemon that opens SQLite becomes a state owner rather than a transport adapter.

### Daemon as cryptographic worker

Rejected. Private key use, signature verification, payload decryption, and payload encryption are runtime responsibilities. The daemon and RSS must not decrypt or re-encrypt application envelopes.

### Daemon-generated protocol acknowledgements

Rejected. Protocol acknowledgements are application protocol responses. They must be generated by the runtime and then routed by the daemon as opaque payloads.

## Lessons from the previous implementation

The previous daemon implementation demonstrated useful local protocol behavior, including local signed/encrypted envelope movement and localhost multi-node convergence. That evidence remains useful, but the implementation placed protocol, SQLite, transaction, cryptographic, peer authorization, queue lifecycle, and acknowledgement responsibilities inside daemon modules or daemon-adjacent paths.

Those placements are not architectural authority. Future implementation should retain transport primitives where useful, but protocol, persistence, cryptographic, authorization, reconciliation, and synchronization logic must follow the documented runtime boundary regardless of where they currently reside.

## Non-goals

This ADR does not define:

- exact command-line syntax for daemon lifecycle;
- exact internal runtime interface spelling;
- exact transport framing;
- service-manager implementation details;
- relay-assisted cross-host behavior;
- discovery outside one local broadcast domain;
- RSS implementation;
- key rotation;
- new transaction formats.

## Related documents

- [ARCHITECTURE_CANON.md](../ARCHITECTURE_CANON.md)
- [PROTOCOL_TRANSPORT_ARCHITECTURE.md](PROTOCOL_TRANSPORT_ARCHITECTURE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [REMOTE_SECRET_SYNC_ADR.md](REMOTE_SECRET_SYNC_ADR.md)
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md)
- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md)
