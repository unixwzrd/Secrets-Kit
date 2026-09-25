# Protocol and Transport Architecture

Status: canonical architecture for daemon transport, protocol envelope handling, and later cross-host, discovery, and Remote Sync Service (RSS) layers.

Architecture note: **the runtime owns state; the daemon owns movement.** The daemon is a transport adapter, not the protocol engine. It owns UDS/TCP availability, connection management, opaque payload routing, transport retry, TLS/session management when implemented, and basic routing metadata. It must not open SQLite, apply transactions, validate transactions, decrypt or encrypt application envelopes, authorize peers at the protocol layer, perform reconciliation, interpret application protocol message types, or generate protocol acknowledgements. Inbound application payloads received over TCP are handed to the runtime through an internal runtime interface. The runtime owns protocol processing and any resulting outbound response envelope.

This document defines the shared peer-safe protocol substrate. Remote synchronization transport details are intentionally outside this public runtime document.

The daemon/runtime boundary is formalized in [DAEMON_RUNTIME_BOUNDARY_ADR.md](DAEMON_RUNTIME_BOUNDARY_ADR.md).

## Event-driven availability and recovery requirement

After authenticated inbound binding on a connection proven relayed by libp2p connection type and same-peer circuit metadata, route selection retains an existing verified circuit or the already selected full circuit for that peer instead of installing an Identify LAN advertisement. Without a selected reverse circuit it installs no new route. Direct, unknown or missing connection metadata does not justify adopting a selected circuit. Authentication, admission, simultaneous-binding ordering and retry policy are unchanged; installed qualification is still required.

Inbound binding can complete its existing runtime-owned challenge, signature and admission checks when peerstore endpoint evidence is unavailable. Missing or expired address metadata does not supply a reverse route; an existing verified circuit remains preserved. An absent claim is diagnosed separately from a mismatched transport identity. Outbound cancellation releases only the attempt-owned inflight tuple and its matching notification entry, allowing a later discovery event to queue once while preserving newer candidates, healthy bindings and rejected authentication state. This adds no retry loop or timer. These source repairs still require installed qualification.

Replacing a discovered RSS dial address refreshes the local peerstore entry before clearing expired address evidence, then retains only the selected circuit address. Missing or expired peerstore evidence is unavailable endpoint information, not peer authorization and not a connection-notification failure. This source repair preserves runtime challenge/signature/admission checks and does not change the rejected-binding retry policy; installed recovery qualification remains pending.

Inbound binding exchanges use the existing binding deadline, with separately bounded stream close. Cancellation propagates after releasing only the exact inflight state owned by that attempt; a disconnected or superseded attempt cannot overwrite a newer binding state merely because its endpoint matches. Authentication and verified-circuit preservation remain unchanged. These deadlines bound cancellable I/O; they do not forcibly terminate a runtime signing operation already executing in a worker thread. This repair is source-tested, not yet installed-qualified.

Incoming recovery binding requests must undergo the existing challenge, signature, transport-identity and admission verification even when a previous binding is cached as healthy or rejected. Cached state does not authorize a peer and must not silently suppress its recovery handshake. Outbound duplicate-event coalescing and simultaneous-binding coordination remain in place; this does not introduce periodic handshakes or a new protocol.

Status: implemented in the source candidate; installed qualification remains pending. Discovery and connection lifecycle events drive transport binding; healthy connections must not be subjected to periodic application identity handshakes. Discovery alone grants no trust. Existing admitted node identity remains stable while its observed address and port may change. Loss of a connection invalidates its ephemeral binding, not peer admission. Successful local pairing explicitly notifies the daemon to reconsider previously rejected candidates through fresh runtime authentication; duplicate events are coalesced and remote callers cannot invoke this same-user control.

Actual envelope delivery uses bounded retries with exponential delay. Exhaustion marks an operational route unavailable and stops automatic transmission attempts until a genuine recovery event, while preserving durable pending work. Successful authenticated return wakes runtime-owned delivery; scope checks, canonical bytes, replay and duplicate validation remain unchanged. The delivery-local attempt counter describes the current bounded episode, not a lifetime audit count: authenticated recovery resets it only for parked retry work, and duplicate wakes during an active episode do not reset its budget or deadline. Libp2p retains connection-management responsibility; the daemon does not acquire datastore or reconciliation authority.

Queued delivery recovery is not proof of complete history reconciliation. The returning-peer requirement includes detecting missing transactions and obtaining them from a mutually validated group peer with bounded sender coordination. Current source implements transaction-envelope fan-out and duplicate suppression, but no missing-history exchange or sender-selection protocol has been identified. This remains an explicit implementation gap requiring protocol review before extension; no new message contract or election mechanism is authorized by this document.

- [Protocol and Transport Architecture](#protocol-and-transport-architecture)
  - [Layering](#layering)
  - [Daemon and Runtime Boundary](#daemon-and-runtime-boundary)
  - [Current Runtime Handoff](#current-runtime-handoff)
  - [Operational Status](#operational-status)
  - [Lifecycle](#lifecycle)
  - [Endpoint, Observation, and Startup Lifecycle](#endpoint-observation-and-startup-lifecycle)
  - [Package Boundary](#package-boundary)
  - [Daemon and RSS Symmetry](#daemon-and-rss-symmetry)
  - [Transports](#transports)
  - [Framing](#framing)
  - [Canonical Envelope](#canonical-envelope)
  - [Envelope Payload Codec](#envelope-payload-codec)
  - [Signing](#signing)
  - [Payload Security](#payload-security)
  - [Identity](#identity)
  - [Test Boundaries](#test-boundaries)

## Layering

```text
daemon transport abstraction
  -> libp2p host (default) or direct TCP compatibility adapter
  -> optional TLS wrapper
  -> length-prefixed JSON frame
  -> routing envelope
  -> signed message envelope
  -> optional encrypted payload
  -> application payload
```

Sockets and libp2p streams are pipes. The transport layer does not know about storage backends, routing policy, or plaintext payloads.

## Daemon and Runtime Boundary

**Architectural invariant: the runtime owns state; the daemon owns movement.**

The daemon is intentionally designed as a communications adapter with no application protocol intelligence. It listens for local messages on UDS, listens for peer traffic on TCP, maintains transport availability, routes opaque payloads between transports, invokes the runtime for inbound application work through an internal runtime interface, and manages transport retry, connections, TLS sessions, and routing metadata.

The daemon must not:

- open or modify SQLite;
- create, validate, or apply transactions;
- decrypt or encrypt application envelopes;
- authorize peers at the protocol layer;
- perform reconciliation;
- generate protocol acknowledgements;
- interpret application protocol message types;
- implement synchronization semantics.

The runtime owns SQLite and persistent state, transactions, protocol semantics, cryptographic envelope processing, authorization, reconciliation, acknowledgements, and protocol responses. The CLI is one interface to the runtime. The daemon is another.

The runtime-to-daemon delivery interface contains only the destination peer identity and opaque canonical envelope bytes. The daemon resolves that peer identity through its in-memory routing table and owns all endpoint, transport, and path selection details. Host names, ports, multiaddrs, relay paths, and transport selection never cross into runtime APIs.

Local daemon control messages may exist for status, graceful shutdown, transport health, and connection management. Those are transport-control messages. Application protocol messages, including transactions, synchronization operations, acknowledgements, reconciliation messages, and protocol-level peer messages wrapped in application envelopes, belong to the runtime even when the daemon physically carries their bytes.

For remote inbound traffic, the daemon receives an opaque payload over TCP and supplies it to the runtime through an internal runtime interface. The initial implementation may use standard input, but the architecture does not require stdin and may later use another internal mechanism. The runtime performs decryption, validation, authorization, transaction application, and acknowledgement generation. Any resulting response envelope returns through the daemon’s local transport path and is routed over TCP.

The exact internal runtime command name is not finalized. It must not be modeled as a `seckit daemon ...` subcommand, because inbound envelope processing is not a daemon responsibility.

The daemon must never become a convenience location for protocol logic simply because it already processes transport events. Any feature requiring protocol knowledge belongs in the runtime.

## Current Runtime Handoff

Inbound TCP application bytes are passed unchanged to the runtime-owned hidden `internal apply-envelope --stdin` operation. The daemon receives only a transport handoff result and does not learn whether an application envelope or transaction was valid.

Outbound durable delivery is runtime-owned. The hidden `internal deliver-pending` operation claims due envelopes, performs Peer Registry authorization and route correlation, submits the already-persisted canonical bytes to the daemon over UDS, and records `sent` or `retry_pending` in separate SQLite transactions. The daemon may schedule at most one non-blocking delivery worker but does not scan or open SQLite.

The UDS routing frame is transport-local metadata containing a version, routing operation, concrete destination, and opaque payload bytes. It is not a canonical application envelope and carries no transaction type, authorization result, envelope validity, or secret metadata.

A successful transport handoff is reported as `delivered`. This is not a protocol acknowledgement. Transport delivery sets `sent_at`; `acknowledged_at` remains reserved for a future runtime-owned protocol acknowledgement.

## Operational Status

Operational status is a control-plane request. It is not an application protocol message, not a datastore transaction, and not part of synchronization semantics.

A status request represents the operational state of an entire node. Status should present a unified view of transport, runtime, and service health rather than exposing separate, unrelated status mechanisms. The daemon may aggregate information from multiple sources, including transport state, runtime state, and service-manager state where applicable. The runtime does not become a transport component merely because the daemon requests runtime status information.

The supported local operator interface is `seckit status`. It requests status through the daemon control plane; the daemon may obtain runtime state through the internal runtime interface and combines it with transport observations. The CLI formats the response and does not read SQLite. This does not introduce a remote API or change protocol ownership. Historical audit reporting remains separate from operational status.

## Lifecycle

The daemon is part of the `seckit` executable for service lifecycle purposes. Lifecycle operations exist, and the daemon may be supervised by launchd, systemd, another service manager, or run standalone. The exact command-line syntax remains an implementation decision.

Local daemon control messages for lifecycle, health, or graceful shutdown may be appropriate when they remain transport-control messages. They must not be confused with application protocol envelopes.

## Endpoint, Observation, and Startup Lifecycle

Persistent configuration belongs to the runtime. This includes the Peer
Registry, node identities, authorization and service groups, relay configuration, configured bootstrap peers, and cryptographic identities.
Relay hostnames, ports, certificates, and bootstrap information are durable configuration; they do not by themselves authorize a peer.

The Peer Registry also persists endpoint metadata as a transaction-derived projection. Endpoint records are keyed by peer identity and carry lifecycle state (`active`, `expired`, or `removed`), the endpoint descriptor, lifecycle timestamps, and optional expiry/operator metadata. Endpoint registration, update/replacement, expiration, and removal are canonical runtime transactions. They do not grant admission or authorization. This durable record is the runtime's last-known endpoint metadata; it is distinct from the daemon's active socket, reachability, and in-memory route cache.

When the daemon binds or rebinds, its runtime registration propagates the canonical lifecycle transaction to admitted peers. Remote runtimes can then replace stale route records without treating endpoint metadata as admission or authorization.

Operational endpoint state belongs to the daemon and is ephemeral. It includes the current endpoint, IP address, TCP port, active connections, connection quality, heartbeat observations, active transport bindings, and routing cache.
Durable endpoint lifecycle records are runtime-owned Peer Registry projections.
The daemon may bind an available endpoint and may bind a different endpoint after restart, DHCP changes, or sleep/wake. The runtime records a canonical endpoint replacement when the newly bound endpoint differs from the prior active record. Loss of daemon state after restart is acceptable because the daemon rebuilds it. A machine is not represented by one permanent endpoint, and endpoint data is never node identity.

The intended startup lifecycle is:

1. Load runtime configuration.
2. Load the Peer Registry.
3. Load relay configuration.
4. Start the daemon.
5. Bind an available endpoint.
6. Register or announce the current endpoint through the approved runtime/control path.
7. Attempt configured bootstrap peers.
8. Attempt the configured RSS connection when applicable.
9. Build the daemon-owned routing cache.
10. Begin normal transport operation.

Endpoint discovery and registration locate candidate endpoints only. They never authorize a peer. Transport observations such as reachability, endpoint changes, RSS connection changes, heartbeat receipt, and heartbeat timeout are reported to the runtime through the internal runtime interface. The runtime decides which observations become durable projections or operator-visible state; the daemon does not update SQLite directly.

Heartbeats establish transport availability only. Their timing is an implementation decision. Heartbeats are not synchronization, reconciliation, or application protocol messages.

The daemon must not ask protocol questions such as “what is the latest transaction?”, “what is the reconciliation state?”, or “should this peer synchronize?”. It reports transport events; the runtime decides whether reconciliation is required and generates any protocol envelopes.

## Package Boundary

Package layout follows architectural ownership. Runtime responsibilities must not remain inside daemon modules merely because they were historically implemented there. Existing package layout is not architectural authority.

Daemon modules should contain transport-adapter code. Runtime modules should contain protocol, persistence, cryptographic, authorization, reconciliation, acknowledgement, and transaction logic.

## Daemon and RSS Symmetry

The local daemon and future Remote Sync Service share the same transport-only philosophy:

```text
UDS  <->  daemon  <->  TCP
TCP  <->  RSS     <->  TCP
```

Both components move opaque payloads. Neither owns datastore authority, transaction authority, protocol authority, cryptographic authority, reconciliation authority, or synchronization authority. The primary distinction is only the transports they bridge. Future implementation should preserve this symmetry.

## Transports

The daemon uses a stable transport-adapter contract selected through a bounded built-in registry. `PyLibP2PTransport` is the preferred production adapter; `DirectTCPTransport` is an explicitly selected compatibility adapter. A selected adapter that cannot start fails closed. The daemon never silently downgrades from libp2p Noise to direct TCP.

Every adapter accepts only a Secrets Kit destination peer identity and opaque canonical envelope bytes. It returns a transport receipt and a transport-neutral operational snapshot. Future reviewed in-process or sidecar adapters must implement this same contract without changing runtime behavior.
Arbitrary third-party entry-point loading is not part of the current product.

**Transport adapters own transport identity. The runtime owns application identity.** Transport adapters may create and observe their own ephemeral transport identities, but they must not generate, interpret, authorize, or persist Secrets Kit node identities. The runtime owns node identities and Peer Registry authorization while treating transport identity as opaque binding material. It must not interpret PeerIDs, multiaddrs, sockets, or transport-specific addressing.

The py-libp2p adapter uses Ed25519 identity and the Noise secure transport only. SECIO, plaintext libp2p, and TLS fallback are not registered in the Secrets Kit transport profile. Application-envelope protection remains runtime-owned; Noise independently authenticates and protects the transport session.

Secrets Kit's preferred production dependency remains an official upstream py-libp2p release with a Noise-only dependency graph. Until that graph is available, the beta installer may apply the approved exact dependency override defined by [NATIVE_DEPENDENCY_RELOCATION_ADR.md](NATIVE_DEPENDENCY_RELOCATION_ADR.md).
Secrets Kit does not fork, rewrite, vendor, publish, or redistribute third-party wheels.

When a daemon binds a wildcard or otherwise local-only address, `SECKIT_DAEMON_ADVERTISED_ENDPOINT` may supply the externally reachable endpoint that the runtime registers for peers. The bind address and advertised endpoint are distinct operational values; the advertised value is never used as a peer identity.

Same-LAN libp2p discovery is enabled by default unless explicitly disabled.
The daemon starts mDNS only after the libp2p listener has selected its actual port, consumes discovered `PeerInfo` records, connects to candidates, and lets the built-in secure handshake and Identify protocol populate the peerstore.
Configured bootstrap peers remain optional candidate locators. Neither mDNS nor bootstrap configuration grants application authorization.

Identify binds addresses, supported protocols, signed peer records, and the libp2p public key to the authenticated libp2p PeerID. It does not bind that PeerID to Secrets Kit's separate `node:<uuid>` identity. Secrets Kit therefore adds only a post-Identify transport-control challenge/response for that final mapping. The runtime creates and verifies its signature against admitted Peer Registry keys while treating transport identity as opaque. The daemon checks the claim against the connected PeerID and stores the verified mapping only in its ephemeral routing cache. Application envelopes and canonical protocol formats are unchanged.

Configured relay peers may later attach libp2p's client-side Circuit Relay v2 services and reservations; this repository does not implement a relay service.
AutoNAT and DCUtR remain separately qualified transport capabilities. Relay configuration never grants application authorization.

Transport-control surfaces may include:

- Unix domain socket helpers for same-host local IPC
- peer TCP listeners and outbound peer TCP connections
- local daemon status, shutdown, and health control messages
- opaque envelope routing between UDS and TCP
- delivery retry and connection management
- transport metadata that remains outside canonical protocol envelopes
- libp2p host lifecycle, local discovery, bootstrap dialing, and opaque streams

Not implemented or not yet demonstrated:

- websockets
- HTTP transport
- gRPC
- service mesh abstractions
- TLS transport wrapping
- length-prefixed frame codec in `seckitd`
- fixed singleton local ports
- installed-product cross-host qualification using signed/encrypted envelopes
- demonstrated five-target dynamic endpoint and rediscovery evidence
- discovery outside a single IPv4 LAN broadcast domain
- NAT traversal
- Circuit Relay v2 reservation, AutoNAT, and DCUtR qualification
- RSS delivery
- hosted RSS service

Local automated integration tests exercise signed/encrypted daemon TCP delivery between isolated SQLite nodes on one machine through the remediated transport-adapter boundary. They prove opaque daemon movement, runtime-owned inbound processing and durable outbound delivery, duplicate suppression, restart retry, two-node convergence, and three-node fan-out. They are not proof of cross-host P2P, RSS, discovery, NAT traversal, hosted RSS behavior, or production deployment behavior.

The local lab uses isolated node state: independent `HOME`/operator stores, SQLite databases, node identities, daemon runtime directories, logs, sockets, and TCP ports. Plaintext SQLite mode is used for protocol-development visibility. Active local multi-node tests do not share SQLite storage keys.

AP2P-01 demonstrated authenticated local multi-node synchronization under one Unix user. That behavior has now been revalidated after removing protocol, crypto, SQLite, authorization, transaction, and durable queue responsibilities from the daemon package.

## Framing

Direct TCP and local control paths use the target frame format:

```text
uint32_be length
utf-8 JSON object bytes
```

The JSON object can be inspected with small shell/Python tools:

```bash
python - <<'PY'
import json, struct, sys
raw = sys.stdin.buffer.read()
n = struct.unpack(">I", raw[:4])[0]
print(json.dumps(json.loads(raw[4:4+n]), indent=2, sort_keys=True))
PY
```

The libp2p stream uses a length-prefixed opaque byte frame for the same transport handoff. The daemon may validate transport framing and transport-control messages. Application envelope parsing and validation belong to the runtime.

Signature verification does not depend on frame bytes or parser-specific JSON key ordering.

## Canonical Envelope

The canonical protocol envelope is deterministic, versioned, transport-independent, persistence-independent, and immutable after creation except for local transport metadata stored outside the protocol object.

Current canonical transaction-envelope fields are:

- `version`
- `envelope_version`
- `envelope_id`
- `message_type`
- `message_id`
- `source_node_id`
- `destination_node_id`
- `transaction_id`
- `protocol_version`
- `created_at`
- `expires_at`
- `routing`
- `payload`
- `payload_hash`
- `signature_metadata`
- `encryption_metadata`

`message_id` currently equals `envelope_id` for daemon compatibility. `payload_hash` is a SHA-256 commitment over the codec output bytes carried by the envelope payload. `signature_metadata` carries EL-02 Ed25519 signature metadata. `encryption_metadata` carries EL-03 encrypted-payload metadata when the encrypted envelope payload codec is selected and remains `null` for plaintext payloads.

Local delivery state is not protocol state. Retry counters, claim timestamps, sent/acknowledged timestamps, failure diagnostics, retry scheduling, and SQLite lifecycle state remain local transport metadata and must not affect canonical envelope bytes.

Protocol handlers in the runtime reject unsupported version values, malformed identifiers, invalid routing fields, missing required fields, duplicate JSON fields, and payload commitment mismatches. The daemon must not become the application protocol validator.

## Envelope Payload Codec

ARCH-01 introduced one canonical envelope payload-codec boundary. Every outbound envelope payload passes through the codec before envelope construction. Every inbound envelope payload passes through the codec before transaction parsing. Code above this boundary must not branch around envelope processing based on SQLite storage mode.

The current implemented codecs are `plaintext` and `encrypted`.

`plaintext` is an identity transform:

```text
encode(canonical_payload_bytes) -> canonical_payload_bytes
decode(encoded_payload_bytes) -> canonical_payload_bytes
```

`plaintext` is an explicit immutable SQLite storage mode used by local protocol-development labs for visibility. It is not a debug switch and it does not disable identifier validation, canonical serialization, payload hashing, peer admission, Peer Registry authorization, transaction validation, envelope validation, replay rules, or signature behavior.

The `encrypted` envelope payload codec encrypts canonical payload bytes for one destination node using the recipient node encryption public key and an ephemeral X25519 sender key, with HKDF-derived ChaCha20-Poly1305 payload encryption. The protocol-visible encryption metadata records the algorithm suite, recipient node id, recipient key fingerprint, ephemeral public key, nonce, and AAD profile. Private keys and ephemeral private keys are never serialized or persisted in envelopes.

SQLite local-storage encryption and `sqlite-storage.key` remain local datastore protection only; they are not peer-envelope encryption and must not become peer-envelope keys.

`payload_hash` commits to the codec output bytes carried by the envelope. In plaintext mode those bytes are identical to the canonical transaction payload bytes. In encrypted-envelope mode the commitment binds ciphertext bytes without exposing plaintext to transport or RSS layers. Transaction-level payload hashes remain inside the decoded transaction record.

## Signing

EL-02 implements canonical signed transaction envelopes for runtime-created application envelopes.

The signed object is the canonical envelope bytes with identical signature metadata except `signature` is `null`. The final signature metadata includes:

- `version`
- `algorithm`
- `signer_node_id`
- `key_fingerprint`
- `signature`

The signature binds symbolic node identifiers, routing fields, destination, timestamp, payload codec metadata, and payload commitment. It does not bind transport framing, hostnames, ports, runtime paths, SQLite row metadata, retry counters, or local configuration.

Outbound signing occurs after payload codec processing, payload commitment generation, and canonical envelope construction. Inbound verification occurs in the runtime before payload decoding, transaction parsing, or transaction-engine submission.

Verification requires the source node to be an admitted, authorized, synchronization-eligible Peer Registry entry. The admitted signing public key must match the signature metadata fingerprint and verify the canonical envelope bytes. Unknown peers, inactive peers, unauthorized peers, modified payloads, modified routing, modified identifiers, modified timestamps, and corrupted signatures fail in the runtime before payload decode.

For encrypted envelopes, runtime inbound processing first confirms the envelope is addressed to the local node, then verifies the source Peer Registry state and canonical signature, and only then decrypts the payload. Payload decode and transaction parsing must not occur before successful signature verification.

Retries retransmit the already-persisted canonical envelope bytes. They must not regenerate payloads, payload commitments, signatures, or canonical JSON.

Signed and encrypted envelopes are source- and destination-specific. A transport adapter must not retarget, decrypt, re-encrypt, or re-sign another node's transaction envelope. Multi-hop forwarding and RSS-safe recipient handling remain future protocol work.

## Payload Security

Payload encryption is destination-specific envelope protection, not transport security and not local SQLite storage encryption. It provides payload confidentiality for selected transaction envelopes while preserving the same canonical envelope, signature, transaction-engine, replay, runtime, and transport boundaries.

Envelope payload codec modes are explicit protocol choices:

- `plaintext`: identity-transform payload codec used where visible local protocol development or compatibility requires it;
- `encrypted`: destination-specific encrypted payload codec using admitted node encryption identity.

Neither mode changes transaction validation, Peer Registry authorization, replay semantics, envelope signing, or transport authority.

## Identity

Identity layers:

- node identity
- runtime instance identity: selected runtime namespace
- agent identity: local process/daemon identity within the instance
- session identity: per-connection runtime session id

Transport endpoints are not stable identity. Secrets Kit runs one daemon per operating-system user, without a privileged host-wide broker or privilege escalation. Multiple users on one host therefore have independent daemon listeners and routing state.

Endpoint assignment is dynamic operational state. A daemon may bind an available TCP port and may bind a different port after restart, DHCP changes, or sleep/wake. A machine is not represented by one permanent endpoint.
Static `host:port` or `node_id@host:port` values are bootstrap hints only; they are not durable application state, node identity, or authorization.

The daemon owns an ephemeral routing cache and active endpoint bindings. At daemon startup it registers the bound endpoint through the runtime interface and refreshes routes from the runtime's active endpoint projection. A restart may bind a different port; the previous endpoint is replaced by a canonical endpoint transaction and the daemon rebuilds its cache. Endpoint discovery or re-registration may locate a candidate, but the Peer Registry must still explicitly authorize synchronization.

Each node is expected to own its own long-lived signing and encryption keypairs. Private keys remain on the originating node. Public keys and fingerprints are exchanged only through explicit peer admission. Discovery may locate a candidate endpoint but must not authorize it.

Peer identity keys are distinct from SQLite storage keys. Active local multi-node tests use plaintext SQLite mode and independent node stores; they do not share SQLite storage keys.

Protocol-visible object identity uses immutable typed UUID identifiers. Human-facing display names are mutable projections and are not routing, admission, authorization, replay, or billing identity. See [PROTOCOL_IDENTITY_AND_NAMING_ADR.md](PROTOCOL_IDENTITY_AND_NAMING_ADR.md).

The Peer Registry owns admitted peer identity, peer state, durable endpoint records, peer authorization, and synchronization eligibility. Static daemon peer configuration is transport bootstrap configuration only, not peer trust authority. Runtime signed/encrypted envelope processing consults admitted and authorized peer state before transaction submission. Authorization mode `none` permits peer-level control traffic but no service-group-scoped datastore synchronization; `allow_list` permits only explicitly projected service groups; `all` is the only explicit wildcard. Missing allow-list rows never imply wildcard access. Endpoint records are metadata and do not authorize a peer.

## Test Boundaries

- Producer tests verify CLI commands create canonical transactions.
- Transaction-engine tests may inject canonical transactions directly.
- Replication tests may inject canonical transactions or envelopes into isolated node instances.
- Transport tests verify delivery without redefining projection semantics.
- End-to-end tests must prove CLI-originated mutations traverse the same canonical transaction/envelope path.
