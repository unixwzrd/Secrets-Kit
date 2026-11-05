> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# Security Model

**Created**: 2026-03-10

**Updated**: 2026-11-04

- [Security Model](#security-model)
  - [Runtime layers](#runtime-layers)
  - [Where values live](#where-values-live)
  - [SQLite local storage](#sqlite-local-storage)
  - [SQLite operator store](#sqlite-operator-store)
  - [How entries are identified](#how-entries-are-identified)
  - [What the redaction rules do](#what-the-redaction-rules-do)
  - [Protected authority handling (summary)](#protected-authority-handling-summary)
  - [What this protects against](#what-this-protects-against)
  - [What this does not protect against](#what-this-does-not-protect-against)
  - [launchd and unattended services](#launchd-and-unattended-services)
  - [Permissions and drift](#permissions-and-drift)
  - [Legacy Keychain migration](#legacy-keychain-migration)
  - [Sync behavior](#sync-behavior)
  - [Practical takeaway](#practical-takeaway)
  - [Back to README](#back-to-readme)


Secrets Kit is a local workflow improvement, not a promise of perfect protection.

If you understand that up front, the tool makes more sense and is easier to use safely.

## Runtime layers

```text
CLI / runtime layer
    → command parsing, selection, launch/injection flows

Local authority layer
    → sqlite backend
    → explicit legacy Keychain migration input

Metadata / index layer
    → operator store files
    → schema catalog
    → lineage / transactions / projections / replay state

Transport / synchronization layer
    → explicit export/import artifacts
    → daemon transport abstraction (py-libp2p default; opaque envelope movement)
    → authenticated LAN P2P and RSS forwarding of encrypted peer envelopes
```

SQLite is the operational local storage authority. Keychain is a read-only migration source and is not selectable for normal secret operations. The daemon transport abstraction and RSS transport encrypted artifacts between local stores and are not themselves authoritative secret backends.

## Where values live

- secret values and authoritative metadata are stored in SQLite
- legacy macOS generic-password items may be read only during explicit migration from the login Keychain or a selected Keychain file
- `~/.config/seckit/registry.json` stores local schema/catalog definitions only
- operator defaults live in `~/.config/seckit/defaults.json`
- the SQLite datastore records its immutable storage mode inside SQLite
- in encrypted mode, the SQLite storage key lives in `~/.config/seckit/sqlite-storage.key`
- the SQLite node identity material lives in `~/.config/seckit/node-identity.key`
- the daemon's operational libp2p identity lives in its protected runtime directory as `libp2p-identity.key` and is retained across daemon restarts
- peer identity keys are separate signing/encryption keys used for node identity and authenticated peer envelopes
- peer identity keys and the operational libp2p identity are distinct from the local SQLite storage key

Storage protection is determined by SQLite's immutable storage mode and local keys. Current transport plumbing and P2P/RSS layers are not queried as authoritative secret stores.

The registry exists so the tool can validate and normalize metadata against local catalog rules without becoming inventory or metadata authority.

SQLite storage keys are local datastore protection keys. They must not be shared between real peers. For encrypted SQLite synchronization, a sender decrypts only the local storage fields immediately before destination-specific envelope encryption. After authenticated envelope decryption, the receiving peer re-encrypts those fields with its independent local storage key. RSS sees only the destination-encrypted opaque envelope and never receives either local storage key or plaintext payload.

Owner-only filesystem permissions restrict ordinary local users, but they do not protect against an operating-system administrator who can access both the encrypted SQLite database and its local storage key. An administrator with that access can decrypt local secrets. RSS and other remote synchronization infrastructure receive neither the local storage key nor plaintext secret payloads.

Envelope payload encryption uses node encryption identities and destination-specific protocol metadata. It does not use `sqlite-storage.key`, does not change SQLite storage mode, and does not make transport, relay, daemon, or Peer Registry components secret authority.

Normal initialization (`seckit init`) selects SQLite with encrypted local storage. Normal synchronization encrypts destination envelopes equally on LAN P2P and RSS, independent of RSS enrollment and storage-at-rest configuration. These are separate controls, not application operating modes. Developer tests requiring unencrypted storage must explicitly use the hidden `--unsafe-plaintext-storage` override; it does not enable general debug behavior or disable envelope encryption. Unencrypted envelope fixtures require both `SECKIT_ENVELOPE_PAYLOAD_CODEC=plaintext` and `SECKIT_UNSAFE_PLAINTEXT_ENVELOPES=1`; neither is persisted as an application setting. Live inbound synchronization rejects plaintext before decoding or transaction application, including when a plaintext fixture override is set. Envelope construction requires an explicit codec; destination validation is independent of codec selection. Custom datastore paths never imply provisioning or relaxed identity validation, and the obsolete `SECKIT_SQLITE_STORAGE_MODE` environment variable cannot select storage. Runtime debug/development flags are absent. Direct TCP requires `SECKIT_UNSAFE_TEST_DIRECT_TCP=1` and is only a test transport; it does not disable envelope encryption or authorization. Installer `--dev` only selects an editable installation. These unsafe overrides are not part of the customer workflow. Existing immutable datastore metadata is retained, not migrated or repurposed into a general application mode.

Secrets Kit runs one daemon per operating-system user without a privileged host-wide broker or privilege escalation. The runtime Peer Registry owns durable endpoint lifecycle records and authorization. The daemon owns the current endpoint binding, connections, heartbeat observations, active transport registrations, and routing cache as ephemeral transport state. Endpoint discovery and re-registration locate candidates but do not authorize them.
Transport observations are reported to the runtime, which decides whether they become durable state. Heartbeats are transport health, not protocol synchronization.

## SQLite local storage

SQLite is a local storage backend. Storage protection is determined by the configured crypto/storage implementation attached to the backend instance.

When SQLite is the configured backend:

- the datastore has an immutable storage mode, `encrypted` or `plaintext`, recorded inside SQLite at initialization;
- `encrypted` is the default mode and requires the local SQLite storage key;
- `plaintext` mode is explicit, visibly reported by `seckit info`, emits an operator warning, stores local secret name/payload bytes unencrypted, and does not create or require a usable SQLite storage key;
- operator defaults may describe the intended storage mode but must not override an existing database; mismatches are fatal;
- runtime must not silently convert, toggle, or repair storage mode;
- canonical transaction history is stored in SQLite `transactions` rows;
- current read models are projections derived from accepted transactions;
- replay rebuilds transaction-owned projections from transaction history;
- projection rows are derived state, not canonical history.

SQLite local storage does not make `registry.json` secret authority. The configured backend is secret authority. `registry.json` remains schema/catalog state only.

## SQLite operator store

The local SQLite operator store is the operator-owned directory:

```text
~/.config/seckit/
```

The current operator store includes:

- `defaults.json` — operator defaults;
- `registry.json` — schema/catalog definitions only;
- `seckit.sqlite` — SQLite datastore;
- `sqlite-storage.key` — local SQLite storage key, present for encrypted SQLite datastores;
- `node-identity.key` — local node signing/encryption identity material.

`seckit init` provisions the operator store. For SQLite, initialization creates the config directory, defaults file, registry catalog, SQLite database with immutable storage-mode metadata, and local node identity so the backend is immediately ready for normal CLI use. In encrypted mode, initialization also creates the SQLite storage key.

Runtime validates the operator store before SQLite backend use. Validation checks:

- owner uid;
- expected filesystem object type;
- symbolic links are rejected;
- required files;
- config directory permissions;
- database permissions;
- storage-key permissions when the datastore is encrypted;
- node-identity material permissions;
- defaults file permissions;
- registry file permissions.

Expected permissions:

```text
~/.config/seckit/          0700
defaults.json              0600
registry.json              0600
seckit.sqlite              0600
sqlite-storage.key         0600 when encrypted
node-identity.key          0600
```

Runtime validation is intentionally fatal. It does not silently repair ownership or permissions. A validation failure includes the failing path, expected permissions, actual permissions or owner state, and an actionable `chmod` / `chown` remediation hint.

Operator-store artifacts must be ordinary expected filesystem objects: directory for `~/.config/seckit/` and regular files for the store artifacts.
Symbolic links, sockets, FIFOs, block devices, character devices, and other unexpected object types are refused.

Runtime refuses to silently repair operator-store security because unexpected permission or ownership changes may indicate operator error, system misconfiguration, or compromise.

Provisioning and runtime have separate responsibilities:

- `seckit init` provisions the operator store;
- provisioning creates SQLite schema, datastore metadata, storage keys, node identity, and local-node projection state;
- opening an existing SQLite datastore opens the connection only;
- runtime validates the operator store;
- runtime validation is read-only;
- runtime does not create schema, metadata, storage keys, node identity, or local-node projection state;
- runtime never silently repairs operator-store security.

## How entries are identified

Each entry is defined by three fields:

- `service`
- `account`
- `name`

That lets you keep the same environment-variable-style name in different scopes without collisions.

## What the redaction rules do

Normal output is redacted by default. You have to explicitly ask for raw values with commands like `get --raw`, export them for a shell session, or launch a child process with `seckit run`.

That default helps prevent casual leaks into terminal history, screenshots, or copied command output.

## Protected authority handling (summary)

**Resolve** means Secrets Kit obtains authoritative entry data inside protected handling. **Materialize** means secret plaintext crosses into an operator-visible or process-visible channel, such as terminal output, an export file, or a child process environment. **Injection** with `seckit run` is a runtime-scoped materialization path and may propagate via environment inheritance unless constrained.

Treat **helpers**, **`repr`**, **loggers**, and **tracebacks** as high risk: they must not **implicitly** surface plaintext outside explicit materialization commands. Exposure labels are descriptive vocabulary only, not compliance tiers.

## What this protects against

Secrets Kit helps with a very common local problem:

- too many `.env` files
- secrets copied into shell rc files
- raw tokens committed by mistake
- values left behind in project directories and archives

Moving those values into encrypted SQLite and launching processes through `seckit run` is a meaningful improvement over plain-text sprawl. Shell export remains available for interactive sessions, but it should not be the default process-launch pattern.

## What this does not protect against

Secrets Kit does not make a compromised local machine safe.

If malware, a hostile script, or an already-compromised shell session can access the local SQLite key or a launched process environment, Secrets Kit cannot override that reality. Child processes launched with `seckit run` can read every selected variable they inherit. RSS is an encrypted forwarding service, not a remote plaintext secret store. Peer admission creates an explicit multi-host trust relationship; it does not make a compromised authorized peer safe.

## launchd and unattended services

Normal operations use the encrypted SQLite operator store. A legacy service Keychain may be selected only as an explicit migration source; it remains untouched after migration. Unattended launchd access to the operator store and its local key requires the same OS account and filesystem permissions as interactive use.

## Permissions and drift

- the operator store directory is validated at `0700`
- `defaults.json` is validated at `0600`
- `registry.json` is validated at `0600`
- `seckit.sqlite` is validated at `0600`
- `sqlite-storage.key` is validated at `0600` when the SQLite datastore is encrypted
- `node-identity.key` is validated at `0600`
- operator-store paths must be owned by the current user
- operator-store paths must not be symbolic links
- runtime refuses unsafe operator-store permissions instead of silently repairing them
- `doctor` reports SQLite operator-store health
- `doctor`, `list`, and `explain` can surface rotation and expiry warnings

Security invariants:

- SQLite is secret authority;
- `registry.json` is never secret authority;
- SQLite transactions are replay authority;
- SQLite projections are derived state;
- transport layers are not secret authority;
- runtime never silently repairs operator-store security;
- daemon, P2P, and RSS components must use the common operator-store validation path.

Future integrity mechanisms may strengthen validation while preserving these invariants. Examples include payload hashes, row hashes, transaction signatures, replay integrity verification, or similar mechanisms. Specific algorithms are intentionally not specified here.

## Legacy Keychain migration

On macOS, `seckit migrate keychain --service SERVICE --account ACCOUNT [--keychain PATH]` produces a dry-run inventory of the selected scope without requesting password values. Dry-run also works before SQLite initialization and marks target states unavailable. Applying migration requires a valid encrypted SQLite operator store. For a legacy home with no SQLite database, `seckit init sqlite` provisions the target while retaining existing defaults and catalog data; never run it against an existing SQLite database, because that command recreates the database. Use `seckit init` only for a fresh operator home; it resets an existing home's defaults and catalog. Review the inventory, then repeat the migration command with `--apply` to copy. Migration never runs during initialization, startup, or upgrade. Original Keychain records and existing SQLite data are preserved.

Known legacy generic-password records use `SERVICE:NAME` and `ACCOUNT`. The migrator accepts the structured JSON metadata formerly stored in the Keychain comment field, or a record with no comment and minimal generated metadata. Invalid, duplicate, ambiguous, or unsupported records stop the selected migration scope. Inventory subprocess output is bounded to 8 MiB while being read, with at most 10,000 parsed items; an individual password read is limited to 1 MiB. Password bytes are read directly from the selected Keychain through the macOS Security framework, never through subprocess arguments, logs, diagnostics, or temporary files. UTF-8 values are copied byte-exactly, including empty values and whitespace; unsupported encodings fail closed. The legacy CLI may already have stored some Unicode or newline-containing inputs as hex text. Migration preserves the bytes actually stored in Keychain and does not guess or decode ambiguous hex text. A different existing SQLite value or metadata, including a deleted identity, prevents copying. An interrupted run can be repeated: matching verified records are skipped and only absent records are copied.

Migrated credentials are local only by default; their transaction history creates no outbound envelopes. `--apply --authorize-sync` first copies and verifies the entire selected scope, then explicitly queues retained transactions for peers currently eligible to receive them. The same command can be repeated after a local-only migration or after a new peer becomes eligible: it verifies unchanged Keychain and SQLite values, then creates missing envelopes without rewriting credentials. If copying fails partway, no synchronization is queued; a later run verifies and skips matching copied items. Authorization requires the original Keychain source and one unchanged active SQLite secret transaction per selected item. No Keychain write or automatic deletion occurs. After verifying migration, set a retained legacy `backend=keychain` default to `sqlite` with `seckit config set backend sqlite`; an overriding `SECKIT_DEFAULT_BACKEND` environment variable must also be changed. Normal operations then use SQLite exclusively. Preserve the original Keychain until the SQLite inventory and values have been independently verified.

Encrypted JSON backup import accepts the documented scrypt profile `n=16384`, `r=8`, `p=1`, with a 16-byte salt, and rejects unsupported parameters before key derivation. The default encrypted export and import byte limit is 128 MiB. An operator may set `--max-backup-bytes N` on encrypted export or import to use a reviewed larger size; import reads no more than `N+1` bytes before rejecting an oversized file. Secret value whitespace is preserved exactly. Existing backups produced by Secrets Kit use the documented scrypt profile; a historical file above the default size requires an explicit size limit selected by the operator.

## Sync behavior

Cross-host workflows use explicit **export** and **import** with an operator-selected file-transfer path, or synchronization between explicitly admitted peers over authenticated P2P or RSS.

**Daemon/envelope transport boundary:** **the runtime owns state; the daemon owns movement.** The daemon uses a stable adapter contract and bounded built-in registry; it is not a protocol, crypto, database, transaction, policy, reconciliation, synchronization, or secret authority. `PyLibP2PTransport` is the default operational adapter and uses Noise only. `DirectTCPTransport` requires an explicit unsafe test flag; startup never silently downgrades to it. Application envelopes received by an adapter are supplied unchanged to the runtime through an internal runtime interface. The runtime owns decryption, signature verification, Peer Registry authorization, transaction validation, transaction application, reconciliation, and protocol acknowledgements.

Transport adapters own transport identity. The runtime owns application identity. Adapters must not generate, interpret, authorize, or persist Secrets Kit node identities. Runtime code treats transport identity as opaque binding material and must not interpret PeerIDs, multiaddrs, sockets, or transport-specific addressing. Libp2p PeerIDs and relay-path metadata never replace Secrets Kit node identity or application authorization.

SECIO, plaintext libp2p, and TLS fallback are excluded from the Secrets Kit py-libp2p profile. The preferred production dependency remains an official upstream py-libp2p release supporting a Noise-only dependency graph. Until available, the installer may deterministically relocate an approved upstream native dependency inside the isolated local runtime as defined by [NATIVE_DEPENDENCY_RELOCATION_ADR.md](NATIVE_DEPENDENCY_RELOCATION_ADR.md).
Each release candidate must qualify the provenance and security status of its pinned py-libp2p dependency before promotion.

Libp2p's secure handshake and Identify protocol authenticate the transport PeerID and its signed peer records. They do not authenticate the separate Secrets Kit node UUID. The daemon therefore carries a challenge-bound mapping claim after Identify. Runtime-owned code signs the local claim and validates a remote claim against the explicitly admitted peer's signing key; the daemon only checks that the opaque claimed transport identity matches the active libp2p connection. A discovered, unidentified, unadmitted, mismatched, or invalidly signed candidate cannot become an application route.

See [DAEMON_RUNTIME_BOUNDARY_ADR.md](DAEMON_RUNTIME_BOUNDARY_ADR.md) for the canonical daemon/runtime boundary.

Operational status is a control-plane view of node health. It is not an application protocol message, datastore transaction, or synchronization semantic. `seckit status` obtains this view from the local daemon; the daemon may aggregate transport, runtime, and service-manager state without making the runtime a transport component. The CLI does not read SQLite directly, and operational status is separate from historical audit reporting.

Synchronization components transport transaction envelopes. They are not secret authority, datastore authority, crypto authority, identity authority, policy authority, or RSS authority. CLI-originated mutations and remotely received mutations must pass through the same transaction validation, persistence, application, projection, and envelope pipeline. Read-only commands such as `get`, `list`, and `explain` resolve authority but do not create transactions.

Peer bootstrap uses explicit admission. Discovery may locate a candidate node but must not authorize it. RSS registration and billing identity are separate from cryptographic node identity unless a later ADR deliberately connects them.

Signed admission requests and decisions prove possession before admission transactions are persisted; explicit operator acceptance remains required. This does not make discovery an authorization mechanism or guarantee general NAT traversal or transport availability.

The daemon carries opaque envelope bytes and receives transport handoff results; runtime-owned code verifies signatures, decrypts payloads, authorizes peers, submits transactions, and owns durable delivery state.

Peer Registry authorization is required for synchronization. Static daemon peer configuration is transport bootstrap only and does not grant trust. Admission and service-group synchronization authorization are separate: `peer accept NODE_ID` admits with authorization mode `none`, repeated `--service-group-id` grants an explicit allow-list, and `--all-service-groups` is the only explicit wildcard. Empty or missing allow-list rows deny service-group-scoped datastore synchronization.

An explicitly invoked `seckit peer revoke NODE_ID` ends an active peer's local admission through a canonical, replayable transaction. It does not propagate a revocation instruction to other nodes or erase historical transactions, delivered secrets, or peer identity records. `peer reject` remains limited to pending requests. A successful revoke waits for any local outbound send already in progress to finish, then commits the revoked projection and denies queued envelopes while holding the same peer delivery boundary. From that commit onward, this node rejects the peer's inbound transactions and new application identity bindings, creates no new envelopes for it, and starts no outbound delivery to it. A payload already handed to transport before the commit may still be processed remotely afterward; revocation cannot retract it. If the delivery boundary cannot be acquired, the operation must fail without claiming that revocation took effect.

Node identity initialization target:

- every initialized SQLite node currently generates or loads its own long-lived signing and encryption keypairs during `seckit init`;
- private keys never leave the originating node;
- private key material is stored only in local operator-store identity material, with SQLite storing public keys and private-key references;
- public keys and fingerprints are exchanged only during explicit peer admission;
- node identity keys are distinct from the SQLite storage key;
- each node is authoritative for its own identity;
- peer trust is explicit registration/admission, not discovery.

Final key storage, wrapping, rotation, and bootstrap protocol formats remain open implementation decisions.

Protocol-visible identity uses immutable typed UUID identifiers. Human-readable names are mutable projections, not routing, admission, authorization, replay, reconciliation, or billing identity. See [LOCAL_FIRST_DATASTORE_ARCHITECTURE.md](LOCAL_FIRST_DATASTORE_ARCHITECTURE.md).

Secrets-Kit does **not** use Apple-managed Keychain replication. Cross-host operator work uses explicit encrypted artifacts or authorized peer synchronization.

**Resilience, noisy export, uninstall:** export/import is the documented resilience path; full plaintext export is **explicit and high-friction**, not a default backup. The supported uninstaller preserves customer data by default; permanent removal requires explicit bounded selections. See [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md).

## Practical takeaway

Use Secrets Kit when you want a more disciplined local workflow for tokens, passwords, API keys, and PII on macOS. Do not use it as an excuse to stop thinking about process isolation, machine trust, or downstream runtime behavior.

## [Back to README](../README.md)
