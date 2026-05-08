# Secrets Kit Glossary of Terms

- [Secrets Kit Glossary of Terms](#secrets-kit-glossary-of-terms)
  - [AAD](#aad)
  - [ADR](#adr)
  - [AEAD](#aead)
  - [Append-Oriented Storage](#append-oriented-storage)
  - [Argon2id](#argon2id)
  - [Authority](#authority)
  - [Backend](#backend)
  - [BackendStore](#backendstore)
  - [Bundle](#bundle)
  - [CA (Certificate Authority)](#ca-certificate-authority)
  - [Ciphertext](#ciphertext)
  - [CLI](#cli)
  - [Conflict Lineage](#conflict-lineage)
  - [Conflict Resolution](#conflict-resolution)
  - [CRUD](#crud)
  - [Datastore Identity](#datastore-identity)
  - [DEK](#dek)
  - [DPAPI](#dpapi)
  - [Ed25519](#ed25519)
  - [Encryption at Rest](#encryption-at-rest)
  - [Encryption in Transit](#encryption-in-transit)
  - [Eventual Consistency](#eventual-consistency)
  - [Host Identity](#host-identity)
  - [Integrity Metadata](#integrity-metadata)
  - [IPC](#ipc)
  - [KDF](#kdf)
  - [KEK](#kek)
  - [Keychain](#keychain)
  - [LaunchAgent](#launchagent)
  - [launchd](#launchd)
  - [LaunchDaemon](#launchdaemon)
  - [libsodium](#libsodium)
  - [Lineage](#lineage)
  - [Local Authority](#local-authority)
  - [Local-first](#local-first)
  - [Metadata](#metadata)
  - [Nonce](#nonce)
  - [Object Identity](#object-identity)
  - [P2P (Peer-to-Peer)](#p2p-peer-to-peer)
  - [Peer](#peer)
  - [Peer Authority](#peer-authority)
  - [Peer Trust](#peer-trust)
  - [Plaintext](#plaintext)
  - [Proxy / Relay](#proxy--relay)
  - [Public/Private Key Pair](#publicprivate-key-pair)
  - [Relay](#relay)
  - [Relay (optional future)](#relay-optional-future)
  - [Revision](#revision)
  - [Revision Lineage](#revision-lineage)
  - [Runtime Injection](#runtime-injection)
  - [Secret Store](#secret-store)
  - [Secure Enclave](#secure-enclave)
  - [Service Group](#service-group)
  - [SQLite](#sqlite)
  - [Synchronization](#synchronization)
  - [Synchronization Authority](#synchronization-authority)
  - [systemd](#systemd)
  - [Tombstone](#tombstone)
  - [TPM](#tpm)
  - [Trust Domain](#trust-domain)
  - [Unlock Provider](#unlock-provider)
  - [UUID](#uuid)
  - [Vault](#vault)
  - [Wrapped Key](#wrapped-key)
  - [Zero-Trust](#zero-trust)

## AAD

Additional Authenticated Data.

Metadata associated with encrypted content that is authenticated but not encrypted.

Example:

- service name
- account name
- version metadata

If modified, decryption/authentication fails.

---

## ADR

Architecture Decision Record.

A document capturing an important architectural decision, the reasoning behind it, the alternatives considered, and the consequences of the decision.

ADRs are intended to preserve architectural intent over time and prevent accidental redesign caused by loss of historical context.

Examples:

- runtime session handling
- IPC authority boundaries
- synchronization semantics
- metadata exposure tradeoffs

---

## AEAD

Authenticated Encryption with Associated Data.

A modern encryption approach that provides both:

- confidentiality (keeps data unreadable)
- integrity/authentication (detects tampering)

Secrets Kit plans to use AEAD encryption modes such as XChaCha20-Poly1305 for encrypted secret storage.

---

## Append-Oriented Storage

A storage model where changes create new immutable revisions rather than destructively overwriting previous data.

Secrets Kit uses append-oriented revision semantics to improve:

- auditability
- synchronization consistency
- rollback capability
- forensic reconstruction
- distributed reconciliation

---

## Argon2id

A modern password hashing and key derivation algorithm designed to resist brute-force attacks and GPU cracking.

Used to derive encryption keys from passphrases.

Secrets Kit uses Argon2id for legacy passphrase-based vaults.

---

## Authority

The ability of a peer, operator, process, or synchronization participant to perform authenticated actions within the system.

Authority is intentionally separated from transport visibility or network location.

Examples:

- synchronization authority
- datastore authority
- runtime authority
- recovery authority

---

## Backend

The storage implementation used by Secrets Kit.

Examples:

- macOS Keychain backend
- SQLite encrypted backend

The backend controls where encrypted secret data is stored.

---

## BackendStore

The internal persistence abstraction responsible for managing encrypted datastore state, revisions, metadata, and synchronization lineage independently from runtime access mechanisms or IPC transport layers.

BackendStore is authoritative persistent state.

---

## Bundle

An encrypted export package containing secret data intended for one or more peer hosts.

Bundles may later support:

- encrypted replication
- peer synchronization
- disaster recovery

---

## CA (Certificate Authority)

A centralized system that issues and validates certificates.

Secrets Kit intentionally avoids requiring a traditional CA and instead uses explicit peer trust similar to SSH.

---

## Ciphertext

Encrypted data.

Ciphertext is unreadable without the correct decryption key.

---

## CLI

Command Line Interface.

The `seckit` executable and associated commands.

Example:

```bash
seckit run my-command
```

---

## Conflict Lineage

The historical chain of revisions associated with an object.

Conflict lineage permits peers to determine:

- synchronization ancestry
- concurrent modification
- stale updates
- reconciliation ordering

---

## Conflict Resolution

The process of determining what happens when two hosts modify the same secret independently.

Initial Secrets Kit rules are intentionally simple:

- newer timestamp wins
- otherwise conflict is reported

---

## CRUD

Create, Read, Update, Delete.

Basic operations supported by a storage backend.

---

## Datastore Identity

The persistent globally unique identity assigned to a datastore instance.

Datastore identity is independent from:

- hostname
- IP address
- container identity
- infrastructure location

This permits datastore migration and synchronization continuity without destabilizing trust relationships.

---

## DEK

Data Encryption Key.

The symmetric encryption key used to encrypt and decrypt secret values stored in the database.

Important:

- the DEK encrypts the actual secrets
- the DEK itself is protected by an unlock provider
- the DEK is not the same as a peer identity key

---

## DPAPI

Data Protection API.

Windows-native encryption and credential protection system.

Potential future unlock provider for Windows systems.

---

## Ed25519

A modern public/private key cryptography algorithm commonly used for:

- SSH keys
- signing
- peer identity

Secrets Kit plans to use Ed25519-style keys for host identity and peer trust.

---

## Encryption at Rest

Data stored in encrypted form while sitting on disk.

Secrets Kit aims to ensure secret values remain encrypted at rest at all times.

---

## Encryption in Transit

Data encrypted while being transferred between systems.

Secrets Kit peer replication bundles are intended to remain encrypted in transit.

---

## Eventual Consistency

A distributed systems property where independently operating peers may temporarily diverge but will converge toward consistent state once synchronization resumes.

Secrets Kit favors eventual consistency over centralized synchronization locking.

---

## Host Identity

A cryptographic identity assigned to a host/machine.

Used for:

- peer trust
- signing bundles
- encrypted synchronization

Not used directly as the local datastore encryption key.

---

## Integrity Metadata

Cryptographic validation information associated with stored objects or revisions.

Integrity metadata is used to detect:

- corruption
- tampering
- replay substitution
- synchronization inconsistency
- unauthorized modification

---

## IPC

Inter-process communication on a **single host** (and, under [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md), same-user transports). Future **user-scoped** `seckitd` is **transport / plumbing only** — **not** the authority over `BackendStore`.

Normative docs: [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md), [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md).

---

## KDF

Key Derivation Function.

A process that derives cryptographic keys from passwords or other input material.

Example:

- Argon2id

---

## KEK

Key Encryption Key.

A key used to encrypt or unwrap another key.

In Secrets Kit:

- the DEK encrypts secrets
- the KEK/unlock provider protects the DEK

Examples of KEK sources:

- Keychain
- passphrase
- TPM
- DPAPI

---

## Keychain

Apple's encrypted credential storage system on macOS.

Currently used by Secrets Kit as:

- a secret backend
- and later as a possible unlock provider

---

## LaunchAgent

A macOS per-user background service managed by `launchd`.

Runs while a user session is active.

---

## launchd

The macOS service manager responsible for:

- background jobs
- daemons
- scheduled processes
- agents

Similar to `systemd` on Linux.

---

## LaunchDaemon

A macOS system-wide background service managed by `launchd`.

Can run before user login.

---

## libsodium

A modern cryptographic library focused on safe defaults and simplicity.

PyNaCl is the Python binding commonly used to access libsodium functionality.

---

## Lineage

The historical relationship between datastore revisions, object revisions, synchronization events, or audit transitions.

Lineage permits deterministic reconstruction of state evolution over time.

---

## Local Authority

Authority granted within the scope of a single datastore instance or local runtime environment.

Local authority does not automatically imply distributed synchronization authority.

---

## Local-first

A design philosophy where:

- data primarily lives locally
- cloud infrastructure is optional
- systems continue functioning independently

Secrets Kit is intentionally local-first.

---

## Metadata

Structured information describing secrets or vaults.

Examples:

- timestamps
- origin host
- domains/groups
- version information

---

## Nonce

A unique random value used during encryption.

Prevents repeated encryptions from producing identical ciphertext.

---

## Object Identity

The stable globally unique identity associated with a stored object independent from logical naming conventions.

Object identity remains stable even if:

- secret names change
- tags change
- metadata changes
- infrastructure changes

---

## P2P (Peer-to-Peer)

A distributed model where hosts communicate directly rather than relying on centralized infrastructure.

---

## Peer

A trusted host participating in encrypted replication.

Peers exchange public keys and can securely send encrypted bundles to each other.

---

## Peer Authority

The synchronization permissions granted to a peer within a distributed trust network.

Examples may include:

- read-only synchronization
- replication authority
- synchronization initiation
- administrative distribution authority

---

## Peer Trust

An explicit trust relationship between hosts.

Secrets Kit follows an SSH-style trust model:

- exchange public keys
- trust intentionally
- no centralized authority required

---

## Plaintext

Readable, unencrypted data.

Secrets Kit attempts to minimize plaintext exposure.

---

## Proxy / Relay

An intermediate system that helps pass encrypted data between hosts.

In the future, relay systems may assist with:

- NAT traversal
- offline delivery
- asynchronous communication

Relays are not intended to decrypt or inspect payloads.

---

## Public/Private Key Pair

A cryptographic identity consisting of:

- public key (shared)
- private key (secret)

Public keys encrypt or verify.

Private keys decrypt or sign.

---

## Relay

A transport component responsible only for forwarding encrypted synchronization payloads between peers.

A relay is intentionally non-authoritative and must never possess plaintext secret material.

---

## Relay (optional future)

A hypothetical **`relayd`**-class component **forwards opaque encrypted payloads only** — **never** decrypts; **minimal ephemeral** metadata; **not** a trust authority or inventory. Prefer **direct peer** when reachable; relay for NAT / async / disconnected timing when specified. See [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) appendix.

---

## Revision

An immutable representation of a specific object state at a specific point in time.

Modifications create new revisions rather than overwriting prior revisions.

---

## Revision Lineage

The ordered historical relationship between revisions of an object.

Revision lineage permits:

- deterministic synchronization
- rollback
- conflict detection
- forensic reconstruction
- audit validation

---

## Runtime Injection

Supplying secrets directly to a running process at execution time rather than storing them in plaintext files.

Example:

```bash
seckit run my-command
```

---

## Secret Store

The underlying storage location for encrypted secrets.

Examples:

- Keychain
- encrypted SQLite database

---

## Secure Enclave

Apple hardware-assisted cryptographic protection system.

Potential future unlock provider integration.

---

## Service Group

A logical grouping of peers, services, synchronization domains, or operational infrastructure participating in shared trust or synchronization relationships.

---

## SQLite

A lightweight embedded SQL database stored in a single file.

Chosen for portability and simplicity.

---

## Synchronization

Replicating encrypted secret data between trusted peers.

Initial synchronization is planned to be:

- manual
- explicit
- deterministic

---

## Synchronization Authority

The ability of a peer to distribute, validate, reconcile, or approve datastore revisions within a trusted synchronization network.

Synchronization authority may differ between peers depending on deployment policy.

---

## systemd

A service manager and initialization system commonly used on Linux systems.

systemd manages:

- background services,
- timers,
- service supervision,
- socket activation,
- logging,
- and system startup orchestration.

Secrets Kit may support user-scoped or system-scoped services managed through systemd depending on deployment requirements.

systemd service behavior is conceptually similar to macOS `launchd`, although implementation details differ substantially.

---

## Tombstone

A special revision indicating that an object has entered a deleted state.

Tombstones prevent stale peers from unintentionally recreating deleted objects during later synchronization reconciliation.

---

## TPM

Trusted Platform Module.

A hardware security component available on many systems.

Potential future unlock provider for Linux and Windows.

---

## Trust Domain

A logical boundary defining which peers, operators, synchronization participants, or services are permitted to participate in shared trust relationships.

Trust domains may represent:

- environments
- organizations
- service groups
- deployment regions
- operational boundaries

---

## Unlock Provider

A component responsible for unlocking or unwrapping the DEK used by the encrypted datastore.

Examples:

- passphrase provider
- Keychain provider
- DPAPI provider
- TPM provider

Unlock providers are separate from storage backends.

---

## UUID

Universally Unique Identifier.

A randomly generated identifier intended to remain globally unique.

Secrets Kit uses UUIDs for:

- datastore identity
- object identity
- peer identity references
- synchronization lineage

UUIDs intentionally avoid dependence on hostnames or infrastructure naming conventions.

---

## Vault

An encrypted datastore containing protected secrets and metadata.

In Secrets Kit, the SQLite encrypted backend effectively becomes a local vault.

---

## Wrapped Key

An encrypted cryptographic key.

Example:

- DEK encrypted by a KEK/unlock provider

This allows the actual datastore encryption key to remain protected.

---

## Zero-Trust

A security philosophy in which no process, peer, network path, relay, or infrastructure component is implicitly trusted.

Trust relationships must instead be:

- explicit
- verifiable
- attributable
- revocable
- continuously validated

Secrets Kit follows a zero-trust operational model.

---
