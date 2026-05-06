# Secrets Kit Glossary of Terms

- [Secrets Kit Glossary of Terms](#secrets-kit-glossary-of-terms)
  - [AEAD](#aead)
  - [AAD](#aad)
  - [Argon2id](#argon2id)
  - [Backend](#backend)
  - [Bundle](#bundle)
  - [CA (Certificate Authority)](#ca-certificate-authority)
  - [Ciphertext](#ciphertext)
  - [CLI](#cli)
  - [Conflict Resolution](#conflict-resolution)
  - [CRUD](#crud)
  - [DEK](#dek)
  - [DPAPI](#dpapi)
  - [Ed25519](#ed25519)
  - [Encryption at Rest](#encryption-at-rest)
  - [Encryption in Transit](#encryption-in-transit)
  - [Host Identity](#host-identity)
  - [IPC](#ipc)
  - [KEK](#kek)
  - [Keychain](#keychain)
  - [KDF](#kdf)
  - [LaunchAgent](#launchagent)
  - [LaunchDaemon](#launchdaemon)
  - [launchd](#launchd)
  - [libsodium](#libsodium)
  - [Local-first](#local-first)
  - [Metadata](#metadata)
  - [Nonce](#nonce)
  - [Peer](#peer)
  - [Peer Trust](#peer-trust)
  - [Plaintext](#plaintext)
  - [P2P (Peer-to-Peer)](#p2p-peer-to-peer)
  - [Proxy / Relay](#proxy--relay)
  - [Public/Private Key Pair](#publicprivate-key-pair)
  - [Runtime Injection](#runtime-injection)
  - [Secret Store](#secret-store)
  - [Secure Enclave](#secure-enclave)
  - [SQLite](#sqlite)
  - [Synchronization](#synchronization)
  - [TPM](#tpm)
  - [Unlock Provider](#unlock-provider)
  - [Vault](#vault)
  - [Wrapped Key](#wrapped-key)

## AEAD

Authenticated Encryption with Associated Data.

A modern encryption approach that provides both:

- confidentiality (keeps data unreadable)
- integrity/authentication (detects tampering)

Secrets Kit plans to use AEAD encryption modes such as XChaCha20-Poly1305 for encrypted secret storage.

---

## AAD

Additional Authenticated Data.

Metadata associated with encrypted content that is authenticated but not encrypted.

Example:

- service name
- account name
- version metadata

If modified, decryption/authentication fails.

---

## Argon2id

A modern password hashing and key derivation algorithm designed to resist brute-force attacks and GPU cracking.

Used to derive encryption keys from passphrases.

Secrets Kit uses Argon2id for legacy passphrase-based vaults.

---

## Backend

The storage implementation used by Secrets Kit.

Examples:

- macOS Keychain backend
- SQLite encrypted backend

The backend controls where encrypted secret data is stored.

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

## Host Identity

A cryptographic identity assigned to a host/machine.

Used for:

- peer trust
- signing bundles
- encrypted synchronization

Not used directly as the local datastore encryption key.

---

## IPC

Inter-Process Communication.

Mechanism for communication between local processes.

Potential future use:

- CLI notifying `seckitd`
- local daemon communication

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

## KDF

Key Derivation Function.

A process that derives cryptographic keys from passwords or other input material.

Example:

- Argon2id

---

## LaunchAgent

A macOS per-user background service managed by `launchd`.

Runs while a user session is active.

---

## LaunchDaemon

A macOS system-wide background service managed by `launchd`.

Can run before user login.

---

## launchd

The macOS service manager responsible for:

- background jobs
- daemons
- scheduled processes
- agents

Similar to `systemd` on Linux.

---

## libsodium

A modern cryptographic library focused on safe defaults and simplicity.

PyNaCl is the Python binding commonly used to access libsodium functionality.

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

## Peer

A trusted host participating in encrypted replication.

Peers exchange public keys and can securely send encrypted bundles to each other.

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

## P2P (Peer-to-Peer)

A distributed model where hosts communicate directly rather than relying on centralized infrastructure.

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

## TPM

Trusted Platform Module.

A hardware security component available on many systems.

Potential future unlock provider for Linux and Windows.

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

## Vault

An encrypted datastore containing protected secrets and metadata.

In Secrets Kit, the SQLite encrypted backend effectively becomes a local vault.

---

## Wrapped Key

An encrypted cryptographic key.

Example:

- DEK encrypted by a KEK/unlock provider

This allows the actual datastore encryption key to remain protected.