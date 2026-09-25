# Concepts — Secrets Kit CLI

**Created**: 2026-05-07  
**Updated**: 2026-06-07

This page is the short mental model for operators.

- [Concepts — Secrets Kit CLI](#concepts--secrets-kit-cli)
  - [Operator mental model](#operator-mental-model)
  - [Resolve vs materialize](#resolve-vs-materialize)
  - [Safe defaults (summary)](#safe-defaults-summary)
  - [Command compatibility (summary)](#command-compatibility-summary)
  - [Automation](#automation)
  - [RSS terminology](#rss-terminology)
  - [Glossary pointer](#glossary-pointer)

## Operator mental model

| Command                    | Think of it as                                                                                                                                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list`                     | **Inventory** — what seckit knows about, redacted by default                                                                                                                                                              |
| `explain`                  | **Inspect** — one entry’s resolved metadata (secret not materialized by default)                                                                                                                                          |
| `get`                      | **Retrieve** — redacted unless you opt into **`--raw`**                                                                                                                                                                   |
| `export`                   | **Exported materialization** — bulk plaintext or an **externalized artifact** (short- or long-lived, depending on how you handle output)                                                                                  |
| `run`                      | **Inject** — use canonical wording: *Injection is a runtime-scoped materialization path that transfers plaintext into another execution context.* Environment variables may propagate via inheritance unless constrained. |
| `status`                   | **Operational health** — daemon-provided identity, endpoint, peer, route, and synchronization state; it does not read SQLite directly                                                        |
| `doctor` / `info`          | **Diagnostics** — backend posture, defaults, and environment status                                                                                                                                                       |
| `envelope` / `transaction` | **Inspection** — read-only views of persisted delivery artifacts and transaction history                                                                                                                                  |

## Resolve vs materialize

| Term                       | Meaning                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Resolve**                | Obtain **authoritative** entry data **inside** the tool (metadata + secret bytes if the operation requires them).                                                               |
| **Materialize** (verb)     | **Expose** secret **plaintext** outside **protected authority handling** (terminal output, env injection, export files, child runtime, etc.). Local-only exposure still counts. |
| **Materialization** (noun) | Any path that moves plaintext out of protected handling. Use **materialize** as the verb and **materialization** as the noun in prose.                                          |
| **Materialize vs persist** | Materialization does **not** imply persistence. **Exported** paths create an **externalized artifact**, which may be transient or persistent depending on transport/storage.    |

Exposure labels such as index-only, resolved-within-handling, materialized, injected, and exported are descriptive operator vocabulary, not formal security tiers.

**Implicit guard:** helpers, `repr`, log formatters, and tracebacks must not **implicitly** surface plaintext off explicit materialization paths.

**Examples:**

- `explain` → resolve without materializing the secret into normal output.
- `get --raw` → resolve + materialize to stdout.
- `export` / `run` → materialize for runtime (explicit flags / command choice).

## Safe defaults (summary)

Defaults favor **redaction**, **least materialization**, and **narrow scope**. **`--raw`**, **`--all`**, and **export** are elevated disclosure. Avoid **implicit bulk** work when scope is ambiguous; prefer explicit **`--all`** and confirmations for destructive multi-entry actions.

## Command compatibility (summary)

Canonical command names are listed in help and reference docs. Advanced and internal commands are labeled as such.

## Automation

Prefer **`--json`** and structured fields over parsing tables or help text.

## RSS terminology

The terms below describe transport-assistance architecture. The daemon is a transport adapter: UDS/control availability, the configured libp2p transport substrate, connection management, opaque payload routing, transport retry, endpoint discovery hooks, and basic routing metadata. Runtime modules own protocol, crypto, SQLite, transaction, and authorization responsibilities; transport qualification remains separate from protocol authority.

| Term                                    | Meaning                                                                                                                                                                                                                        |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **RSS**                                 | **Remote Secret Sync**: optional transport-assistance infrastructure supporting peer-authoritative synchronization between mutually reachable peers or peers using operator-selected remote synchronization assistance.        |
| **Remote Secret Sync**                  | The preferred public term for RSS node / transport-assistance behavior. It is not a new authority model and does not change bundle, envelope, reconciliation, or schema semantics.                                             |
| **Mutually reachable peers**            | Peers that can exchange synchronization artifacts or envelopes through an operator-controlled direct path without RSS infrastructure.                                                                                          |
| **Indirectly reachable peers**          | Peers that cannot currently exchange synchronization traffic directly, but can both reach optional RSS transport-assistance infrastructure.                                                                                    |
| **Transport-assistance infrastructure** | Optional future infrastructure that may receive, forward, retry within explicit bounds, or route opaque synchronization envelopes without becoming datastore, merge, reconciliation, identity, decryption, or queue authority. |

## Glossary pointer

Use this page, [CLI_REFERENCE.md](CLI_REFERENCE.md), and [WORKFLOWS.md](WORKFLOWS.md) as the current operator glossary.
