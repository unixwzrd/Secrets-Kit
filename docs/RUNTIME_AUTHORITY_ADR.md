# ADR: Runtime authority and materialization model

**Created**: 2026-05-05  
**Updated**: 2026-05-08

Normative vocabulary for **protected authority handling**, **materialization**, **injection**, and **export** surfaces in Secrets Kit. This phase is **semantic, documentary, and invariant-oriented** only: no daemon, IPC transport, resident caches, or lease enforcement.

## Related documents

- [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md) — index vs authority, safe rows  
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — operator-facing security posture  
- [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) — local runtime session, ownership, same-host authority, caching bias
- [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) — local IPC and peer-side `seckitd` semantics
- [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) — CLI mapping to these terms  

## Terminology: protected authority handling

Prefer **protected authority handling** for the in-process layer where:

- authority payloads are **resolved**;
- unlock paths may **materialize DEKs or key material** (e.g. SQLite `materialize_master_key`-style naming) — distinct from **secret plaintext** crossing to operators;
- plaintext may **exist transiently in memory** before explicit **materialization**, **injection**, or **exported** artifact creation.

**Legacy synonym:** “runtime authority boundary” → prefer **protected authority handling** when daemon or API consumers exist later.

## Resolved-within-handling

**Resolved data may contain plaintext in memory while still inside protected authority handling.** Resolution is **not** the same as “metadata only”: `resolve_by_*` and `ResolvedEntry` may hold full authority (including secret bytes) without **materialization** until plaintext **crosses** to operators, child processes, filesystems, IPC consumers, or external runtimes.

Disambiguation: **`materialize_master_key`** (or similar) refers to **cryptographic key material** for the store, not automatically to **disclosing secret plaintext** to the operator.

## Core operations

### Resolve

Authoritative work **inside** protected handling. By itself it **does not** disclose plaintext **outside** that layer. See **Resolved-within-handling** above.

### Materialize (directional)

**Materialization** occurs when plaintext **leaves protected authority handling** and becomes accessible to any of:

- operators (terminal, API response to user);
- child processes (including via **injection**);
- filesystems;
- IPC consumers (future local, same-user transports — see [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md));
- external runtimes.

**Same-user local IPC** that delivers **secret plaintext** to another process is a **materialization** to that **IPC consumer**, governed by this ADR and [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md).

Local-only exposure is still materialization.

### Materialize vs persistence

| Idea | Meaning |
|------|--------|
| Materialization | Plaintext becomes available outside protected handling (any channel above). |
| Persistence | Plaintext or ciphertext **remains stored** on disk or in an artifact beyond the immediate operation. |

**Materialization alone does not imply persistence.** Examples:

- **Transient:** stdout; injection into a child environment; future IPC delivery; clipboard (if ever supported).
- **Persistent / exported:** plaintext export files; encrypted bundle **artifacts**; recovery **artifacts**.

**Exported exposure** intentionally creates an **externalized artifact**, which may be **transient or persistent** depending on transport and storage semantics.

### Inject (canonical wording)

Use this sentence consistently in ADR, CLI help, and docs:

> **Injection** is a **runtime-scoped materialization path** that **transfers plaintext into another execution context**.

**Environment inheritance:** Injection into child execution contexts may **further propagate** through **environment inheritance** unless explicitly constrained by the caller or runtime.

`seckit run` is the primary injection command today.

### Exported

**Exported** patterns are materialization paths that produce an **externalized artifact** (file, bundle, or similar). The artifact may be short-lived or long-lived; “exported” describes the **crossing** and **artifact creation**, not a specific TTL.

## Exposure levels (descriptive only)

These labels are **operational vocabulary** for reasoning about crossings. They are **not** formal security classifications, compliance tiers, or policy levels unless a separate framework says so.

| Level (conceptual) | Typical meaning |
|---------------------|-----------------|
| Index-only / safe index | Decrypt-free rows (e.g. `iter_index`); no secret plaintext. |
| Resolved-within-handling | Authority in memory inside the tool; not yet crossed. |
| Materialized | Plaintext crossed to an operator-visible or process-visible channel. |
| Injected | Materialization via **injection** into another execution context. |
| Exported | Materialization into an **externalized artifact** (transient or persistent). |

## Implicit materialization guard

**No helper, formatter, serializer, `repr`/`str` for secrets, debug utility, or convenience accessor may implicitly surface plaintext outside explicit materialization paths.** Treat logging, tracebacks, and “pretty” formatters as high-risk unless proven redacted. Invariants: no plaintext secrets on **stdout** or **stderr** except documented materialization commands (see below).

## Stdout / stderr invariant (CLI)

No command **except explicit materialization paths** may emit **plaintext secrets** to **stdout** or **stderr**.

**Explicit materialization paths** (today) include: `get --raw`, `export` outputs, and **injection** side effects in the **child** environment (parent stdout/stderr must not carry the injected secret needlessly). Tests lock non-materialization commands first.

**Exempt:** platform-conditional help strings; dynamically generated capability blobs without secret payloads.

## `RuntimeAccessResult` and `RuntimeLease` (non-contract)

- **`RuntimeAccessResult`** (if present in code) is **informational / documentary only**. It **must not** redefine `BackendStore`, imply IPC, caching, or lease semantics, or become a stable daemon API **in this phase**. **`ResolvedEntry`** and existing resolve APIs stay unchanged; store methods **must not** return `RuntimeAccessResult`.
- **`RuntimeLease`** is a **placeholder** only (optional fields, no validation). This phase does **not** define lease enforcement, revocation, runtime expiration, policy engines, audit pipelines, or stable lease APIs.

## Anti-daemon / anti-expansion guard (non-goals)

This phase **does not** add:

- Daemon bootstrap, socket listeners, polling threads, resident caches, runtime agents, singleton helper processes, lock-managed background helpers;
- IPC or “runtime fetch” APIs;
- Policy engines, remote trust, MFA, revocation, or audit pipelines tied to leases.

Semantics and invariants **only** — not `seckitd`, REST/gRPC, or remote fetch.

## Future consumers (API / daemon)

Future daemons or APIs **must reuse** this vocabulary: **resolve**, **materialize**, **inject**, and **exported** meanings **must not** be redefined by new layers. New work may extend **plumbing** (transport, scheduling) only.

Session, ownership, and IPC boundaries are specified in [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) and [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md). Local runtime implementations should **emerge from** those ADRs rather than redefine them retroactively.

Future endpoints **must** remain **local-first** by default: **no implicit remote trust** for authority. Placeholder **lease**, **policy**, and **audit** stories stay **out of scope** until specified elsewhere.

## Initial invariants (summary)

1. Safe index paths (`iter_index`, `IndexRow.to_safe_dict`) do not carry secret plaintext.  
2. Default operator output stays redacted unless a documented materialization flag/command is used.  
3. Helpers and reprs must not smuggle secrets into logs or tracebacks (see **Implicit materialization guard**).  
4. Exposure-level labels are descriptive, not certifications.  
