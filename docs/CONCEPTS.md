# Concepts — Secrets Kit CLI

**Created**: 2026-05-07  
**Updated**: 2026-05-05

This page is the short mental model for operators. Deeper backend semantics live in [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md) and [METADATA_REGISTRY.md](METADATA_REGISTRY.md). Runtime vocabulary (**resolve**, **materialize**, **inject**, **exported**): [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Operator mental model

| Command | Think of it as |
|---------|------------------|
| `list` | **Inventory** — what seckit knows about, redacted by default |
| `explain` | **Inspect** — one entry’s resolved metadata (secret not materialized by default) |
| `get` | **Retrieve** — redacted unless you opt into **`--raw`** |
| `export` | **Exported materialization** — bulk plaintext or an **externalized artifact** (short- or long-lived, depending on how you handle output) |
| `run` | **Inject** — use canonical wording: *Injection is a runtime-scoped materialization path that transfers plaintext into another execution context.* Environment variables may propagate via inheritance unless constrained. |
| `recover` | **Rebuild** slim registry / index state from the live store when needed |
| `backend-index` | **Diagnostics** — decrypt-safe view of the store index, not secrets |

## Resolve vs materialize

| Term | Meaning |
|------|--------|
| **Resolve** | Obtain **authoritative** entry data **inside** the tool (metadata + secret bytes if the operation requires them). |
| **Materialize** (verb) | **Expose** secret **plaintext** outside **protected authority handling** (terminal output, env injection, export files, child runtime, etc.). Local-only exposure still counts. |
| **Materialization** (noun) | Any path that moves plaintext out of protected handling. Use **materialize** as the verb and **materialization** as the noun in prose. |
| **Materialize vs persist** | Materialization does **not** imply persistence. **Exported** paths create an **externalized artifact**, which may be transient or persistent depending on transport/storage. |

**Exposure levels** (index-only, resolved-within-handling, materialized, injected, exported) in the ADR are **descriptive** operational labels — not formal security tiers without a separate policy framework.

**Implicit guard:** helpers, `repr`, log formatters, and tracebacks must not **implicitly** surface plaintext off explicit materialization paths.

**Examples:**

- `explain` → resolve without materializing the secret into normal output.
- `get --raw` → resolve + materialize to stdout.
- `export` / `run` → materialize for runtime (explicit flags / command choice).

## Safe defaults (summary)

Defaults favor **redaction**, **least materialization**, and **narrow scope**. **`--raw`**, **`--all`**, and **export** are elevated disclosure. Avoid **implicit bulk** work when scope is ambiguous—prefer explicit **`--all`** and confirmations for destructive multi-entry actions. Details: [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md), [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md).

## Command compatibility (summary)

Canonical command names are listed first in help and reference docs. **Compatibility aliases** (e.g. `defaults` for `config`, `migrate recover-registry` for `recover`) remain **script-safe** until explicitly deprecated. **Advanced / internal** commands are labeled as such. Full policy: [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Automation

Prefer **`--json`** and structured fields over parsing tables or help text. See [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) (JSON output stability).

## Glossary pointer

Extended term list: [Secrets-Kit-Glossary-of-Terms.md](Secrets-Kit-Glossary-of-Terms.md).
