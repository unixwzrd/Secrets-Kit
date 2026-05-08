# CLI architecture — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-05-05

How the `seckit` CLI relates to **registry**, **backends**, **safe index**, **authority**, and **materialization**. This is operator-facing architecture, not Python module layout. Parser code is split into `cli_parser.py`, `cli_help.py`, and `cli_groups.py`; handlers remain in `cli.py`. Normative terms: [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Authority vs slim index

- **Authority** — Secret payload and rich metadata as stored in the backend (Keychain item + comment JSON, or SQLite ciphertext + row metadata), resolved via backend APIs.
- **Registry** (`registry.json`) — **Slim, non-secret** index (locator, `entry_id`, timestamps, optional peer hints). Not a full duplicate of authority. See [METADATA_REGISTRY.md](METADATA_REGISTRY.md).
- **Registry journal** — Optional append-only log; **not authoritative** for resolving current metadata.

Canonical semantics: [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md).

## `backend-index`

- **Purpose:** Operator-facing **diagnostic** stream over **`BackendStore.iter_index()`**: decrypt-free **where the backend supports** a safe index.
- **Not** authoritative metadata (authority lives in the store / resolve path).
- **Not** a **materialization** path (no secret plaintext in output).

## `list` semantics (capability-driven)

`list` is **inventory**, not “ dump everything cheaply” by definition.

- It uses **safe enumeration paths** appropriate to **backend capabilities** and available **index / registry** data.
- **Selective authority resolve** happens **only when needed** (e.g. filters such as type, kind, tag, stale) and when the backend supports it (`supports_selective_resolve`).
- **Do not treat today’s implementation as the normative long-term contract** for prose or tests—wording tracks **policy and capabilities**, not frozen implementation detail (same maturity applies elsewhere).

## Safe output policy

- Inventory-oriented commands default to **redaction** and **minimal disclosure**.
- **`get --raw`**, **`export`**, and **`run`** are **materialization** paths and must be explicit.
- **`explain`** resolves **without** materializing the secret into normal stdout.

## Future daemons / machine APIs

No background daemon ships in this repo today. If a future `seckit` API or daemon appears, it **must reuse** the ADR meanings of **resolve**, **materialize**, **inject**, and **exported** — extending transport only, not redefining those terms. Prefer **local-first** authority; **no implicit remote trust** for secret material. Placeholder **lease**, **policy**, and **audit** stories remain **out of scope** until specified. See [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

## Future command hierarchy

If commands are regrouped (e.g. `seckit backend unlock`):

- Preserve **scripting compatibility** where possible.
- Keep **aliases** during migration windows.
- Avoid casual renames of **high-frequency** operator commands.

Shared argparse helpers **must not** force **identical semantics** across commands where behavior differs—see [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md).

## Related docs

- [CONCEPTS.md](CONCEPTS.md) — mental model and resolve vs materialize  
- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) — protected authority handling and crossings  
- [CLI_REFERENCE.md](CLI_REFERENCE.md) — per-command reference  
- [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) — help wording, JSON stability, errors  
