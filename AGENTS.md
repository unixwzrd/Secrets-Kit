# AGENTS.md — Secrets-Kit

**Created**: 2026-05-02  
**Updated**: 2026-05-09

## Git and release management discipline

This repository contains security-sensitive tooling and distributed-sync infrastructure. Public repository state must remain intentionally curated and operationally trustworthy.

### Local development vs public history

- Local commits, temporary branches, experimental implementations, and checkpoint snapshots are normal during development.
- The public repository history is **not** a scratchpad and must not become a stream of partially-working experiments.

### Push restrictions

- Agents must **never** run:
  - `git push`
  - force-push operations
  - branch deletion on remotes
  - tag publication
  - release publication
  - PR creation implying readiness

unless the maintainer explicitly requests that action.

- Agents may create local commits when useful for checkpointing or rollback safety, but should prefer logically grouped commits rather than noisy micro-commits.

### Main branch expectations

The `main` branch should remain:

- reasonably stable,
- testable,
- installable,
- operationally coherent.

Do not merge or publish work that:

- knowingly breaks tests,
- leaves the repository non-runnable,
- introduces incomplete schema migrations,
- partially implements security-sensitive behavior,
- changes authority boundaries without validation,
- leaves docs materially misleading relative to shipped behavior.

### Public release expectations

Before public push/tag/release:

- tests should pass in the intended environment,
- CLI smoke tests should succeed,
- daemon startup/status paths should work,
- install/bootstrap flows should be validated,
- documentation should reflect actual shipped behavior,
- version references should be consistent,
- future/planning docs should not be mistaken for shipped functionality.

### Commit hygiene

Prefer commits that are:

- logically grouped,
- reversible,
- understandable from history,
- scoped to a coherent change.

Avoid mixing:

- schema work,
- transport work,
- docs rewrites,
- runtime refactors,
- formatting-only changes

into one large commit unless explicitly performing a coordinated migration.

### Generated and temporary artifacts

Do not commit:

- temporary reports,
- generated scratch outputs,
- local runtime databases,
- transient debug artifacts,
- temporary diagrams,
- experimental exports,
- plaintext debug datastore contents.

Generated architecture graphs or analysis outputs should live under:

- `docs/dev/`
- `tmp/`
- or another explicitly non-runtime location,

not under `src/` unless intentionally shipped.

### Planning documents

`docs/plans/` contains working engineering and architectural planning material.

These documents:

- may describe future or partially implemented systems,
- are not necessarily release commitments,
- should not be treated as proof that functionality already ships.

Avoid modifying planning documents in ways that obscure:

- implementation status,
- operational limitations,
- authority boundaries,
- or non-goals.

## Documentation and document-control rules

- **Never future-date documents.**
  - Use ISO-8601 date format: `YYYY-MM-DD`.
  - Preserve chronological consistency across:
    - changelogs,
    - release notes,
    - migration docs,
    - ADRs,
    - and planning documents.
  - `Created:` and `Updated:` headers must reflect the actual local/current date at generation time.
  - Do not guess future dates.
  - If uncertain, prefer leaving the prior date unchanged rather than inventing one.
- Preserve original `Created:` dates whenever editing an existing document.
- Only update `Updated:` when substantive content changes occur.
- Planning documents under `docs/plans/` are working engineering artifacts, not release promises; avoid language that implies unimplemented features are shipped.

## Coding style and implementation rules

- Prefer small, composable modules and functions.
- Prefer explicit data models over implicit dictionaries where practical.
- Use type hints on new or substantially modified functions.
- Prefer dataclasses, TypedDict, or Pydantic models for structured state.
- Document public functions and non-obvious internal functions:
  - purpose,
  - inputs,
  - outputs,
  - side effects,
  - authority/security considerations where relevant.
- Avoid deep inheritance hierarchies or plugin ecosystems unless explicitly requested.
- Avoid introducing framework/server abstractions prematurely.
- Keep transport, datastore, reconciliation, IPC, and authority layers clearly separated.
- Prefer deterministic/state-machine-oriented behavior over hidden background behavior.
- Keep daemon/runtime logic bounded and inspectable.
- Avoid hidden retries, unbounded queues, or silent recovery loops.

## SQLite and datastore guidance

SQLite is the authoritative distributed-sync backend.

Prefer:

- transactional correctness,
- explicit schema evolution,
- replay-safe operations,
- deterministic reconciliation,
- auditability,
- integrity metadata,
- tombstones/history tables,
- rebuild/recovery tooling.

Where practical, prefer SQLite-enforced invariants:

- triggers,
- constraints,
- foreign keys,
- transactional updates,
- integrity checks.

Avoid pushing reconciliation correctness entirely into daemon or CLI business logic when SQLite can enforce it safely and transparently.

Keep active tables optimized for operational lookup.

Prefer separate/history/tombstone tables for:

- deleted rows,
- prior revisions,
- replay history,
- audit lineage,
- corruption/recovery analysis.

## Keychain backend guidance

macOS Keychain support is primarily:

- local-machine storage,
- operator convenience,
- local runtime integration.

Do not force distributed reconciliation semantics onto Keychain unless explicitly implementing sidecar metadata/index support.

Distributed-sync semantics should be designed SQLite-first.

## Error handling and operational behavior

This project is intended to support:

- automation,
- DevOps,
- MLOps,
- CI/CD,
- orchestration,
- recovery tooling.

Therefore:

- Avoid prose-only failures.
- Prefer stable machine-readable error structures.
- Prefer structured JSON output for daemon/runtime operations.
- Keep stdout machine-readable where appropriate.
- Human-readable diagnostics belong primarily on stderr.

### Exit codes

Prefer standard POSIX/sysexits-style exit semantics where practical instead of inventing arbitrary return codes.

Examples:

```text
0    success
1    generic failure
2    misuse of shell/CLI
64   command usage error
65   invalid input data
66   missing input/file
69   service unavailable
70   internal software error
73   cannot create output/resource
74   I/O error
77   insufficient permissions
78   configuration error
```

Map distributed/runtime conditions onto the closest meaningful standard code before inventing new conventions.

If custom codes are required:

- document them centrally,
- keep them stable,
- expose machine-readable error identifiers alongside human text.

### Error structure

Where practical, structured errors should contain:

- stable error code/id,
- human-readable summary,
- operation name,
- retryability classification,
- optional diagnostic context,
- no secret/plaintext leakage.

Example shape:

```json
{
  "ok": false,
  "error": {
    "code": "peer_unreachable",
    "exit_code": 69,
    "retryable": true,
    "message": "peer transport unavailable"
  }
}
```

## Security and materialization discipline

Never:

- log plaintext secrets,
- log decrypted payloads,
- log sensitive environment material,
- emit encrypted payload bodies unnecessarily,
- expand relay visibility beyond approved metadata boundaries.

The relay/sync-host remains:

- opaque,
- non-authoritative,
- non-reconciling,
- non-decrypting by default.

## Distributed-system design constraints

The following concerns must remain separated:

- transport,
- IPC,
- datastore,
- reconciliation,
- authority,
- runtime coordination.

Do not allow:

- relay delivery order,
- daemon timing,
- queue behavior,
- or transport reconnect semantics

to become the source of distributed truth.

Distributed truth belongs to:

- datastore lineage,
- revision identity,
- tombstones,
- replay-safe reconciliation,
- peer-authoritative merge semantics.

## Environment

- Use the **same Python environment** for development, tests, and tooling as in the IDE (**Command Palette → Python: Select Interpreter**), e.g. Conda **`venvutil`**.
- Some setups wrap **`conda`** and **`pip`** in shell functions (e.g. via `do_wrapper`) to log installs/uninstalls and other venv-changing commands. Prefer a shell where those hooks run when changing dependencies; one-off automation should still target the same interpreter (e.g. `conda run -n venvutil …`) so it matches the selected environment.

## Scope

- Prefer changes that stay aligned with [docs/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md](docs/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md) and [CHANGELOG.md](CHANGELOG.md).
- macOS **launchd** and login-keychain checks remain partly manual; see [docs/LAUNCHD_VALIDATION.md](docs/LAUNCHD_VALIDATION.md).

## Tests

From the repo root, with the project env active:

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
```

(or `conda run -n venvutil python -m unittest discover -s tests -q` when hooks are non-interactive.)
