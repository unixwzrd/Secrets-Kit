# Contributor instructions — Secrets Kit

This is the client product: CLI, same-user daemon, local storage, encrypted peer synchronization, client-side RSS enrollment and read-only MCP. Hosted services, billing authority, deployment automation, private qualification evidence and release planning do not belong in this repository.

## Scope and safety

- Inspect current code and tests before changing behavior. Preserve unrelated edits.
- Prefer small, reversible changes with explicit data flow; do not introduce speculative frameworks or abstractions.
- Keep datastore, transport, IPC, authorization and runtime coordination separate. Transport delivery order must not define datastore truth.
- Never log plaintext secrets, decrypted payloads, sensitive environment values or private keys.
- Keep MCP fail-closed and preserve same-user access boundaries.
- Stop for maintainer review before authority, cryptographic, datastore, replay or transport semantic changes; compatibility-surface removal; destructive cleanup; or broad restructuring.
- Do not push, publish tags/releases, delete remote branches or create readiness-implying pull requests without explicit maintainer approval.

## Implementation

- Preserve CLI and machine-readable output contracts. Use stable error identifiers and bounded execution.
- Keep human-facing CLI text in the existing locale dictionaries; keep protocol and JSON field names stable and unlocalized.
- Document touched modules and public entry points with purpose, inputs, outputs, side effects and relevant security boundaries. Include module names in module docstrings and type hints where practical.
- Prefer direct imports, explicit wiring and keyword arguments. Do not embed Python in shell scripts.
- Preserve transactional integrity, identity, tombstones and replay protections. Do not simplify correctness checks merely to reduce line counts.
- Verify runtime, CLI and test references before removing code. Record deferred findings rather than broadening the change silently.

## Validation

Use the configured project Python environment consistently. The Makefile is the canonical test orchestration surface; inspect `make help` and run the narrowest relevant `make test-*` target first.

- `make test-fast`: fast client regression checks.
- `make test-uninstall`: installer, uninstall and managed-service checks.
- `make test-mcp`: MCP contract checks.
- `make test`: full serial suite; macOS live integrations may run in an interactive GUI session.

Do not change environments, install dependencies or run live service tests silently. For boundary changes, retain reference searches and package-content checks in addition to unit tests. A source test pass does not qualify a built release or installed system.

## Documentation and handoff

- Keep customer documentation factual; distinguish implemented, planned and qualified behavior.
- Update customer-facing changelog entries when behavior materially changes.
- Where an authoritative documentation source is supplied by the maintainer, edit it first and synchronize only approved public derivatives.
- Keep Markdown paragraphs and list items on single physical lines; do not hard-wrap prose.
- Exclude generated build copies, caches, local databases, secret exports, private reports and host inventories from publication inputs.
- Report changed files, tests and failures, invariant checks and remaining limitations. Never imply release readiness from partial qualification.
