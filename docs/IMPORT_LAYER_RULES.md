# Import layer rules (Phase 1)

**Created**: 2026-05-09  
**Updated**: 2026-05-09

After the package restructure, dependencies should follow these directions:

## Allowed

- `cli` → `sync`, `runtime`, `backends`, `registry`, `identity`, `models`, `utils`, `recovery`, top-level `importers`, etc.
- `sync` → `models`, `backends`, `registry`, `identity`, `utils`, `importers`
- `backends` → `models` (and internal backend cross-imports)
- `registry` → `models`

## Forbidden (do not add new edges)

- `models` → `cli` or `sync`
- `backends` → `cli`
- `registry` → `cli`

## Documented exception (pre-existing, Phase 1)

- **`sync` → `cli`**: `sync/merge.py` lazily imports `_read_metadata` from `secrets_kit.cli.main` inside `apply_peer_sync_import`, matching pre-refactor behavior. This is **technical debt**; remove when a small shared service/helper module is extracted (no new `sync` → `cli` imports).

## Static import analysis note

A simple AST pass over `src/secrets_kit` may report **cycles** that are broken at runtime by **lazy imports** (for example `cli.parser.base` importing `cli.main` inside `build_parser`, `sync.merge` importing `_read_metadata` inside `apply_peer_sync_import`, `backends.base.resolve_backend_store` importing concrete backends inside the function). This matches the pre-refactor design; do not fix by adding new top-level imports without an ADR.

## Validation

Regenerate a dependency overview with standard tooling (for example `pydeps` or `importlab` on `src/secrets_kit`) after large edits. Confirm no **new** import cycles vs the prior flat layout.
