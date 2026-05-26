# Import layer rules

**Created**: 2026-05-09  
**Updated**: 2026-05-19

After the package restructure (Phase 1) and CLI extraction (Phase 2), dependencies should follow these directions:

## Allowed

- `cli` → `sync`, `runtime`, `backends`, `registry`, `identity`, `models`, `utils`, `schemas`, `recovery`, top-level `importers`, `seckitd`, etc.
- `cli.parser` → `cli.commands`, `cli.support`, `backends`, `models` (explicit handler imports; **no** `cli.main` for parser wiring).
- `sync` → `models`, `backends`, `registry` (including `registry.resolve`), `identity`, `utils`, `importers`, `schemas`
- `sync.envelope` — pure dict helpers only; **no** CLI, no network I/O.
- `identity.enrollment` — public enrollment dict builders; **no** `schemas` imports (identity stays emitter-side).
- `backends` → `models` (and internal backend cross-imports)
- `registry` → `models`, `backends` (e.g. `registry.resolve` orchestrates store metadata reads)
- **``seckitd``** → `schemas` (inbound wrapper validation), stdlib + subprocess only — **must not import** `secrets_kit.cli` (invoke the operator entrypoint via argv only).
- `schemas` → `models` (helpers/normalizers only — mirror Pydantic types; **not** canonical runtime types). Phase 4 adds `schemas/enrollment.py` and `schemas/envelope.py` (Pydantic mirrors only; **no** `model_dump()` emitters in production paths).

## Forbidden (do not add new edges)

- `models` → `cli` or `sync` or `schemas`
- `backends` → `cli`
- `registry` (core index helpers) → `cli`
- **`registry.resolve`** → `cli` — shared metadata resolution must stay free of CLI/presentation.
- **`sync`** → `cli` — use `registry.resolve` (or other domain modules) instead.
- **`schemas`** → `cli` — keep boundary validation out of CLI package; CLI may import `schemas` only if a future refactor explicitly documents it (Phase 3: avoid).

## Shared metadata resolution

- **`registry/resolve.py`** owns **`read_metadata`**, **`resolve_status`**, and **`merge_import_metadata`**. CLI commands use **`cli/metadata_build.py`** for argparse-specific construction. Tests patch/import `registry.resolve`—not `cli.main`.

## Static import analysis note

A simple AST pass over `src/secrets_kit` may report **cycles** that are broken at runtime by **lazy imports** inside functions (for example `backends.base.resolve_backend_store` importing concrete backends inside the function). Prefer explicit top-level imports in new code unless an ADR documents a lazy edge.

## Allowed import-boundary exceptions (Phase 4)

Intentional transitional or runtime edges — guards must **not** treat these as violations:

| Edge | Status | Reason |
|------|--------|--------|
| `sqlite/legacy_payload.py` → `comment_codec` | **Allowed** | Migration-only compatibility path |
| `sqlite/recovery.py` → `sqlite.store` | **Allowed** | Lazy import cycle break |
| `models/core.py` → `comment_codec` (lazy) | **Allowed transitional shim** | External API compatibility |
| `sync/merge.py` → `to_keychain_comment` | **Deferred** | Dedicated sync pass — do not remove in Phase 4 |

**Default:** `backends/sqlite/*.py` (except `legacy_payload.py`) must not reference `comment_codec`; use `compat/keychain_projection`.

## Validation

- **`tests/test_import_layer_guards.py`** — `backends/sqlite/*.py` must not import `backends.keychain`; `backends/keychain/*.py` must not import `backends.sqlite`.
- **`tests/test_backend_boundaries.py`** — backend modules stay isolated; CLI metadata build stays free of subprocess/keychain store code.
- Optional: regenerate a dependency overview with standard tooling (for example `pydeps` on `src/secrets_kit`) after large edits.
