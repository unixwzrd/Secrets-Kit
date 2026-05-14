# Architecture: runtime, registry, and transport surfaces

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

This document classifies selected modules for **maintainers** (post–Phase C remediation). Taxonomy labels:

| Label | Meaning |
|-------|---------|
| **Production contract** | Wire or operator behavior depends on it; changes need tests + changelog. |
| **Compatibility layer** | Shims or re-exports preserving older import paths. |
| **Documentary surface** | Aligns docs/tests with ADRs; not a runtime wire codec. |
| **Future placeholder** | Reserved namespace until a chartered IPC/schema effort lands. |
| **Runtime abstraction** | Protocol/ABC describing local runtime shape; not a product API. |
| **Test seam** | Supports tests or drift guards; may look “unused” in prod-only graphs. |
| **Experimental surface** | Helpers for tests or alternate formats; not the default prod path. |

## Classified modules

| Module | Primary label | Disposition | Rationale |
|--------|---------------|-------------|-----------|
| `secrets_kit.version_meta` | Production contract | **Retain** | Single version authority; explicit unknown sentinel. |
| `secrets_kit.cli.strings` (`en`, `es`, `it`) | Production contract | **Retain** | Each locale exposes ``STRINGS: dict[str, str]`` (all argparse ``help`` / ``description`` / ``epilog`` operator prose). Use ``STRINGS["KEY"]``. **Not** for JSON keys. No loader/gettext.
| `secrets_kit.runtime.authority` | Documentary + test seam | **Retain** | Drift guard (`backend_interface_exposure_complete`); do not use as `BackendStore` return types. |
| `secrets_kit.runtime.ipc` | Documentary / future placeholder | **Retain** | ADR-aligned labels; not `seckitd` wire opcodes. |
| `secrets_kit.schemas.runtime` | Future placeholder | **Retain** stub | No Pydantic wire until IPC schema ADR; avoid “fake” schemas. |
| `secrets_kit.registry.core` (slim index v2) | Production contract | **Retain** | On-disk `registry.json` authority for index rows. |
| `secrets_kit.registry.v2` | Experimental surface | **Retain** | Alternate v2 **experiment** types; **not** the same as “slim index v2” naming in `registry.core`—see glossary risk in docs. |
| `secrets_kit.sync.envelope` | Production contract | **Retain** | Phase 4 transport message helpers (peer routing hints); distinct from bundle v1. |
| `secrets_kit.seckitd` package | Production contract (local peer runtime) | **Retain** | Same-user Unix IPC + optional coordinator; **not** “hosted relay” by default—see `AGENTS.md` and `IPC_SEMANTICS_ADR.md` Phase C. |
| `secrets_kit.identity.enrollment` | Production contract + test seam | **Retain** | Builds public enrollment payloads for peer wiring; wire keys remain stable (`relay_endpoints` alias per Phase B policy)—see `CHANGELOG.md` 2026-05-14. |
| `secrets_kit.schemas.base` | Production contract | **Retain** | Shared Pydantic/schema helpers; high fan-in—treat as contract surface. |
| `secrets_kit.schemas.backend` | Production contract | **Retain** | Backend capability and validation mirrors; do not delete on vulture/pyflakes alone. |
| `secrets_kit.schemas.enrollment` | Production contract | **Retain** | Enrollment payload schema mirror; aligns with `identity.enrollment` builder. |
| `secrets_kit.schemas.envelope` | Production contract | **Retain** | Envelope validation alongside `sync.envelope` transport helpers. |
| `secrets_kit.schemas.index` | Production contract + test seam | **Retain** | Index-row validation helpers for registry/index contracts. |
| `secrets_kit.schemas.sync_bundle` | Production contract | **Retain** | Bundle v1 validation surface; changes affect peer sync tests and wire stability. |
| `secrets_kit.cli.parser.family_*` / `daemon` | Production contract | **Retain** | Argparse wiring only; **registration order** must match historical `seckit --help`; use `tests/test_parser_handler_bindings.py` when editing. |

## Terminology: local vs hosted

- **Local peer runtime** (`seckitd`): same-user daemon, IPC, optional `OutboundRuntimeCoordinator`.
- **Hosted / managed relay** (product): out of public repo per `AGENTS.md`; plans may use “sync host” vocabulary for **opaque** forwarding only.

Do not conflate **local** `seckitd` with **hosted** relay infrastructure when naming tests or docs.
