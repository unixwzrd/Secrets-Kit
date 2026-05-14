# Docstring contract (contributors)

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

Short reference for **S3.5** (post–Phase C). Prefer **contracts** in docstrings; **design philosophy** belongs in ADRs.

## What to document

- **Public functions** and **CLI handlers** (`cmd_*`): **Args**, **Returns**, **Raises** where non-obvious; note **defaults** (“if omitted …”).
- **Env-driven behavior**: one line naming `SECKIT_*` / `SECKITD_*` and point to the canonical env table in security/CLI docs—do not duplicate long prose.
- **Failure semantics**: raise vs `None` vs CLI exit; side effects (writes paths, IPC).
- **Runtime context**: library vs CLI vs daemon—one clause; link `docs/IPC_SEMANTICS_ADR.md` when IPC assumptions matter.

## Non-goals

- Long narrative “why we built it this way” in every module—link an ADR or architecture doc instead.
- Restating obvious `argparse` behavior unless a flag interaction is surprising.

## Parser modules

Family builders (`cli/parser/family_*.py`, `daemon.py`) should document **registration order invariants** when moved out of `base.py` so `seckit --help` stays stable across refactors.
