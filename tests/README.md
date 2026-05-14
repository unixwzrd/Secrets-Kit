# Tests layout and vocabulary notes

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

## Parser and CLI

- `src/secrets_kit/cli/parser/base.py` orchestrates family modules: `family_secrets.py`, `family_diagnostics.py`, `family_sync_peer.py` (migrate/identity/peer/reconcile/sync), and `daemon.py`. **Do not reorder** `add_*` calls without checking `seckit --help` and the introspection test below.
- `tests/test_parser_handler_bindings.py` — every leaf subcommand registered by `build_parser()` must bind `func` (argparse `set_defaults`).
- `tests/test_cli_strings_en.py` — `en.STRINGS` entries are non-empty; stubs share `en.STRINGS`.

## Local runtime vs hosted-relay tests

- **Local peer / `seckitd`**: prefer `tests/test_seckitd_phase5*.py`, `tests/test_seckit_daemon_subprocess_integration.py` (CLI subprocess: `daemon serve` + `daemon ping`), `tests/test_runtime_session.py`, and related harnesses. These assert **same-user** IPC and optional loopback coordination—not a hosted multi-tenant control plane.
- **Relay / sync-host / managed-infrastructure** semantics: keep **mocked** or documented as future private-repo concerns; avoid naming that implies `seckitd` is hosted relay **product** code.

When adding tests, tag confusing cases with short comments referencing `docs/ARCHITECTURE_RUNTIME_SURFACE.md` or `docs/IPC_SEMANTICS_ADR.md` Phase C.
