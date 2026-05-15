# Tests layout and vocabulary notes

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

## Makefile (quick reference)

From the repo root:

- `make` or `make help` — **index of all targets**, how to combine groups, `unittest` / `pytest-args` escapes, and environment notes.
- **`make test`** — full suite, **loud** (pytest **`-v -rs`**, each case + skip summary). Needs **`pip install -e ".[test]"`**. On **macOS** outside **`CI`**, launchd jobs run when **`gui/<uid>`** exists.
- **`make test-quiet`** / **`make test-ci`** — full suite, **quiet** (pytest **`-q`**; exit code for CI; traceback only on failure).
- **`make test-unittest`** — same scope via **`unittest discover`** (no pytest).
- `make test-parallel` — **`pytest -n 8`** by default (`pip install -e ".[test]"`).
- `make test-groups` — runs each **group** in order (same modules as a full run when taken together; fails fast on the first broken group).

Exact module lists are the `TEST_*` variables at the top of `Makefile`; do not duplicate them here—**add new `tests/test_*.py` files to the right `TEST_*` block** when you introduce tests.

| Make target | Area |
|-------------|------|
| `test` | Full suite, **loud** pytest (`-v -rs`) |
| `test-quiet` / `test-ci` | Full suite, **quiet** pytest (`-q`) |
| `test-unittest` | Full **`unittest discover`** (`-v`) |
| `test-sqlite` | `test_sqlite_*` modules |
| `test-contract` | `test_backend_store_contract`, `test_backend_resolution` |
| `test-backends` | **contract + all sqlite** (one invocation) |
| `test-cli` | CLI, parser bindings, native helper, package version |
| `test-daemon` | `seckitd` 5a/5b/5d, daemon subprocess, runtime IPC/session/log, launchd |
| `test-sync` | Sync merge/bundle, peers, peer sync dry-run/e2e, relay boundaries |
| `test-registry` | Registry permissions, slim, v2 |
| `test-models` | Models, identity, schemas, authority invariants, enrollment |
| `test-keychain` | Keychain backend/inventory/real/disposable, CLI Keychain E2E |
| `test-keychain-live` | macOS: pytest Keychain modules only (`-n 0`; same as auto in **`make test`** on console) |
| `test-launchd-live` | macOS: pytest launchd module only (`-n 0`) |
| `test-reconciliation` | `tests/reconciliation/` package only |
| `test-operational-live` | macOS opt-in: Keychain + launchd live pytest slice |

Custom slices:

- `make unittest ARGS="tests.test_foo tests.test_bar -v"`
- `make pytest-args ARGS="tests/test_sqlite_*.py -n 4 --tb=short"` (needs `.[test]` for xdist)

## Platform skips

- **`tests/platform_guards.py`** — macOS-only tests skip with **`skipped: macOS only`** on Linux CI.
- **`test_configure_unix_ipc_socket_on_af_unix`** — open `AF_UNIX`, platform `setsockopt`, bind (CLI ↔ `seckitd` transport; not Keychain, not peer auth).

## Parser and CLI

- `src/secrets_kit/cli/parser/base.py` orchestrates family modules: `family_secrets.py`, `family_diagnostics.py`, `family_sync_peer.py` (migrate/identity/peer/reconcile/sync), and `daemon.py`. **Do not reorder** `add_*` calls without checking `seckit --help` and the introspection test below.
- `tests/test_parser_handler_bindings.py` — every leaf subcommand registered by `build_parser()` must bind `func` (argparse `set_defaults`).
- `tests/test_cli_strings_en.py` — `en.STRINGS` entries are non-empty; stubs share `en.STRINGS`.

## Local runtime vs hosted-relay tests

- **Local peer / `seckitd`**: prefer `tests/test_seckitd_phase5*.py`, `tests/test_seckit_daemon_subprocess_integration.py` (CLI subprocess: `daemon serve` + `daemon ping`), `tests/test_runtime_session.py`, and related harnesses. These assert **same-user** IPC and optional loopback coordination—not a hosted multi-tenant control plane.
- **Relay / sync-host / managed-infrastructure** semantics: keep **mocked** or documented as future private-repo concerns; avoid naming that implies `seckitd` is hosted relay **product** code.

When adding tests, tag confusing cases with short comments referencing `docs/ARCHITECTURE_RUNTIME_SURFACE.md` or `docs/IPC_SEMANTICS_ADR.md` Phase C.

## macOS Keychain integration (opt-in)

Live `security` CLI tests (`test_keychain_backend_store`, `test_seckit_cli_keychain_e2e`) are **skipped by default** so CI sandboxes and Linux runners stay fast. On a Mac developer machine:

**Make (recommended — env vars only apply to that command):**

```bash
make test-keychain-live          # SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 + pytest -n 0
make test-launchd-live          # SECKIT_RUN_LAUNCHD_TESTS=1 + pytest -n 0
make test-operational-live      # both flags + pytest Keychain + launchd modules
```

No-password temp keychains use `security create-keychain -p ''` / `unlock-keychain -p ''` so **recent macOS does not prompt** interactively (avoids pytest hanging on password prompts).

Manual:

```bash
# Live Keychain/launchd tests auto-run on macOS when logged in at the GUI (`launchctl print gui/$UID`).
# Opt-out: SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=0 (or LAUNCHD_* / LOCKED_* equivalents).
PYTHONPATH=src python3 -m unittest tests.test_keychain_backend_store tests.test_seckit_cli_keychain_e2e -v
```

Or use the operational wrapper (macOS only; requires `security` on `PATH`; writes reports under `test-reports/run_keychain_integration/`):

```bash
./test-scripts/run_keychain_integration.sh
```

Ensure `seckit` is on `PATH` for the E2E module (or set `SECKIT_BIN`).
