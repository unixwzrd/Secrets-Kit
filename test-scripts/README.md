# test-scripts — operational runners

**Created**: 2026-05-05  
**Updated**: 2026-05-05

Shell entry points for **runtime** validation: subprocess smokes, optional Keychain/launchd gates, and wrapped **unittest** discovery. They are **not** install/release/bootstrap scripts (those stay under [`scripts/`](../scripts/)).

Reports are written under **`test-reports/<run-name>/<timestamp>/`** at the repo root. That tree is **gitignored**; each run creates fresh artifacts.

## What every run produces

For each top-level runner that calls `report_init` (via [`runtime_report.sh`](runtime_report.sh)):

| Artifact | Contents |
|----------|----------|
| `environment.txt` | Sorted `env`, repo root, initial cwd |
| `commands.log` | Optional `log_cmd` lines (timestamp + quoted argv) |
| `stdout.log` | Live copy of stdout (`tee`) |
| `stderr.log` | Live copy of stderr (`tee`) |
| `summary.txt` | Start metadata + final **PASS/FAIL** and exit code |
| `test-results.txt` | One-line final status (JUnit XML deferred) |

Nested subprocess runners (for example `smoke_full_local_runtime.sh` calling each smoke) emit **their own** report directories under `test-reports/`.

## Python: unit vs integration vs everything

| Script | Purpose |
|--------|---------|
| [`run_unit_tests.sh`](run_unit_tests.sh) | **`python -m unittest discover -s tests -v`** with `PYTHONPATH=src`. Same broad coverage as maintainer CI; some tests skip on Linux or without optional env. Set **`SECKIT_UNITTEST_QUIET=1`** for **`-q`** instead of **`-v`**. **`PYTHON`** selects the interpreter (default: `python3`). |
| [`run_integration_tests.sh`](run_integration_tests.sh) | SQLite **operational** gate only: runs [`smoke_full_local_runtime.sh`](smoke_full_local_runtime.sh) (three smokes: `smoke_sqlite`, `smoke_sqlite_restart`, `smoke_run`). Uses temp `HOME`, **`seckit` on PATH** or `python -m secrets_kit.cli.main`, and **`sqlite3`**. |
| [`run_all_tests.sh`](run_all_tests.sh) | Runs **`run_unit_tests.sh`** then **`run_integration_tests.sh`**; stops on first failure. |

**Makefile (optional):** from repo root,

```bash
make -C test-scripts unit
make -C test-scripts integration
make -C test-scripts all
```

## SQLite operational smokes (components of integration)

| Script | Role |
|--------|------|
| [`smoke_sqlite.sh`](smoke_sqlite.sh) | SQLite CRUD, `doctor`, `rebuild-index`, `recover --dry-run --json`, DB + `strings` checks |
| [`smoke_sqlite_restart.sh`](smoke_sqlite_restart.sh) | Persistence across subprocesses / `env -i` |
| [`smoke_run.sh`](smoke_run.sh) | `seckit run`: inject, child exit code, missing `--names`, stderr must not leak secrets |
| [`smoke_full_local_runtime.sh`](smoke_full_local_runtime.sh) | Runs the three above in order |

## macOS-only / opt-in gates

| Script | Role |
|--------|------|
| [`run_keychain_integration.sh`](run_keychain_integration.sh) | Sets **`SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1`** and runs **`tests.test_keychain_backend_store`** + **`tests.test_seckit_cli_keychain_e2e`**. Requires **Darwin** + **`security`**. Not part of **`run_all_tests.sh`**. |
| [`seckit_launchd_smoke.sh`](seckit_launchd_smoke.sh) | LaunchAgent/Daemon smoke vs Keychain; operator-owned. Agent simulator stays **[`scripts/seckit_launchd_agent_simulator.py`](../scripts/seckit_launchd_agent_simulator.py)**. See [docs/LAUNCHD_VALIDATION.md](../docs/LAUNCHD_VALIDATION.md). |

## Shared helper (do not run directly)

[`runtime_report.sh`](runtime_report.sh) — sourced by runners; defines `report_init`, `log_cmd`, `finalize_summary`, and `tee` redirects.

## Maintainer CI bundle

Full compile + unittest + optional localhost transport (not replaced by this directory) remains **[`scripts/run_local_validation.sh`](../scripts/run_local_validation.sh)**.
