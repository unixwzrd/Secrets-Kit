# Operations status

**Created**: 2026-05-05  
**Updated**: 2026-05-14  

Operator-facing snapshot: **what is safe to rely on in production-like environments** vs **what still needs a human validation pass**. Evidence detail lives in [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md)—keep that matrix updated when you change any row here.

## Environment assumptions

| Requirement | Notes |
|-------------|--------|
| **macOS** | Full Keychain backend (`secure`), `security` CLI, disposable-keychain tests, typical `seckitd` UDS. |
| **Linux / other Unix** | SQLite backend and tests that skip Keychain; **`AF_UNIX` required** for `seckitd` tests. |
| **Python 3.9+** with deps | `pip install -e .` per [QUICKSTART.md](QUICKSTART.md); PyYAML required for CLI. |
| **PyNaCl** | Peer/crypto paths; some tests skip if missing. |
| **Non-sandboxed runs** | Full `unittest` + Keychain + UDS bind often **fail** in restricted sandboxes (PermissionError on socket bind / keychain create). Run validation on a normal developer machine or CI macOS runner. |
| **CI** | [`scripts/run_local_validation.sh`](../scripts/run_local_validation.sh) → compile + full discover; see [docs/README.md](README.md) Testing section. |

## Blockers (known)

- **None recorded in-tree** as of **2026-05-05**. File issues here when an operational run fails with repro + version/SHA.

## Required infrastructure

- **Local:** repo checkout or installed wheel, writable `HOME` for `~/.config/seckit` / `registry.json` defaults.  
- **Keychain ops:** GUI login session helps when tests need default login keychain.  
- **Disposable keychain:** follow [CROSS_HOST_CHECKLIST.md](CROSS_HOST_CHECKLIST.md).  
- **Distributed:** multiple hosts or VMs per [DISTRIBUTED_VALIDATION_STATUS.md](DISTRIBUTED_VALIDATION_STATUS.md).

## Maintainer smoke (subprocess, local dev)

Recorded **2026-05-05** on a full-permission shell (not CI sandbox):

| Command | Exit | Notes |
|---------|------|--------|
| `PYTHONPATH=src python -m secrets_kit.cli.main --help` | 0 | Top of help shows `seckit` usage |
| `PYTHONPATH=src python -m secrets_kit.cli.main version` | 0 | Printed `1.2.5` (project version from distribution / env) |

This does **not** replace backend or persistence checks; update [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md) when you promote evidence columns.

## SQLite operational gate (subprocess + DB inspection)

**Target layout (repo root):**

- [`scripts/integration/smoke_sqlite.sh`](../scripts/integration/smoke_sqlite.sh) — CRUD, `doctor`, `rebuild-index`, `recover --dry-run --json`, `sqlite3` integrity/journal/WAL info, `strings` must not find the **stored secret literal**.
- [`scripts/integration/smoke_sqlite_restart.sh`](../scripts/integration/smoke_sqlite_restart.sh) — write in one environment, read after `env -i` (or new login shell), then rebuild/recover + integrity.
- [`scripts/integration/smoke_run.sh`](../scripts/integration/smoke_run.sh) — `seckit run` success path, failing child exit code, missing `--names`.
- [`scripts/integration/smoke_full_local_runtime.sh`](../scripts/integration/smoke_full_local_runtime.sh) — runs the three above in order; `set -e`, stop on first failure.

**Status:** scripts are **in-tree**. Maintainer run **2026-05-14** (full-permission shell, conda `python3.12` with PyYAML + PyNaCl, `sqlite3` on `PATH`): **`bash scripts/integration/smoke_full_local_runtime.sh`** exit **0**; per-stage **`smoke_sqlite`**, **`smoke_sqlite_restart`**, **`smoke_run`** printed **OK**. Observed DB: tables **`secrets`**, **`vault_meta`**; **`pragma integrity_check`** ok; **`journal_mode`** **delete**; smoke secret substring **absent** from **`strings`** on the DB file. Re-run after meaningful SQLite/CLI changes and record host + SHA here.

```bash
cd /path/to/secrets-kit
export PYTHON=/path/to/venv-or-conda/bin/python   # if default python lacks PyNaCl
bash scripts/integration/smoke_full_local_runtime.sh
```

Evidence columns in [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md) are updated from these runs—not from unit tests alone.

## CLI workflow status

Use: **works** / **partial** / **broken** / **untested (ops)**. Fill **Last verified** when you personally run the check.

| Command / flow | Status | Exit / `--json` | Registry / disk | Persistence (new process) | Matrix row / evidence |
|----------------|--------|-----------------|-----------------|---------------------------|----------------------|
| `seckit --help` | partial | help text | none | n/a | Maintainer smoke 2026-05-05; subprocess exit 0 |
| `seckit -v` / `--version` | partial | 0 | none | n/a | Root parser |
| `seckit version` | partial | 0 observed | none | n/a | Maintainer smoke 2026-05-05 |
| `seckit set` | partial | 0 on success | updates registry + backend | **verify** same home | RTM: set Keychain/SQLite |
| `seckit get` | partial | 0 / `--raw` materialization | read | n/a | RTM: get |
| `seckit list` | partial | table / `--json` if offered | read | n/a | RTM: list |
| `seckit delete` | partial | — | registry + backend | subprocess smoke 2026-05-14 | `smoke_sqlite.sh` |
| `seckit run` | partial | child exit code propagates (`os.execvpe`) | inject | subprocess smoke 2026-05-14 | `smoke_run.sh` |
| `seckit export` | partial | macOS disposable KC scripts | optional artifact | n/a | CROSS_HOST_CHECKLIST |
| `seckit import` (subcommands) | partial | — | registry + backend | — | import tests + scripts |
| `seckit recover` | partial | `--dry-run` / `--json` | registry scan from backend | subprocess smoke 2026-05-14 | `smoke_sqlite.sh` |
| `seckit migrate recover-registry` | same as recover | alias | same | same | [CLI_REFERENCE.md](CLI_REFERENCE.md) |
| `seckit rebuild-index` | partial | — | index from authority | subprocess smoke 2026-05-14 | `smoke_sqlite.sh` |
| `seckit doctor` | partial | environment-dependent | may suggest repairs | subprocess smoke 2026-05-14 | `smoke_sqlite.sh` |

**How to verify persistence:** same `HOME`, new terminal, repeat `get` / `list`; compare `registry.json` mtime and contents (no secret values in registry—see [METADATA_REGISTRY.md](METADATA_REGISTRY.md)).

## SQLite backend (operational checks)

| Check | Status | How to verify |
|-------|--------|---------------|
| DB creation / schema | partial | **`smoke_sqlite.sh`:** `.tables`, `PRAGMA table_info(secrets)` (verified 2026-05-14) |
| Encrypted payload storage | partial | **`strings "$DB"`** must not contain injected smoke secret literal |
| Decrypt / retrieve | partial | **`smoke_sqlite.sh`:** `get --raw` |
| `rebuild-index` / recovery | partial | **`smoke_sqlite.sh` / `smoke_sqlite_restart.sh`** |
| Corrupt DB | partial | unit tests; ops repro ad hoc |
| Concurrency | unknown | Document assumptions (single writer); no strong multi-process writer guarantee unless measured |

## Keychain backend (operational checks)

| Check | Status | How to verify |
|-------|--------|---------------|
| create / unlock | partial | `make_temp_keychain` tests; manual `security` |
| CRUD | partial | disposable-keychain flow tests |
| lock / timeout | partial | `SECKIT_RUN_LOCKED_KEYCHAIN_TESTS` optional |
| CLI `--keychain` | partial | CROSS_HOST_CHECKLIST |

## Registry / index

| Check | Status | Notes |
|-------|--------|-------|
| `registry.json` generation | partial | Normal CLI paths |
| Slim v2 index | documented | [METADATA_REGISTRY.md](METADATA_REGISTRY.md) |
| Stale / missing registry | partial | `recover` / doctor |
| Authority vs registry | documented | Registry is **not** authoritative for secrets |

## Local daemon (`seckitd`)

| Check | Status | Notes |
|-------|--------|-------|
| In-process `serve_forever` + IPC | works (tests) | `test_seckitd_phase5a.py`, `test_seckitd_phase5d.py` |
| Subprocess `seckit daemon serve` + `ping` | partial | `test_seckit_daemon_subprocess_integration.py` when `AF_UNIX` + permissions OK |
| Malformed payload | partial | mocked + some framing tests |
| Restart / leftover socket | untested (ops) | Add repro here when validated |

## Distributed / multi-host

See [DISTRIBUTED_VALIDATION_STATUS.md](DISTRIBUTED_VALIDATION_STATUS.md)—single-host rows above do **not** imply peer correctness across machines.
