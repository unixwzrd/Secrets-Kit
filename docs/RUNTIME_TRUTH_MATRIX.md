# Runtime truth matrix

**Created**: 2026-05-05  
**Updated**: 2026-05-14  

**Source of truth** for *how we know* a capability works in real environments—not merely that unit tests pass. Refresh this document after each validation tranche.

**Legend (evidence columns):** use one primary cell per row (the *strongest* evidence you have actually run). Supporting layers may appear in **Notes**.

- **mocked** — behavior exercised only with mocks / fakes.
- **in-process** — real code, same process (e.g. `args.func` after `build_parser()`, or `serve_forever` in a thread).
- **subprocess** — `python -m secrets_kit.cli.main …` or installed `seckit` / `seckitd`, separate OS process.
- **multi-host** — peers on distinct machines/VMs with observed network or manual transport as designed.
- **unknown** — not yet validated at runtime; **do not** upgrade to a stronger column based on unit tests alone.

**Boundaries:** **CLI** = `seckit` client; **LOCALD** = `seckitd` / `seckit daemon`; **RELAY** = future `secrets-kit-relay` (not shipped from this repo).

## Feature / capability matrix

| Capability | Boundary | Evidence | Notes |
|------------|----------|----------|--------|
| Root `--help`, subcommand help | CLI | in-process + subprocess | Parser/help snapshots in tests; subprocess: `python -m secrets_kit.cli.main --help` (**verified 2026-05-05** dev shell). |
| `version` / `-v` | CLI | in-process + subprocess | Subprocess: `python -m secrets_kit.cli.main version` exit 0 (**2026-05-05**). |
| `set` / `get` / `list` / `delete` (Keychain) | CLI | in-process + subprocess (macOS) | Disposable-keychain subprocess flow in `tests/test_disposable_keychain_flow.py`; full suite needs macOS + `security`. |
| `set` / `get` / `list` / `delete` (SQLite encrypted) | CLI | in-process | **Target ops gate:** [`scripts/integration/smoke_sqlite.sh`](../scripts/integration/smoke_sqlite.sh) (subprocess CLI + `sqlite3` + `strings` on DB). **Do not** mark subprocess/datastore-inspected here until that script has been added and run successfully on a real host. |
| SQLite persistence / new process / `env -i` | CLI | unknown | **Target:** [`scripts/integration/smoke_sqlite_restart.sh`](../scripts/integration/smoke_sqlite_restart.sh). |
| `seckit run` (inject + exit codes) | CLI | in-process | **Target:** [`scripts/integration/smoke_run.sh`](../scripts/integration/smoke_run.sh). |
| Full local SQLite runtime gate (sequential smokes) | CLI | unknown | **Target:** [`scripts/integration/smoke_full_local_runtime.sh`](../scripts/integration/smoke_full_local_runtime.sh). |
| `export` / `import` | CLI | in-process + subprocess (macOS) | Cross-host scripts + disposable keychain tests. |
| `recover` / `migrate recover-registry` | CLI | in-process | Covered in SQLite smoke target (`recover --dry-run --json` + subprocess); promote when script lands and passes. |
| `rebuild-index` | CLI | in-process | Same: SQLite smoke target after CRUD. |
| `doctor` | CLI | in-process | Same: SQLite smoke target on temp `HOME`. |
| `daemon serve` (Unix socket) | LOCALD | in-process | `serve_forever` + thread in `tests/test_seckitd_phase5a.py`. |
| `daemon serve` via `seckit` subprocess | LOCALD | subprocess | `tests/test_seckit_daemon_subprocess_integration.py` (entrypoint + argv + real UDS). |
| `daemon ping` / `status` / `sync-status` / `submit-outbound` | LOCALD | in-process + subprocess | Client IPC tests in-process; CLI subprocess exercises `cmd_daemon_*`. |
| IPC malformed / oversized frames | LOCALD | mocked + in-process | Mix of `test_relay_operational_boundaries.py` (mocked handlers) and framing tests; full **subprocess** fuzzing not exhaustive. |
| Daemon restart / stale socket | LOCALD | unknown → partial | Needs explicit operational scenario (kill -9, leftover `.sock`); document in [OPERATIONS_STATUS.md](OPERATIONS_STATUS.md) when run. |
| Peer identity / enrollment / sync bundle | CLI + LOCALD | in-process + multi-host (partial) | SQLite e2e: `tests/test_peer_sync_e2e_sqlite.py`. **Multi-host** = see [DISTRIBUTED_VALIDATION_STATUS.md](DISTRIBUTED_VALIDATION_STATUS.md). |
| Reconcile / verify | CLI | in-process | Operational fixtures in `tests/reconciliation/`; multi-host **unknown** until distributed doc filled. |
| Opaque relay / forwarder | RELAY | N/A (future repo) | No runtime in this repo; boundaries in [RELAY_SEPARATION_STATUS.md](RELAY_SEPARATION_STATUS.md). |

## Test suite posture (honest)

| Area | Over-indexed (today) | Under-indexed (target) |
|------|----------------------|-------------------------|
| Argparse topology, `STRINGS`, handler binding | Yes | Subprocess CLI for critical paths |
| Authority / leakage / repr invariants | Yes | End-to-end materialization + log review |
| `seckitd` protocol with mocks | Partial | Malformed payloads over real UDS from subprocess |
| Multi-host peer sync | No | Documented runs + sqlite-only CI signal |

## After validation — intentional implementation (Priority 5)

Only implement relay, daemon, or sync **gaps** that appear here or in [OPERATIONS_STATUS.md](OPERATIONS_STATUS.md) with **repro steps** and **operator impact**. Do not add features inferred only from architecture notes.
