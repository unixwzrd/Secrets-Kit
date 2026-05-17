# Runtime truth matrix

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

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
| `set` / `get` / `list` / `delete` (SQLite encrypted) | CLI | in-process + subprocess (datastore inspected) | [`test-scripts/smoke_sqlite.sh`](../test-scripts/smoke_sqlite.sh): `seckit` or `python -m secrets_kit.cli.main` in temp `HOME`, `sqlite3` (`integrity_check` ok, `journal_mode` delete, row counts), `strings` on DB **without** smoke secret literal (**verified 2026-05-14** dev host). |
| SQLite persistence / new process / `env -i` | CLI | subprocess | [`test-scripts/smoke_sqlite_restart.sh`](../test-scripts/smoke_sqlite_restart.sh): writes, minimal `env -i` + `PYTHONPATH`/`HOME`/`SECKIT_SQLITE_*`, `get` + `rebuild-index` + `recover --dry-run --json`, integrity (**2026-05-14**). |
| `seckit run` (inject + exit codes) | CLI | subprocess | [`test-scripts/smoke_run.sh`](../test-scripts/smoke_run.sh): inject `--names`, child exit propagation (`SystemExit(19)` → 19), bogus `--names` non-zero + stderr must not leak secrets (**2026-05-14**). |
| Full local SQLite runtime gate (sequential smokes) | CLI | subprocess | [`test-scripts/smoke_full_local_runtime.sh`](../test-scripts/smoke_full_local_runtime.sh) runs the three smokes in order; exit 0 on same host (**2026-05-14**). |
| `export` / `import` | CLI | in-process + subprocess (macOS) | Cross-host scripts + disposable keychain tests. |
| `recover` / `migrate recover-registry` | CLI | in-process + subprocess | `recover --dry-run --json` in [`test-scripts/smoke_sqlite.sh`](../test-scripts/smoke_sqlite.sh) + restart smoke (**2026-05-14**). |
| `rebuild-index` | CLI | in-process + subprocess | Same integration scripts (**2026-05-14**). |
| `doctor` | CLI | in-process + subprocess | Same integration scripts on isolated `HOME` (**2026-05-14**). |
| `daemon serve` (Unix socket) | LOCALD | in-process | `serve_forever` + thread in `tests/test_seckitd_phase5a.py`. |
| `daemon serve` via `seckit` subprocess | LOCALD | subprocess | `tests/test_seckit_daemon_subprocess_integration.py` (entrypoint + argv + real UDS). |
| `daemon ping` / `status` / `sync-status` / `peer-outbound` | LOCALD | in-process + subprocess | Client IPC tests in-process; CLI subprocess exercises `cmd_daemon_*`. |
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
