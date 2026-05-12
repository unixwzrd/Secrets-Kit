# Phase 6B — Operational validation (ugly conditions)

**Created**: 2026-05-12  
**Updated**: 2026-05-12

Phase **6B0** must be usable first: disposable peers from [`PHASE6B0_PEER_BOOTSTRAP.md`](PHASE6B0_PEER_BOOTSTRAP.md) ([`scripts/install.sh`](../../scripts/install.sh), [`scripts/bootstrap_peer.sh`](../../scripts/bootstrap_peer.sh), [`scripts/reset_peer.sh`](../../scripts/reset_peer.sh), [`scripts/bootstrap_vm_smoke.sh`](../../scripts/bootstrap_vm_smoke.sh)).

Phase **6B** adds **operator runbooks** under ugly conditions: restarts, duplicates, tombstones, relay interruption, SQLite snapshots, lineage/diagnosis, convergence. **No** new coordination services, relay intelligence, or orchestration.

## Topology

- **Layer 1:** Administrator or developer machine with a normal checkout; not a control plane.
- **Layer 2:** Two or three **disposable peers** (macOS or Linux), each with its own **peer-root** and `source env.sh`.
- **Relay:** Dumb forward only (existing Phase 5/6 assumptions). No merge authority on the relay.

Documentation for multi-peer smoke (when present in your tree): [`scripts/peer_sync_remote_smoke.sh`](../../scripts/peer_sync_remote_smoke.sh), [`scripts/reconcile_two_db_compare.sh`](../../scripts/reconcile_two_db_compare.sh), [`scripts/replay_import_sequence.py`](../../scripts/replay_import_sequence.py).

## Philosophy

- **Crude but transparent** beats sophisticated but hidden.
- **SQLite + reconcile trace** are the primary evidence surfaces.
- **Manual steps** and copy-paste commands are acceptable; avoid automation frameworks here.

## Success criteria (exit 6B)

Operators can:

- Bootstrap and smoke peers consistently (6B0).
- Re-run bundles after restarts without guessing hidden global state.
- Explain duplicate suppression and tombstone outcomes from tooling output.
- Recover or diagnose using `reconcile verify`, `lineage`, `explain`, and optional DB compare scripts.
- Tolerate relay failures without expecting new relay features.

---

## Runbook 1 — VM bootstrap and repeatable smoke

**Goal:** Same peer-root layout every time; non-interactive sanity checks.

**Steps**

1. On a clean VM or fresh directory, run [`scripts/bootstrap_peer.sh`](../../scripts/bootstrap_peer.sh) with `--editable` or `--git` + `--branch` / `--ref` (see [PHASE6B0_PEER_BOOTSTRAP.md](PHASE6B0_PEER_BOOTSTRAP.md)).
2. `source peer-root/env.sh`
3. Run [`scripts/bootstrap_vm_smoke.sh`](../../scripts/bootstrap_vm_smoke.sh) (`--env-file` if not in peer root).
4. Optionally set `SECKIT_SYNC_VERIFY_BUNDLE` and run [`scripts/peer_sync_remote_smoke.sh`](../../scripts/peer_sync_remote_smoke.sh) for extra checks.

**Pass:** `bootstrap_vm_smoke` prints `PASS`; `reconcile verify` reports `"ok": true` on an empty or healthy DB.

---

## Runbook 2 — Replay after restart

**Goal:** Process death or shell change does not corrupt lineage expectations; same bundle can be re-imported safely.

**Steps**

1. Bootstrap peer; `source env.sh`.
2. Import a bundle (or generate one with `seckit sync export` on another peer) using documented sync import commands from [`PEER_SYNC.md`](../PEER_SYNC.md).
3. Kill the importer / `seckitd` / shell; start a **new** shell; `source env.sh` again.
4. Re-import the **same** bundle (or replay from `SECKIT_BUNDLE_DIR`).

**Check**

- `seckit reconcile verify --backend sqlite --db "$SECKIT_SQLITE_DB"`
- `seckit reconcile lineage` / `inspect` as needed for the entry under test.
- Optional: [`scripts/reconcile_two_db_compare.sh`](../../scripts/reconcile_two_db_compare.sh) against a snapshot from before restart.

**Pass:** No unexpected hash conflicts; replay decisions match stabilization semantics (duplicate echo / suppressed as designed).

---

## Runbook 3 — Duplicate replay / delivery

**Goal:** Delivering the same bundle twice yields deterministic importer stats and trace (no silent divergence).

**Steps**

1. Note `SECKIT_BUNDLE_DIR` from `env.sh` or copy a bundle file into `bundles/`.
2. Import bundle **A** twice in a row (same file, same channel).

**Check**

- STDERR trace if `--reconcile-trace` is enabled on import.
- Importer summary: expect **duplicate** / **replay_suppressed** style outcomes as appropriate to row state (see Phase 6A reconciliation docs in-repo).

**Pass:** Operator can explain the second delivery outcome from trace + SQLite row state without ad-hoc tooling.

---

## Runbook 4 — Delayed tombstone

**Goal:** Tombstone wins with generation semantics; no “resurrection” of deleted rows beyond documented ladder behavior.

**Steps**

1. Establish a row on peer **P1**; export bundle; import on **P2**.
2. Delete/tombstone on **P1**; export tombstone bundle; import on **P2** after delay (or reorder with other bundles).
3. Optionally repeat with restart mid-sequence (combine with Runbook 2).

**Reference test (when present):** `tests/reconciliation/test_stabilization_crash_restart.py`.

**Pass:** Local SQLite reflects tombstone authority; `reconcile explain` / trace matches expectation.

---

## Runbook 5 — Relay interruption

**Goal:** Killing the relay mid-forward surfaces a clean failure; **no** new relay-side recovery logic required.

**Steps**

1. Start dumb relay path as in your environment (stdin/IPC bridge per `seckitd` docs).
2. Begin a bundle transfer that crosses the relay; interrupt relay (kill PID) during forward.
3. Observe importer / IPC exit status and STDERR tails (redacted per Phase 5B defaults).

**Optional automated coverage:** [`tests/test_relay_operational_boundaries.py`](../../tests/test_relay_operational_boundaries.py).

**Pass:** Failure is visible and non-corrupting; operator can retry from a known bundle file.

---

## Runbook 6 — SQLite snapshot / restore

**Goal:** File-level backup/restore of `vault.db` (or full `state/`) is a supported debugging primitive.

**Steps**

1. `source env.sh`; copy `"$SECKIT_SQLITE_DB"` to `"$SECKIT_SNAPSHOT_DIR/pre-step.db"` (or tarball `state/`).
2. Run destructive or exploratory imports.
3. Restore snapshot (stop writers; replace DB file or extract tarball).
4. `seckit reconcile verify --backend sqlite --db "$SECKIT_SQLITE_DB"`

**Pass:** `verify` ok; lineage matches restored snapshot expectations.

---

## Runbook 7 — Stale lineage replay

**Goal:** Lower-generation writes are skipped or suppressed; no silent overwrite of newer state.

**Steps**

1. Create two bundles where **B_old** carries older `generation` (or missing lineage) vs local **B_new** after local edits.
2. Import **B_old** after **B_new** is applied.

**Check:** `reconcile explain` / import stats; row unchanged where stale.

**Pass:** Behavior matches Phase 6A ladder; operator sees explicit reason in trace or tool output.

---

## Runbook 8 — Operator diagnosis workflow

**Goal:** Fixed triage order for “something went wrong” without new dashboards.

**Order**

1. `seckit reconcile verify --backend sqlite --db "$SECKIT_SQLITE_DB"` (add `--strict-content-hash` if investigating hash discipline).
2. `seckit reconcile lineage` / `inspect` for affected locators.
3. `seckit reconcile explain` on a specific bundle row if needed.
4. Re-run import with `--reconcile-trace` (secret-safe trace on STDERR).
5. Optional: [`scripts/reconcile_two_db_compare.sh`](../../scripts/reconcile_two_db_compare.sh) between peer DBs or against a snapshot.

**Pass:** Operator can point to **which** rule fired and **which** row versions collided.

---

## Runbook 9 — Convergence explainability

**Goal:** Different bundle **orderings** that should converge do converge to the same lineage projection (entry_id may differ across vaults; compare logical identity via locator + generation fields).

**Steps**

1. Build two bundles **X** and **Y** from peers that should end in the same authoritative state when applied in permuted order (design specific pairs using [`scripts/replay_import_sequence.py`](../../scripts/replay_import_sequence.py) if helpful).
2. Apply **X** then **Y** vs **Y** then **X** (separate peer-roots or reset between runs).
3. Compare `reconcile lineage` / projection-relevant fields (not raw `entry_id` across vaults unless documented).

**Pass:** Operator documents equivalence class; mismatches become explicit conflicts, not silent drift.

---

## Runbook 10 — Master checklist (ugly conditions)

| Scenario | Key steps | Pass criteria |
| --- | --- | --- |
| Cold bootstrap | 6B0 scripts + `bootstrap_vm_smoke` | PASS banner; `verify` ok |
| Restart mid-work | Runbook 2 | No mystery corruption; trace explains replay |
| Duplicate delivery | Runbook 3 | Deterministic stats |
| Tombstone wins | Runbook 4 | No resurrection |
| Relay dies | Runbook 5 | Visible failure; retry safe |
| DB snapshot | Runbook 6 | Restore + verify ok |
| Stale replay | Runbook 7 | Skip/suppress explicit |
| Incident triage | Runbook 8 | Root cause in SQLite + trace |
| Convergence | Runbook 9 | Same projection class |
| Full sweep | Runbooks 1–9 sampled | Operator sign-off in notes |

---

## Testing rhythm (maintainers)

- After changing **Python** code: `PYTHONPATH=src python -m unittest discover -s tests/reconciliation -q` plus touched relay tests.
- Shell: `bash -n` on [`scripts/install.sh`](../../scripts/install.sh), [`scripts/bootstrap_peer.sh`](../../scripts/bootstrap_peer.sh), [`scripts/reset_peer.sh`](../../scripts/reset_peer.sh), [`scripts/bootstrap_vm_smoke.sh`](../../scripts/bootstrap_vm_smoke.sh).

## Optional automated tests

Phase 6B does **not** require new timing-based or fleet tests. Prefer extending existing [`tests/reconciliation/`](../../tests/reconciliation/) or [`tests/test_relay_operational_boundaries.py`](../../tests/test_relay_operational_boundaries.py) only when a scenario is fully deterministic without sleeps.
