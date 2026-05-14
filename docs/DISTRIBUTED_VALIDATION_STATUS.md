# Distributed validation status

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

**Purpose:** Record **multi-host** / **multi-VM** evidence for peer sync, identity, and transport—not CI unit tests. Link each scenario to [RUNTIME_TRUTH_MATRIX.md](RUNTIME_TRUTH_MATRIX.md) when you upgrade **multi-host** columns.

**Target topology (from stabilization plan):** 3 VMs, 2 physical systems, mixed restarts—adjust to what you actually run.

## Run metadata (template)

| Field | Value |
|-------|--------|
| Date | |
| seckit version / git SHA | |
| Hosts (roles) | e.g. peer-a VM1, peer-b bare metal |
| OS versions | |
| Backend(s) | Keychain / SQLite |
| Transport | manual bundle / future relay (document) |

## Scenarios

For each: **pass / fail / not run**, hosts used, repro, expected vs actual (no secrets in this file).

| Scenario | Status | Hosts | Repro / notes |
|----------|--------|-------|----------------|
| Identity creation | not run | | `seckit identity init` … |
| Peer enrollment | not run | | |
| Peer persistence across restart | not run | | |
| Sync export / import | not run | | |
| Reconcile / verify | not run | | |
| Reconnect / replay | not run | | |
| Delete propagation | not run | | |
| Registry consistency across peers | not run | | |
| Transport failure handling | not run | | |
| Partial availability (one peer down) | not run | | |
| Restart recovery | not run | | |

## CI signal (same-machine only)

- SQLite-heavy peer flow tests (e.g. `tests/test_peer_sync_e2e_sqlite.py`) are **not** a substitute for the table above; they only reduce regression risk.

**Relay / hosted forwarder:** out of scope for this public repo’s runtime proof; see [RELAY_SEPARATION_STATUS.md](RELAY_SEPARATION_STATUS.md).
