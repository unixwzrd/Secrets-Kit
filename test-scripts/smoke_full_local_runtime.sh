#!/usr/bin/env bash
# Full local SQLite operational gate: run all SQLite smokes in order; fail fast.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

report_init "smoke_full_local_runtime"

# shellcheck source=/dev/null
bash "$SCRIPT_DIR/smoke_sqlite.sh"
# shellcheck source=/dev/null
bash "$SCRIPT_DIR/smoke_sqlite_restart.sh"
# shellcheck source=/dev/null
bash "$SCRIPT_DIR/smoke_run.sh"
echo "smoke_full_local_runtime: ALL OK" >&2
