#!/usr/bin/env bash
# Operational integration gate: SQLite subprocess smokes (temp HOME, sqlite3, seckit CLI).
# Does not run the Python unittest suite; see run_unit_tests.sh / run_all_tests.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

report_init "run_integration_tests"

# shellcheck source=/dev/null
bash "${SCRIPT_DIR}/smoke_full_local_runtime.sh"

echo "run_integration_tests: OK" >&2
