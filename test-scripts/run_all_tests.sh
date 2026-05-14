#!/usr/bin/env bash
# Runs the unittest suite, then the SQLite operational integration gate (sequential; fail fast).
# macOS-only gates (Keychain opt-in, launchd smoke) stay separate; see README.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

report_init "run_all_tests"

echo "== phase 1: unit tests (unittest discover) ==" >&2
bash "${SCRIPT_DIR}/run_unit_tests.sh"

echo "== phase 2: integration (SQLite operational smokes) ==" >&2
bash "${SCRIPT_DIR}/run_integration_tests.sh"

echo "run_all_tests: ALL OK" >&2
