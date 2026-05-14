#!/usr/bin/env bash
# Python unittest discovery (full suite under tests/). CI-style; not macOS-only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

report_init "run_unit_tests"

PY_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"
if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]]; then
  echo "ERROR: need PYTHON or python3 on PATH." >&2
  exit 1
fi
if ! "${PY_BIN}" -c "import yaml" 2>/dev/null; then
  echo "ERROR: ${PY_BIN} cannot import PyYAML. From repo root: ${PY_BIN} -m pip install -e ." >&2
  exit 1
fi

UNITTEST_ARGS=(-s tests -v)
if [[ -n "${SECKIT_UNITTEST_QUIET:-}" ]]; then
  UNITTEST_ARGS=(-s tests -q)
fi

log_cmd "${PY_BIN}" -m unittest discover "${UNITTEST_ARGS[@]}"
PYTHONPATH=src "${PY_BIN}" -m unittest discover "${UNITTEST_ARGS[@]}"

echo "run_unit_tests: OK" >&2
