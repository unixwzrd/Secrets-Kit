#!/usr/bin/env bash
# Opt-in Keychain integration unittest surface (macOS + security CLI).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

report_init "run_keychain_integration"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "FAIL: Keychain integration tests require macOS (Darwin)." >&2
  exit 2
fi

if ! command -v security >/dev/null 2>&1; then
  echo "FAIL: macOS security(1) CLI not found on PATH." >&2
  exit 2
fi

export SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1

PY_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"
if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]]; then
  echo "ERROR: need PYTHON or python3 on PATH." >&2
  exit 1
fi

log_cmd "${PY_BIN}" -m unittest -v tests.test_keychain_backend_store tests.test_seckit_cli_keychain_e2e
PYTHONPATH=src "${PY_BIN}" -m unittest -v tests.test_keychain_backend_store tests.test_seckit_cli_keychain_e2e

echo "run_keychain_integration: OK" >&2
