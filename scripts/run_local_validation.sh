#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

run_localhost_transport="auto"

usage() {
  cat <<'EOF'
Usage:
  run_local_validation.sh [--with-localhost-transport] [--without-localhost-transport]

Runs the CI-safe local validation sequence:
  - helper script syntax checks
  - Python bytecode compile check
  - Python unittest suite
  - optional localhost transport validation when ssh localhost works

Environment:
  PYTHON   interpreter to use (default: python3). Must have project deps (pip install -e .).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-localhost-transport) run_localhost_transport="yes"; shift ;;
    --without-localhost-transport) run_localhost_transport="no"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

cd "$REPO_ROOT"

PYTHON_BIN="${PYTHON:-python3}"
if ! "$PYTHON_BIN" -c "import yaml" 2>/dev/null; then
  echo "ERROR: $PYTHON_BIN cannot import PyYAML (required by seckit). From repo root: $PYTHON_BIN -m pip install -e ." >&2
  echo "Or set PYTHON to a venv interpreter: PYTHON=/path/to/venv/bin/python $0" >&2
  exit 1
fi

echo "== syntax checks =="
bash -n \
  scripts/build_bundled_helper_for_wheel.sh \
  scripts/package_release_wheels.sh \
  scripts/release_preflight.sh \
  scripts/seckit_cross_host_prepare.sh \
  scripts/seckit_cross_host_verify.sh \
  scripts/seckit_cross_host_transport_localhost.sh \
  scripts/seckit_launchd_smoke.sh \
  scripts/run_local_validation.sh

echo
echo "== python compile check =="
"$PYTHON_BIN" -m py_compile src/secrets_kit/*.py scripts/seckit_launchd_agent_simulator.py

echo
echo "== python tests =="
# Full discover expects macOS Keychain for some backend tests; see docs/README.md (Testing and CI).
PYTHONPATH=src "$PYTHON_BIN" -m unittest discover -s tests -v

should_run_transport="no"
if [[ "$run_localhost_transport" == "yes" ]]; then
  should_run_transport="yes"
elif [[ "$run_localhost_transport" == "auto" ]]; then
  if ssh -o BatchMode=yes -o ConnectTimeout=2 localhost true >/dev/null 2>&1; then
    should_run_transport="yes"
  fi
fi

if [[ "$should_run_transport" == "yes" ]]; then
  echo
  echo "== localhost transport validation =="
  bash ./scripts/seckit_cross_host_prepare.sh --service sync-test --account local --reset
  bash ./scripts/seckit_cross_host_transport_localhost.sh --service sync-test --account local
else
  echo
  echo "== localhost transport validation =="
  echo "skipped: ssh localhost is not available in batch mode"
fi

echo
echo "local validation complete"
