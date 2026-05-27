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
  - shell script syntax checks
  - Python bytecode compile check
  - ruff + basedpyright lint (make lint; requires pip install -e '.[dev]' from repo root)
  - Python unittest suite
  - optional localhost transport validation when ssh localhost works

Environment:
  PYTHON   interpreter to use (default: python3). Activate the intended environment first.
  Install dev tools once (zsh: quote the specifier): pip install -e '.[dev]'
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

if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$(command -v "$PYTHON" || echo "$PYTHON")"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  PYTHON_BIN="$(command -v python3)"
fi
export PYTHON="$PYTHON_BIN"

echo "== syntax checks =="
bash -n \
  install.sh \
  scripts/lib/install_lib.sh \
  scripts/lib/seckit_env.sh \
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
echo "== lint =="
echo "lint interpreter: $PYTHON_BIN ($("$PYTHON_BIN" -V 2>&1 | head -1))"
make lint

echo
echo "== python tests =="
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
