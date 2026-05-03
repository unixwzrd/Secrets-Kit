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
  - Swift native helper compile check when Swift is available
  - Python unittest suite
  - optional localhost transport validation when ssh localhost works
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

echo "== syntax checks =="
bash -n \
  scripts/build_bundled_helper_for_wheel.sh \
  scripts/package_release_wheels.sh \
  scripts/seckit_cross_host_prepare.sh \
  scripts/seckit_cross_host_verify.sh \
  scripts/seckit_cross_host_transport_localhost.sh \
  scripts/seckit_launchd_smoke.sh \
  scripts/run_local_validation.sh

echo
echo "== python compile check =="
python3 -m py_compile src/secrets_kit/*.py scripts/seckit_launchd_agent_simulator.py

echo
echo "== swift helper build =="
if command -v swift >/dev/null 2>&1; then
  swift build -c release --package-path src/secrets_kit/native_helper_src
else
  echo "skipped: swift not found"
fi

echo
echo "== python tests =="
PYTHONPATH=src python3 -m unittest discover -s tests -v

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
