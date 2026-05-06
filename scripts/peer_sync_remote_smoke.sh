#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/peer_sync_remote_smoke.sh
  bash peer_sync_remote_smoke.sh

Run this script ON the peer machine (after tar + pip install, or from a checkout)
to confirm SSH/non-interactive-style execution works and seckit is wired.

Checks:
  - hostname and UTC time
  - `seckit` is on PATH; `seckit --help` succeeds
  - `seckit identity show` (warns only if no identity yet)

Optional environment:

  SECKIT_SYNC_VERIFY_BUNDLE=/path/to/bundle.json
      If set and the file exists, runs: `seckit sync verify` on it.
      If set but the path is missing, prints a warning and skips (avoids failing
      when copy-pasting example commands before a bundle exists).

  PEER_SYNC_REPO_ROOT=/path/to/secrets-kit-checkout
      If set and the directory exists, runs the SQLite peer-sync E2E unit test
      (needs PyNaCl): tests.test_peer_sync_e2e_sqlite

  PEER_SYNC_RUN_LAUNCHD_SQLITE=1
      If set together with PEER_SYNC_REPO_ROOT, runs ONE opt-in launchd + SQLite
      unittest method (macOS, may require GUI/login keychain context):
      LaunchdRunFlowTest.test_launch_agent_sqlite_backend_injects_env

Examples (run ONE block at a time; the first line is optional once you have a bundle):

  ./scripts/peer_sync_remote_smoke.sh

  SECKIT_SYNC_VERIFY_BUNDLE=/path/to/real-bundle.json ./scripts/peer_sync_remote_smoke.sh

  PEER_SYNC_REPO_ROOT="$HOME/src/secrets-kit" ./scripts/peer_sync_remote_smoke.sh
  PEER_SYNC_REPO_ROOT="$HOME/src/secrets-kit" PEER_SYNC_RUN_LAUNCHD_SQLITE=1 \
    ./scripts/peer_sync_remote_smoke.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

echo "=== peer_sync_remote_smoke: $(hostname) @ $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="

if ! command -v seckit >/dev/null 2>&1; then
  echo "ERROR: seckit not on PATH (try the same shell you use interactively)." >&2
  exit 1
fi
echo "seckit: $(command -v seckit)"

seckit --help >/dev/null
echo "seckit --help: ok"

if seckit identity show 2>/dev/null; then
  echo "identity: ok"
else
  echo "WARN: no host identity yet; run: seckit identity init" >&2
fi

if [[ -n "${SECKIT_SYNC_VERIFY_BUNDLE:-}" ]]; then
  if [[ ! -f "$SECKIT_SYNC_VERIFY_BUNDLE" ]]; then
    echo "WARN: SECKIT_SYNC_VERIFY_BUNDLE set but file missing (skipping verify): $SECKIT_SYNC_VERIFY_BUNDLE" >&2
  else
    echo "=== seckit sync verify (SECKIT_SYNC_VERIFY_BUNDLE) ==="
    seckit sync verify "$SECKIT_SYNC_VERIFY_BUNDLE"
  fi
fi

if [[ -n "${PEER_SYNC_REPO_ROOT:-}" ]]; then
  if [[ ! -d "$PEER_SYNC_REPO_ROOT" ]]; then
    echo "ERROR: PEER_SYNC_REPO_ROOT is not a directory: $PEER_SYNC_REPO_ROOT" >&2
    exit 1
  fi
  repo="$PEER_SYNC_REPO_ROOT"
  echo "=== unittest: tests.test_peer_sync_e2e_sqlite (PEER_SYNC_REPO_ROOT) ==="
  ( cd "$repo" && PYTHONPATH=src python -m unittest tests.test_peer_sync_e2e_sqlite -q )

  if [[ "${PEER_SYNC_RUN_LAUNCHD_SQLITE:-}" == "1" ]]; then
    echo "=== unittest: launchd sqlite (opt-in, macOS) ==="
    (
      cd "$repo"
      export PYTHONPATH=src
      export SECKIT_RUN_LAUNCHD_TESTS=1
      export SECKIT_RUN_LAUNCHD_SQLITE_TESTS=1
      python -m unittest \
        tests.test_launchd_run_flow.LaunchdRunFlowTest.test_launch_agent_sqlite_backend_injects_env \
        -v
    )
  fi
fi

echo "=== peer_sync_remote_smoke: done ==="
