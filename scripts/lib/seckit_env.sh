#!/usr/bin/env bash
# Minimal shared shell helpers for Secrets-Kit operator scripts.

SECKIT_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export SECKIT_REPO_ROOT

# Integration scripts must exercise the checkout under test, not an older `seckit`
# on PATH (e.g. venvutil). Unit tests already use PYTHONPATH=src via the Makefile.
# Set SECKIT_USE_PATH_CLI=1 to force the installed `seckit` binary instead.
run_seckit() {
  if [[ "${SECKIT_USE_PATH_CLI:-0}" == "1" ]] && command -v seckit >/dev/null 2>&1; then
    seckit "$@"
    return
  fi
  PYTHONPATH="$SECKIT_REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m secrets_kit.cli "$@"
}
