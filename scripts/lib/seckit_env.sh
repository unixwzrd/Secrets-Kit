#!/usr/bin/env bash
# Minimal shared shell helpers for Secrets-Kit operator scripts.

SECKIT_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export SECKIT_REPO_ROOT

resolve_seckit_python() {
  if [[ -n "${PYTHON:-}" ]]; then
    command -v "$PYTHON" 2>/dev/null || printf '%s' "$PYTHON"
    return 0
  fi
  for candidate in python python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      local candidate_path
      candidate_path="$(command -v "$candidate")"
      if "$candidate_path" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
      then
        printf '%s' "$candidate_path"
        return 0
      fi
    fi
  done
  echo "ERROR: could not find Python >= 3.10; set PYTHON=/path/to/python" >&2
  return 1
}

SECKIT_PYTHON_BIN="${SECKIT_PYTHON_BIN:-$(resolve_seckit_python)}"
export SECKIT_PYTHON_BIN

# Integration scripts must exercise the checkout under test, not an older `seckit`
# on PATH (e.g. venvutil). Unit tests already use PYTHONPATH=src via the Makefile.
# Set SECKIT_USE_PATH_CLI=1 to force the installed `seckit` binary instead.
run_seckit() {
  if [[ "${SECKIT_USE_PATH_CLI:-0}" == "1" ]] && command -v seckit >/dev/null 2>&1; then
    seckit "$@"
    return
  fi
  PYTHONPATH="$SECKIT_REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" "$SECKIT_PYTHON_BIN" -m secrets_kit.cli "$@"
}
