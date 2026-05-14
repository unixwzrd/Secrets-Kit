#!/usr/bin/env bash
# seckit run: env injection, exit propagation, missing name, no secret leakage on parent stderr before exec.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PY_BIN="${PYTHON:-}"
_py_ok() { [ -n "$1" ] && [ -x "$1" ] && "$1" -c "import yaml, nacl" 2>/dev/null; }
if ! _py_ok "$PY_BIN"; then PY_BIN=""
fi
if [ -z "$PY_BIN" ]; then
  for try in \
    "${REPO_ROOT}/.venv/bin/python" \
    "${REPO_ROOT}/venv/bin/python" \
    python3.12 python3.11 python3.10 python3
  do
    cand="$try"
    if [ ! -x "$cand" ]; then cand="$(command -v "$try" 2>/dev/null || true)"; fi
    if _py_ok "$cand"; then PY_BIN="$cand"; break; fi
  done
fi
if [ -z "$PY_BIN" ]; then
  echo "ERROR: need Python with PyYAML + PyNaCl. export PYTHON=/path/to/venv/bin/python" >&2
  exit 1
fi
echo "== using python: $PY_BIN" >&2

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-smoke-run.XXXXXX")"
cleanup() { rm -rf "$SMOKE_HOME"; }
trap cleanup EXIT

DB="$SMOKE_HOME/.config/seckit/secrets.db"
PASS="${SECKIT_SQLITE_PASSPHRASE:-seckit-smoke-run-passphrase-test!!}"
SVC=run-smoke
ACCT=local

run_cli() {
  HOME="$SMOKE_HOME" \
    SECKIT_SQLITE_UNLOCK=passphrase \
    SECKIT_SQLITE_PASSPHRASE="$PASS" \
    SECKIT_SQLITE_DB="$DB" \
    PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PY_BIN" -m secrets_kit.cli.main "$@"
}

echo "== seed secrets" >&2
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name RUN_A --value secret-value-aaa --kind generic
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name RUN_B --value secret-value-bbb --kind generic

echo "== run: inject two vars, verify in child (no printing secrets to parent)" >&2
HOME="$SMOKE_HOME" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
  "$PY_BIN" -m secrets_kit.cli.main run \
  --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" \
  --names RUN_A,RUN_B -- \
  "$PY_BIN" -c \
  "import os,sys; assert os.environ.get('RUN_A')=='secret-value-aaa'; assert os.environ.get('RUN_B')=='secret-value-bbb'; sys.exit(0)"

echo "== run: failing child exit code propagates" >&2
set +e
HOME="$SMOKE_HOME" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
  "$PY_BIN" -m secrets_kit.cli.main run \
  --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" \
  --names RUN_A -- \
  "$PY_BIN" -c "raise SystemExit(19)"
rc=$?
set -e
test "$rc" -eq 19

echo "== run: missing selection (nonexistent name -> no entries)" >&2
set +e
out_err="$(
  HOME="$SMOKE_HOME" \
    SECKIT_SQLITE_UNLOCK=passphrase \
    SECKIT_SQLITE_PASSPHRASE="$PASS" \
    SECKIT_SQLITE_DB="$DB" \
    PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PY_BIN" -m secrets_kit.cli.main run \
    --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" \
    --names NOSUCH_KEY_XYZ -- \
    "$PY_BIN" -c "print('should_not_run')" 2>&1
)"
miss_rc=$?
set -e
test "$miss_rc" -ne 0
if echo "$out_err" | grep -F "secret-value" >/dev/null; then
  echo "FAIL: secret material leaked to stderr" >&2
  exit 1
fi

echo "smoke_run: OK" >&2
