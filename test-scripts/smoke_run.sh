#!/usr/bin/env bash
# seckit run: env injection, exit propagation, missing name, no secret leakage on parent stderr before exec.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

SECKIT_BIN="${SECKIT_BIN:-$(command -v seckit || true)}"
PY_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"
have_seckit=0
if [[ -n "${SECKIT_BIN}" && -x "${SECKIT_BIN}" ]]; then
  have_seckit=1
fi

if [[ "${have_seckit}" -eq 0 ]]; then
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]] || ! "${PY_BIN}" -c "import yaml, nacl" 2>/dev/null; then
    echo "ERROR: need seckit on PATH or PYTHON / python3 with PyYAML + PyNaCl." >&2
    exit 1
  fi
fi

if [[ "${have_seckit}" -eq 1 ]]; then
  echo "== using seckit: ${SECKIT_BIN}" >&2
else
  echo "== using python module: ${PY_BIN} -m secrets_kit.cli.main" >&2
fi

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-smoke-run.XXXXXX")"

__runtime_report_cleanup_hook() {
  rm -rf "${SMOKE_HOME}"
}

report_init "smoke_run"

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
    run_cli_inner "$@"
}

run_cli_inner() {
  if [[ "${have_seckit}" -eq 1 ]]; then
      "$SECKIT_BIN" "$@"
  else
      "$PY_BIN" -m secrets_kit.cli.main "$@"
  fi
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
  run_cli_inner run \
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
  run_cli_inner run \
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
    run_cli_inner run \
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
