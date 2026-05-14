#!/usr/bin/env bash
# SQLite standalone CLI smoke: CRUD, doctor, rebuild-index, recover (dry-run), DB inspection.
# Run from repo root. Uses isolated HOME only.
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
else
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]] || ! "${PY_BIN}" -c "import json" 2>/dev/null; then
    PY_BIN="$(command -v python3 || command -v python || true)"
  fi
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]] || ! "${PY_BIN}" -c "import json" 2>/dev/null; then
    echo "ERROR: need a Python interpreter for JSON checks (python3 on PATH or PYTHON=…)." >&2
    exit 1
  fi
fi

if [[ "${have_seckit}" -eq 1 ]]; then
  echo "== using seckit: ${SECKIT_BIN}" >&2
else
  echo "== using python module: ${PY_BIN} -m secrets_kit.cli.main" >&2
fi

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-sqlite-smoke.XXXXXX")"

__runtime_report_cleanup_hook() {
  rm -rf "${SMOKE_HOME}"
}

report_init "smoke_sqlite"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "ERROR: sqlite3 CLI not found" >&2
  exit 1
fi

export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

seckit() {
  if [[ "${have_seckit}" -eq 1 ]]; then
      "$SECKIT_BIN" "$@"
  else
      "$PY_BIN" -m secrets_kit.cli.main "$@"
  fi
}

export HOME="$SMOKE_HOME"
export SECKIT_SQLITE_UNLOCK="${SECKIT_SQLITE_UNLOCK:-passphrase}"
export SECKIT_SQLITE_PASSPHRASE="${SECKIT_SQLITE_PASSPHRASE:-seckit-smoke-sqlite-passphrase-test!!}"
DB="${SECKIT_SQLITE_DB:-$HOME/.config/seckit/secrets.db}"
export SECKIT_SQLITE_DB="$DB"
SECRET_VALUE="SECKIT_SMOKE_PLAINTEXT_XYZZY_42"
SVC=smoke
ACCT=test
NAME=SMOKE_KEY

echo "== smoke_sqlite: HOME=$HOME DB=$DB" >&2

echo "== Set" >&2
log_cmd seckit set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name "$NAME" --value "$SECRET_VALUE" --kind generic
seckit set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name "$NAME" --value "$SECRET_VALUE" --kind generic

echo "== sqlite: tables" >&2
sqlite3 "$DB" ".tables"

echo "== sqlite: integrity_check" >&2
sqlite3 "$DB" "PRAGMA integrity_check;"

echo "== sqlite: journal_mode" >&2
sqlite3 "$DB" "PRAGMA journal_mode;"

echo "== sqlite: row counts (active / all)" >&2
sqlite3 "$DB" "SELECT COUNT(*) AS active_not_deleted FROM secrets WHERE deleted=0;"
sqlite3 "$DB" "SELECT COUNT(*) AS all_rows FROM secrets;"

echo "== sqlite: table_info (head)" >&2
sqlite3 "$DB" "PRAGMA table_info(secrets);" | head -n 20

if command -v strings >/dev/null 2>&1; then
  echo "== strings: secret literal must NOT appear in DB file" >&2
  if strings "$DB" 2>/dev/null | grep -F "$SECRET_VALUE" >/dev/null; then
    echo "FAIL: plaintext secret found in DB via strings(1)" >&2
    exit 1
  fi
  echo "ok (no plaintext match)" >&2
else
  echo "WARN: strings(1) not available; skipping plaintext scan" >&2
fi

echo "== get --raw" >&2
raw="$(seckit get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name "$NAME" --raw)"
test "$raw" = "$SECRET_VALUE"

echo "== list" >&2
seckit list --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

echo "== delete" >&2
seckit delete --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name "$NAME" --yes

echo "== list after delete (expect no entries)" >&2
out="$(seckit list --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" 2>&1)" || true
if ! echo "$out" | grep -q "no entries"; then
  echo "FAIL: expected 'no entries', got: $out" >&2
  exit 1
fi

echo "== get after delete (expect failure)" >&2
set +e
seckit get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name "$NAME" --raw 2>/dev/null
gcode=$?
set -e
test "$gcode" -ne 0

echo "== doctor" >&2
seckit doctor --backend sqlite --db "$DB"

echo "== rebuild-index" >&2
seckit rebuild-index --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

echo "== recover dry-run --json" >&2
seckit recover --backend sqlite --db "$DB" --dry-run --json | "${PY_BIN}" -c "import json,sys; d=json.load(sys.stdin); assert 'candidates' in d; print('recover_stats_ok')"

echo "== post-delete integrity_check" >&2
sqlite3 "$DB" "PRAGMA integrity_check;"

echo "smoke_sqlite: OK" >&2
