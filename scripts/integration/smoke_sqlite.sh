#!/usr/bin/env bash
# SQLite standalone CLI smoke: CRUD, doctor, rebuild-index, recover (dry-run), DB inspection.
# Run from repo root. Uses isolated HOME only.
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
  echo "ERROR: need Python with PyYAML + PyNaCl. export PYTHON=/path/to/venv/bin/python or: cd repo && pip install -e ." >&2
  exit 1
fi
echo "== using python: $PY_BIN" >&2
if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "ERROR: sqlite3 CLI not found" >&2
  exit 1
fi

export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
seckit() { "$PY_BIN" -m secrets_kit.cli.main "$@"; }

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-sqlite-smoke.XXXXXX")"
cleanup() { rm -rf "$SMOKE_HOME"; }
trap cleanup EXIT

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

echo "== set" >&2
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
seckit recover --backend sqlite --db "$DB" --dry-run --json | "$PY_BIN" -c "import json,sys; d=json.load(sys.stdin); assert 'candidates' in d; print('recover_stats_ok')"

echo "== post-delete integrity_check" >&2
sqlite3 "$DB" "PRAGMA integrity_check;"

echo "smoke_sqlite: OK" >&2
