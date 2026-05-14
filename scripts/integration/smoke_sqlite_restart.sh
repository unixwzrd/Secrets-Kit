#!/usr/bin/env bash
# Persistence: write secrets, then read/rebuild/recover in a minimal-env subprocess.
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
if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "ERROR: sqlite3 CLI not found" >&2
  exit 1
fi

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-sqlite-restart.XXXXXX")"
cleanup() { rm -rf "$SMOKE_HOME"; }
trap cleanup EXIT

DB="$SMOKE_HOME/.config/seckit/secrets.db"
PASS="${SECKIT_SQLITE_PASSPHRASE:-seckit-smoke-restart-passphrase-test!!}"
SVC=restart-smoke
ACCT=local
export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

run_cli() {
  HOME="$SMOKE_HOME" \
    SECKIT_SQLITE_UNLOCK="${SECKIT_SQLITE_UNLOCK:-passphrase}" \
    SECKIT_SQLITE_PASSPHRASE="$PASS" \
    SECKIT_SQLITE_DB="$DB" \
    PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PY_BIN" -m secrets_kit.cli.main "$@"
}

echo "== write phase (subprocess A): two secrets" >&2
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name ALPHA --value alpha-one --kind generic
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name BETA --value beta-two --kind generic
run_cli list --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

echo "== read phase (subprocess B, env -i)" >&2
env -i \
  HOME="$SMOKE_HOME" \
  PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src" \
  "$PY_BIN" -m secrets_kit.cli.main get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name ALPHA --raw \
  | grep -qx 'alpha-one'

env -i \
  HOME="$SMOKE_HOME" \
  PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src" \
  "$PY_BIN" -m secrets_kit.cli.main get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name BETA --raw \
  | grep -qx 'beta-two'

echo "== rebuild-index + recover (env -i)" >&2
env -i \
  HOME="$SMOKE_HOME" \
  PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src" \
  "$PY_BIN" -m secrets_kit.cli.main rebuild-index --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

recover_out="$(env -i \
  HOME="$SMOKE_HOME" \
  PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  SECKIT_SQLITE_UNLOCK=passphrase \
  SECKIT_SQLITE_PASSPHRASE="$PASS" \
  SECKIT_SQLITE_DB="$DB" \
  PYTHONPATH="${REPO_ROOT}/src" \
  "$PY_BIN" -m secrets_kit.cli.main recover --backend sqlite --db "$DB" --dry-run --json)"

echo "$recover_out" | "$PY_BIN" -c "import json,sys; d=json.load(sys.stdin); assert d.get('candidates',0)>=2, d"

echo "== integrity" >&2
sqlite3 "$DB" "PRAGMA integrity_check;"

echo "smoke_sqlite_restart: OK" >&2
