#!/usr/bin/env bash
# Compare lineage projections between two SQLite vaults (test/helper utility).
# Usage: ./scripts/reconcile_two_db_compare.sh /path/to/a.db /path/to/b.db
# Requires: PyNaCl, PYTHONPATH (set below from repo root). Ignores entry_id UUIDs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${ROOT}/src:${ROOT}"
exec python3 -c "
import sys
from tests.support.ops_reconcile import assert_lineage_projection_equal, lineage_projection
if len(sys.argv) != 3:
    sys.exit('usage: reconcile_two_db_compare.sh A.db B.db')
try:
    assert_lineage_projection_equal(
        lineage_projection(sys.argv[1]),
        lineage_projection(sys.argv[2]),
        ignore_entry_id=True,
    )
except AssertionError as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
print('lineage projections match (entry_id ignored)')
" "$@"
