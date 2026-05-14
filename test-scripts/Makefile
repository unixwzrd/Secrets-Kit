# Convenience targets for operational runners (same as invoking the scripts from this directory).
# From repo root: make -C test-scripts unit
# From test-scripts: make unit

.PHONY: help unit integration all

help:
	@echo "Targets: unit | integration | all"
	@echo "  unit          - Python unittest discover (tests/)"
	@echo "  integration   - SQLite subprocess smokes (smoke_full_local_runtime.sh)"
	@echo "  all           - unit, then integration"
	@echo "Reports: ../test-reports/<run-name>/<timestamp>/ (gitignored)"

unit:
	@./run_unit_tests.sh

integration:
	@./run_integration_tests.sh

all:
	@./run_all_tests.sh
