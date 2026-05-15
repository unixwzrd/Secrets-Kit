# secrets-kit — developer convenience targets
#
# Install parallel test extras: pip install -e ".[test]"

SHELL := /bin/bash
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export PYTHONPATH := $(ROOT)/src:$(ROOT)/tests

PYTHON ?= python3
# Workers for pytest-xdist (override: make test-parallel PYTEST_JOBS=4)
PYTEST_JOBS ?= 8

# Grouped unittest slices (test-sqlite, test-cli, …): loud like `make test`.
UNITTEST_FLAGS ?= -v

# --- Grouped packages (unittest module paths: tests.test_foo) ---
TEST_SQLITE := \
	tests.test_sqlite_backend \
	tests.test_sqlite_queries \
	tests.test_sqlite_audit \
	tests.test_sqlite_schema_audit \
	tests.test_sqlite_plaintext_debug \
	tests.test_sqlite_unlock

TEST_BACKENDS_CONTRACT := \
	tests.test_backend_store_contract \
	tests.test_backend_resolution

TEST_CLI := \
	tests.test_cli_commands \
	tests.test_cli_help_consistency \
	tests.test_cli_strings_en \
	tests.test_parser_handler_bindings \
	tests.test_native_helper \
	tests.test_package_version

TEST_DAEMON_RUNTIME := \
	tests.test_seckitd_phase5a \
	tests.test_seckitd_phase5b \
	tests.test_seckitd_phase5d \
	tests.test_seckit_daemon_subprocess_integration \
	tests.test_runtime_session \
	tests.test_runtime_ipc_contract \
	tests.test_runtime_log \
	tests.test_launchd_run_flow

TEST_SYNC_PEER := \
	tests.test_sync_merge \
	tests.test_sync_bundle \
	tests.test_peer_sync_dry_run \
	tests.test_peer_sync_e2e_sqlite \
	tests.test_peers \
	tests.test_relay_operational_boundaries

TEST_REGISTRY := \
	tests.test_registry_permissions \
	tests.test_registry_slim \
	tests.test_registry_v2

TEST_MODELS_SCHEMAS := \
	tests.test_models_kind \
	tests.test_identity \
	tests.test_schemas_phase3 \
	tests.test_runtime_authority_invariants \
	tests.test_phase4_enrollment_envelope

TEST_KEYCHAIN := \
	tests.test_keychain_backend_store \
	tests.test_keychain_inventory \
	tests.test_keychain_backend_real \
	tests.test_disposable_keychain_flow \
	tests.test_seckit_cli_keychain_e2e

TEST_MISC := \
	tests.test_export_shell \
	tests.test_import_dotenv \
	tests.test_import_layer_guards \
	tests.test_operator_config_migration \
	tests.test_leakage_invariants

.DEFAULT_GOAL := help

.PHONY: help test test-quiet test-ci test-unittest test-parallel test-parallel-auto \
	test-sqlite test-contract test-backends test-cli test-daemon test-sync \
	test-registry test-models test-keychain test-reconciliation test-misc \
	test-keychain-live test-launchd-live test-operational-live \
	test-groups unittest pytest-args

help:
	@printf '%s\n' \
	  'secrets-kit — Make targets (run from repo root)' \
	  '' \
	  '=== All targets ===' \
	  '  help                 This overview (default goal).' \
	  '  test                 FULL suite, LOUD (pytest -v, each case + skip summary).' \
	  '  test-quiet           FULL suite, QUIET (pytest -q; exit code only-ish; use in CI).' \
	  '  test-ci              Same as test-quiet.' \
	  '  test-unittest        FULL suite via unittest discover (no pytest).' \
	  '  test-parallel        FULL suite, parallel pytest-xdist (-n $(PYTEST_JOBS), loud).' \
	  '  test-parallel-auto   FULL suite, pytest-xdist (-n auto, loud).' \
	  '' \
	  '  test-sqlite          SQLite store, schema/audit, queries, unlock, plaintext-debug.' \
	  '  test-contract        BackendStore contract + backend resolution only (shared layer).' \
	  '  test-backends        test-contract + test-sqlite together (one unittest invocation).' \
	  '  test-cli             CLI, parser bindings, native helper, package version.' \
	  '  test-daemon          seckitd phases 5a/5b/5d, daemon subprocess, runtime IPC/session/log, launchd.' \
	  '  test-sync            Sync merge/bundle, peer/dry-run/e2e, relay boundary docs.' \
	  '  test-registry        Permissions + slim + v2 registry.' \
	  '  test-models          Models, identity, Pydantic schemas, authority invariants, enrollment.' \
	  '  test-keychain        Keychain backend + inventory + real keychain + disposable + CLI e2e.' \
	  '  test-keychain-live   macOS: opt-in live Keychain integration (env set in recipe; pytest -n 0).' \
	  '  test-launchd-live    macOS: opt-in launchd integration (env set in recipe; pytest -n 0).' \
	  '  test-operational-live  macOS: Keychain + launchd live slices in one pytest run.' \
	  '  test-reconciliation  Package tests/reconciliation/ only.' \
	  '  test-misc            Export/import dotenv, import guards, operator config, leakage needles.' \
	  '' \
	  '  test-groups          test-sqlite → test-contract → test-cli → test-daemon → test-sync →' \
	  '                       test-registry → test-models → test-keychain → test-reconciliation →' \
	  '                       test-misc (same modules as `make test` when combined; stops at first error).' \
	  '' \
	  '  unittest             Custom unittest modules. Example:' \
	  '                         make unittest ARGS="tests.test_sqlite_backend -v"' \
	  '  pytest-args          Custom pytest. Example:' \
	  '                         make pytest-args ARGS="tests/test_sqlite_*.py -n 4 --tb=short"' \
	  '' \
	  '=== Combining groups ===' \
	  '  Run several slices in one shell (sequential):' \
	  '    make test-sqlite test-cli test-registry' \
	  '  Or pass explicit unittest modules:' \
	  '    make unittest ARGS="tests.test_sync_merge tests.test_sync_bundle -v"' \
	  '' \
	  '=== Module lists ===' \
	  '  Exact unittest module lists live under TEST_* variables at the top of this Makefile;' \
	  '  tests/README.md has a target→area summary table.' \
	  '' \
	  '=== Prerequisites ===' \
	  '  Full suite needs: pip install -e ".[test]"' \
	  '  Parallel: pip install -e ".[test]"' \
	  '  Keychain live tests: skipped unless SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 (see tests/README.md).' \
	  '    Convenience: make test-keychain-live (sets env + pytest -n 0 on the two Keychain modules).' \
	  '  Launchd: make test runs temp-keychain/SQLite jobs on macOS when launchctl gui/<uid> exists (not CI); SECKIT_RUN_LAUNCHD_TESTS=0 skips.' \
	  '    Pytest slice: make test-launchd-live (forces SECKIT_RUN_LAUNCHD_TESTS=1).' \
	  '  Both: make test-operational-live' \
	  '  Daemon / socket tests: need POSIX + often `seckit` on PATH; may fail in sandboxes.' \
	  ''

# LOUD — default for humans: every test name, colors, short tracebacks, skip summary at end.
test:
	@$(PYTHON) -c "import pytest" 2>/dev/null || { printf '%s\n' 'pytest required: pip install -e ".[test]"' >&2; exit 1; }
	$(PYTHON) -m pytest tests -n 0 -v -rs --tb=short --color=yes

# QUIET — CI/CD: minimal output; non-zero exit on failure (traceback only when something breaks).
test-quiet:
	@$(PYTHON) -c "import pytest" 2>/dev/null || { printf '%s\n' 'pytest required: pip install -e ".[test]"' >&2; exit 1; }
	$(PYTHON) -m pytest tests -n 0 -q --tb=short

test-ci: test-quiet

# Full suite via unittest (no pytest); same scope as `make test`.
test-unittest:
	$(PYTHON) -m unittest discover -s tests $(UNITTEST_FLAGS)

test-parallel:
	@$(PYTHON) -c "import pytest" 2>/dev/null || { printf '%s\n' 'pytest required: pip install -e ".[test]"' >&2; exit 1; }
	$(PYTHON) -m pytest tests -n $(PYTEST_JOBS) -v -rs --tb=short --color=yes

test-parallel-auto:
	@$(PYTHON) -c "import pytest" 2>/dev/null || { printf '%s\n' 'pytest required: pip install -e ".[test]"' >&2; exit 1; }
	$(PYTHON) -m pytest tests -n auto -v -rs --tb=short --color=yes

test-sqlite:
	$(PYTHON) -m unittest $(TEST_SQLITE) $(UNITTEST_FLAGS)

# “Backends” = contract/resolution + all SQLite-focused modules (one command).
test-backends:
	$(PYTHON) -m unittest $(TEST_BACKENDS_CONTRACT) $(TEST_SQLITE) $(UNITTEST_FLAGS)

test-cli:
	$(PYTHON) -m unittest $(TEST_CLI) $(UNITTEST_FLAGS)

test-daemon:
	$(PYTHON) -m unittest $(TEST_DAEMON_RUNTIME) $(UNITTEST_FLAGS)

test-sync:
	$(PYTHON) -m unittest $(TEST_SYNC_PEER) $(UNITTEST_FLAGS)

test-registry:
	$(PYTHON) -m unittest $(TEST_REGISTRY) $(UNITTEST_FLAGS)

test-models:
	$(PYTHON) -m unittest $(TEST_MODELS_SCHEMAS) $(UNITTEST_FLAGS)

test-keychain:
	$(PYTHON) -m unittest $(TEST_KEYCHAIN) $(UNITTEST_FLAGS)

# Opt-in live Keychain modules only (sets SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS; needs macOS + security).
# Uses pytest -n 0 so xdist does not fork before interactive-looking security calls.
test-keychain-live:
	SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 $(PYTHON) -m pytest -n 0 -v -rs --tb=short --color=yes \
		tests/test_keychain_backend_store.py \
		tests/test_seckit_cli_keychain_e2e.py \
		--import-mode=importlib

# Pytest slice for launchd module (forces SECKIT_RUN_LAUNCHD_TESTS; interactive make test also runs these on macOS).
test-launchd-live:
	SECKIT_RUN_LAUNCHD_TESTS=1 $(PYTHON) -m pytest -n 0 -v -rs --tb=short --color=yes \
		tests/test_launchd_run_flow.py \
		--import-mode=importlib

# Keychain + launchd live slices in one command (no global export/unset in your shell).
test-operational-live:
	SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 SECKIT_RUN_LAUNCHD_TESTS=1 $(PYTHON) -m pytest -n 0 -v -rs --tb=short --color=yes \
		tests/test_keychain_backend_store.py \
		tests/test_seckit_cli_keychain_e2e.py \
		tests/test_launchd_run_flow.py \
		--import-mode=importlib

test-reconciliation:
	$(PYTHON) -m unittest discover -s tests/reconciliation $(UNITTEST_FLAGS)

test-misc:
	$(PYTHON) -m unittest $(TEST_MISC) $(UNITTEST_FLAGS)

# Shared-store contract tests only (no SQLite modules). Used by test-groups to avoid
# running SQLite twice.
test-contract:
	$(PYTHON) -m unittest $(TEST_BACKENDS_CONTRACT) $(UNITTEST_FLAGS)

# Same modules as `make test` when summed, but one group at a time (easier to spot failures).
test-groups: \
	test-sqlite \
	test-contract \
	test-cli \
	test-daemon \
	test-sync \
	test-registry \
	test-models \
	test-keychain \
	test-reconciliation \
	test-misc

unittest:
	@test -n "$(ARGS)" || (printf '%s\n' "Usage: make unittest ARGS=\"tests.test_foo [tests.test_bar ...] [-v]\"" && exit 1)
	$(PYTHON) -m unittest $(ARGS)

pytest-args:
	@test -n "$(ARGS)" || (printf '%s\n' "Usage: make pytest-args ARGS=\"tests/test_foo.py -k pattern -n 4 --tb=short\"" && exit 1)
	$(PYTHON) -m pytest $(ARGS) --import-mode=importlib