# secrets-kit — developer convenience targets
#
# Install parallel test extras: pip install -e ".[test]"

SHELL := /bin/bash
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export PYTHONPATH := $(ROOT)/src

PYTHON ?= python3
# Workers for pytest-xdist (override: make test-parallel PYTEST_JOBS=4)
PYTEST_JOBS ?= 8

UNITTEST_Q ?= -q

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

.PHONY: help test test-parallel test-parallel-auto \
	test-sqlite test-contract test-backends test-cli test-daemon test-sync \
	test-registry test-models test-keychain test-reconciliation test-misc \
	test-groups unittest pytest-args

help:
	@printf '%s\n' \
	  'secrets-kit — Make targets (run from repo root)' \
	  '' \
	  '=== All targets ===' \
	  '  help                 This overview (default goal).' \
	  '  test                 FULL suite, serial (unittest discover).' \
	  '  test-parallel        FULL suite via pytest-xdist (-n $(PYTEST_JOBS)).' \
	  '  test-parallel-auto   FULL suite via pytest (-n auto).' \
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
	  '  Parallel: pip install -e ".[test]"' \
	  '  Keychain live tests: skipped unless SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 (see tests/README.md).' \
	  '  Daemon / socket tests: need POSIX + often `seckit` on PATH; may fail in sandboxes.' \
	  ''

# Full discover (canonical; matches AGENTS.md).
test:
	$(PYTHON) -m unittest discover -s tests $(UNITTEST_Q)

test-parallel:
	$(PYTHON) -m pytest tests -n $(PYTEST_JOBS) -q --import-mode=importlib

test-parallel-auto:
	$(PYTHON) -m pytest tests -n auto -q --import-mode=importlib

test-sqlite:
	$(PYTHON) -m unittest $(TEST_SQLITE) $(UNITTEST_Q)

# “Backends” = contract/resolution + all SQLite-focused modules (one command).
test-backends:
	$(PYTHON) -m unittest $(TEST_BACKENDS_CONTRACT) $(TEST_SQLITE) $(UNITTEST_Q)

test-cli:
	$(PYTHON) -m unittest $(TEST_CLI) $(UNITTEST_Q)

test-daemon:
	$(PYTHON) -m unittest $(TEST_DAEMON_RUNTIME) $(UNITTEST_Q)

test-sync:
	$(PYTHON) -m unittest $(TEST_SYNC_PEER) $(UNITTEST_Q)

test-registry:
	$(PYTHON) -m unittest $(TEST_REGISTRY) $(UNITTEST_Q)

test-models:
	$(PYTHON) -m unittest $(TEST_MODELS_SCHEMAS) $(UNITTEST_Q)

test-keychain:
	$(PYTHON) -m unittest $(TEST_KEYCHAIN) $(UNITTEST_Q)

test-reconciliation:
	$(PYTHON) -m unittest discover -s tests/reconciliation $(UNITTEST_Q)

test-misc:
	$(PYTHON) -m unittest $(TEST_MISC) $(UNITTEST_Q)

# Shared-store contract tests only (no SQLite modules). Used by test-groups to avoid
# running SQLite twice.
test-contract:
	$(PYTHON) -m unittest $(TEST_BACKENDS_CONTRACT) $(UNITTEST_Q)

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