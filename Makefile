PYTHONPATH=src
PYTHON ?= python
TEST_JOBS ?= 1
UNITTEST_FLAGS ?= -b
.DEFAULT_GOAL := help

TEST_FAST := \
	tests.test_rss_auth \
	tests.test_rss_provisioning \
	tests.test_daemon_mdns \
	tests.test_daemon_transport \
	tests.test_locale \
	tests.test_cli_commands \
	tests.test_backend_resolution \
	tests.test_models_kind \
	tests.test_registry_permissions \
	tests.test_registry_storage \
	tests.test_backend_boundaries \
	tests.test_crypto_export_json \
	tests.test_import_layer_guards \
	tests.test_backend_dispatch \
	tests.test_info \
	tests.test_init \
	tests.test_schema_descriptors \
	tests.test_schema_cli \
	tests.test_metadata_merge \
	tests.test_taxonomy_cli \
	tests.test_taxonomy_registry \
	tests.test_taxonomy_normalize \
	tests.test_metadata_build \
	tests.test_import_taxonomy \
	tests.test_taxonomy_store \
	tests.test_package_data \
	tests.test_install_check \
	tests.test_install_transport_validation \
	tests.test_install_native_prefix \
	tests.test_cli_install \
	tests.test_installer_downloads \
	tests.test_install_bundle \
	tests.test_release_preflight \
	tests.test_upgrade \
	tests.test_uninstall

.PHONY: test-uninstall
.PHONY: test-upgrade
.PHONY: test-rss-auth
test-rss-auth:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) tests.test_rss_auth tests.test_daemon_transport

.PHONY: test-mcp
.PHONY: test-locales
test-locales:
	PYTHONPATH=src $(PYTHON) -m unittest -b tests.test_locale

test-mcp:
	PYTHONPATH=src $(PYTHON) -m unittest -b tests.test_mcp_server

test-uninstall:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) tests.test_uninstall tests.test_cli_install tests.test_upgrade tests.test_daemon_service tests.test_boot_service_helper

test-upgrade:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) tests.test_upgrade tests.test_cli_install tests.test_installer_downloads tests.test_install_bundle

TEST_IMPORT_EXPORT := \
	tests.test_import_dotenv \
	tests.test_export_shell

TEST_SQLITE_UNIT := \
	tests.test_sqlite_transactions \
	tests.test_sqlite_replay \
	tests.test_schema_registry_sqlite \
	tests.test_sqlite_taxonomy \
	tests.test_sqlite_vocabulary_transactions

TEST_PARALLEL_SAFE := \
	$(TEST_FAST) \
	$(TEST_IMPORT_EXPORT)

UNITTEST_DISCOVER := $(PYTHON) -m unittest discover $(UNITTEST_FLAGS) -s tests

.PHONY: help
help:
	@printf '\n'
	@printf '%s\n' 'Secrets-Kit make targets:'
	@printf '%s\n' ''
	@printf '%s\n' '  help                 Show this help'
	@printf '%s\n' '  lint                 Run ruff + basedpyright (pip install -e ".[dev]")'
	@printf '%s\n' '  fmt                  Run ruff autofix on src and tests (alias: FMT)'
	@printf '%s\n' '  format               Run ruff format on src and tests'
	@printf '%s\n' '  test-fast            Run fast unit module group'
	@printf '%s\n' '  test-upgrade         Run upgrade/check/service and installer unit tests'
	@printf '%s\n' '  test-import-export   Run import/export unit module group'
	@printf '%s\n' '  test-sqlite-unit     Run SQLite transactions and replay unit tests'
	@printf '%s\n' '  test-unit            Run test-fast and test-import-export'
	@printf '%s\n' '  test-unit-parallel   Run safe unit modules in parallel (set TEST_JOBS=N)'
	@printf '%s\n' '  test                 Run full unittest discovery'
	@printf '%s\n' '  security             Run permission and hardening regression tests'
	@printf '%s\n' '  test-integration     Run Keychain and SQLite backend integration checks'
	@printf '%s\n' '  test-keychain        Run Keychain backend integration checks'
	@printf '%s\n' '  test-sqlite          Run SQLite backend integration checks'
	@printf '%s\n' '  test-launchd         Run launchd unittest module'
	@printf '%s\n' '  install              Run ./install.sh (release pip install)'
	@printf '%s\n' '  install-dev          Run ./install.sh --dev (editable checkout)'
	@printf '%s\n' '  install-upgrade      Run ./install.sh --upgrade'
	@printf '%s\n' '  install-check        Run seckit doctor --install-check'
	@printf '%s\n' '  smoke                Print seckit CLI version'
	@printf '%s\n' '  validate-fast        Run lint, test-fast, and smoke'
	@printf '%s\n' '  validate-full        Run lint, full tests, integration, and launchd'
	@printf '%s\n' '  validate             Alias for validate-fast'
	@printf '%s\n' '  make-all             Alias for validate-full'
	@printf '%s\n' '  check                Alias for lint, test-fast, and smoke'
	@printf '%s\n' '  tree                 List Python source files'
	@printf '%s\n' '  stats                Show line counts for Python files'
	@printf '\n'

.PHONY: lint lint-ruff lint-types
lint: lint-ruff lint-types

lint-ruff:
	$(PYTHON) -m ruff check src tests

lint-types:
	@$(PYTHON) -c "import basedpyright" 2>/dev/null || { \
	  printf '%s\n' 'basedpyright is not installed for this Python.' \
	    'Install dev dependencies: pip install -e ".[dev]"'; \
	  exit 1; \
	}
	$(PYTHON) -m basedpyright --pythonpath "$$($(PYTHON) -c 'import sys; print(sys.executable)')" src tests

.PHONY: fmt FMT format fmt-ruff-check
fmt FMT: fmt-ruff-check
	-$(PYTHON) -m ruff check src tests --fix
	$(PYTHON) -m ruff check src tests

.PHONY: format
format: fmt-ruff-check
	$(PYTHON) -m ruff format src tests

fmt-ruff-check:
	@$(PYTHON) -c "import ruff" 2>/dev/null || { \
	  printf '%s\n' 'ruff is not installed for this Python.' \
	    'Install dev dependencies: pip install -e ".[dev]"'; \
	  exit 1; \
	}

.PHONY: test-fast
test-fast:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) $(TEST_FAST)

.PHONY: test-import-export
test-import-export:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) $(TEST_IMPORT_EXPORT)

.PHONY: test-sqlite-unit
TEST_SQLITE_UNIT += tests.test_sqlite_encrypted_sync
test-sqlite-unit:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) $(TEST_SQLITE_UNIT)

.PHONY: test-unit
test-unit: test-fast test-import-export

.PHONY: test-unit-parallel
test-unit-parallel:
	@tmp_dir="$$(mktemp -d /tmp/seckit-unit.XXXXXX)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	status=0; index=0; logs=""; pids=""; \
	for module in $(TEST_PARALLEL_SAFE); do \
		while [ "$$(jobs -pr | wc -l | tr -d ' ')" -ge "$(TEST_JOBS)" ]; do \
			sleep 0.1; \
		done; \
		index=$$((index + 1)); \
		log="$$tmp_dir/$$(printf '%02d' "$$index")-$${module}.log"; \
		logs="$$logs $$log"; \
		( \
			echo "== $$module =="; \
			PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) "$$module" \
		) >"$$log" 2>&1 & \
		pids="$$pids $$!"; \
	done; \
	for pid in $$pids; do \
		wait "$$pid" || status=1; \
	done; \
	for log in $$logs; do \
		cat "$$log"; \
	done; \
	exit "$$status"

.PHONY: test
test:
	PYTHONPATH=$(PYTHONPATH) $(UNITTEST_DISCOVER)

.PHONY: security
security:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover $(UNITTEST_FLAGS) -s tests/security

.PHONY: test-integration test-keychain test-sqlite
test-integration: test-keychain test-sqlite

test-keychain:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) tests.test_keychain_backend_real

test-sqlite:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest $(UNITTEST_FLAGS) tests.test_sqlite_storage_mode tests.test_sqlite_storage_codec

.PHONY: test-launchd
test-launchd:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover $(UNITTEST_FLAGS) -s tests -p 'test_launchd_run_flow.py'

.PHONY: install install-dev install-upgrade install-check
install:
	bash ./install.sh

install-dev:
	bash ./install.sh --dev --yes

install-upgrade:
	bash ./install.sh --upgrade

install-check:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m secrets_kit.cli doctor --install-check

.PHONY: smoke
smoke:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m secrets_kit.cli --version

.PHONY: tree
tree:
	find src/secrets_kit -name '*.py' | sort

.PHONY: stats
stats:
	find src tests -name '*.py' -exec wc -l {} \; | sort -n

.PHONY: check
check: lint test-fast smoke

.PHONY: validate-fast
validate-fast: lint test-fast smoke

.PHONY: validate-full
validate-full: lint test test-integration test-launchd

.PHONY: validate
validate: validate-fast

.PHONY: all
all: validate-full
