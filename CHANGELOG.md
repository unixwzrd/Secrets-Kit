# Secrets-Kit Changelog

**Created**: 2026-03-10  
**Updated**: 2026-06-01

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### 2026-06-01 — Release validation tooling

- **What changed:** Added [RELEASE_VALIDATION.md](docs/RELEASE_VALIDATION.md), `scripts/install-validation.sh`, `scripts/upgrade-validation.sh`, and `scripts/verify-release-artifacts.sh`. Release CI verifies wheel naming matches `install.sh` expectations.

### 2026-06-01 — Installer hardening (downloader, acceptance test, uv cache)

- **What changed:** `install.sh` uses a single downloader layer (`curl` / `wget` / `python3` urllib) with connect/transfer timeouts and retries for GitHub API, release assets, and uv bootstrap. GitHub release tags resolve via `python3` + `json` (release/prerelease channels; drafts ignored). Installer no longer sets `UV_CACHE_DIR` or a private uv cache. `state/runtime-path` remains as a legacy compatibility file; `runtime/current` is canonical for the launcher. Post-install runs `seckit doctor --install-check` and `seckit doctor --acceptance-test` (ephemeral `__seckit_test__` CRUD with guaranteed cleanup).

### 2026-05-30 — Pre-release `2.0.0a3`

- **What changed:** Phase 2 installer on `dev-local`: uv-managed Python 3.12, universal wheel/sdist release install (latest GitHub prerelease), runtime retention, dynamic release resolution (no baked tag in `install.sh`). Operator account init prefers `$HOME` over inherited `USER=root`. CI targets Linux and macOS with Python 3.11–3.12; release builds one `py3-none-any` wheel and one sdist. Removed obsolete `sync_repos.sh`, `package_release_wheels.sh`, `install_lib.sh`. Maintainer release via `scripts/release`.

### 2026-05-30 — Fix silent default install exit (`set -e` + `verbose_log`)

- **What changed:** Default `curl | bash` no longer exits immediately after step 1. `verbose_log` and other conditional helpers no longer use `[[ … ]] && cmd` patterns that abort the script under `set -euo pipefail` when verbose mode is off.

### 2026-05-28 — Installer default bootstrap (post-`2.0.0a2`)

- **What changed:** Default `curl | bash` install now bootstraps missing runtime tooling automatically (no extra flags). `--safe` and `--no-uv-download` opt out of network bootstrap. Deprecated `--allow-uv-download`. Operator messages avoid runtime-manager product names in default mode.

### 2026-05-28 — Pre-release `2.0.0a2`

- **What changed:** Tag `v2.0.0a2`. Standalone `install.sh` UV bootstrap (isolated runtime under `~/.local/share/seckit`, launcher at `~/.local/bin/seckit`). Installer flags: `--repair`, `--verbose`, `--safe`, shell-profile controls. `seckit install` forwards new flags; `doctor --install-check` validates launcher and runtime-path. Version refs aligned across `pyproject.toml`, `install.sh`, and `install_constants.py`.

### 2026-05-27 — Pre-release `2.0.0a1`

- **What changed:** Tag `v2.0.0a1`. Operator [INSTALL.md](docs/INSTALL.md) split from [MAINTAINER_RELEASE.md](docs/MAINTAINER_RELEASE.md). [QUICKSTART.md](docs/QUICKSTART.md) is CLI-only (unlock/set/list/run/lock). Installer Python order: conda → venv → managed → `SECKIT_PYTHON` → PATH. `install_lib.sh` is bash-only (no inline Python); Python 3.9+ prerequisite with clean failure. Release wheel smoke uses `seckit --version` and `doctor --install-check`.

### 2026-05-26 — PEP 440 pre-release version `2.0.0a0`

- **What changed:** `project.version` set to `2.0.0a0` (valid PEP 440; fixes CI/setuptools). Installer refs and docs use tag `v2.0.0a0`. Replaces invalid `2.0.0-pre-0a`.

### 2026-05-26 — Align installer refs with pre-release tag

- **What changed:** `install.sh`, `install_constants.py`, and [INSTALL.md](docs/INSTALL.md) aligned with `pyproject.toml`. Publish checklist (tag `v` + version). `--dev` defaults pip ref to `dev`.

### 2026-05-26 — Bootstrap install experience (phase 1)

- **What changed:** Operator install via `curl -fsSL …/install.sh | bash`; `install.sh` + `scripts/lib/install_lib.sh` with conda → venv → managed venv (`$HOME/.local/share/seckit/venv`), `"$PYTHON" -m pip` from tagged GitHub URL, `~/.config/seckit/install.json` state, and `--upgrade` reusing the recorded interpreter when still executable. `seckit install` (--upgrade, remote SSH wrapper), `seckit doctor --install-check` (fast path in `cli/install_check.py`). Taxonomy builtin seeds added to `pyproject.toml` package-data. Docs: [INSTALL.md](docs/INSTALL.md); Makefile `install`, `install-dev`, `install-upgrade`, `install-check`.

### 2026-05-26 — Taxonomy remediation completion

- **What changed:** Import candidates no longer gate kinds on `ENTRY_KIND_VALUES`; import writes register vocabulary via `sync_vocabulary_on_write`. Added `taxonomy/register.py`, `tests/test_taxonomy_store.py`, `tests/test_import_taxonomy.py`, `docs/worklog.md`. Aligned [OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md](docs/OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md) and [LOCAL_FIRST_DATASTORE_ARCHITECTURE.md](docs/LOCAL_FIRST_DATASTORE_ARCHITECTURE.md) with vocabulary transaction authority.

### 2026-05-26 — Schema/taxonomy registry keychain alignment

- **What changed:** `build_metadata()` and import merge now pass `--keychain` through to `load_schema_registry` / `load_taxonomy_registry` / `save_taxonomy_registry`, so disposable or alternate keychains bootstrap and validate registries on the same backend path used for the secret write. Fixes `unknown schema_id 'builtin.secret.generic'` on `seckit set --keychain …`. Taxonomy registry is persisted only when vocabulary changed (avoids redundant Keychain rewrite after bootstrap). Keychain `set` uses delete-then-add when an item already exists (replaces flaky `-U` update on disposable keychains). Operator scripts (`scripts/lib/seckit_env.sh`) now run the **repo** CLI via `PYTHONPATH=src` by default (not an older `seckit` on PATH); set `SECKIT_USE_PATH_CLI=1` to test the installed binary. Empty schema/taxonomy registry payloads re-bootstrap bundled seeds.

### 2026-05-26 — Taxonomy list filters and operator docs

- **What changed:** `seckit taxonomy list` accepts `--types`, `--kinds`, and `--tags` (combine to filter); human output includes `comment` column; JSON includes `operator_comment`. Updated [TAXONOMY.md](docs/TAXONOMY.md), [CLI_REFERENCE.md](docs/CLI_REFERENCE.md), [WORKFLOWS.md](docs/WORKFLOWS.md) with `schema` and `taxonomy` command trees.

### 2026-05-26 — Taxonomy registry, canonical names, vocabulary transactions

- **Scope:** `secrets_kit/taxonomy/`, `backends/sqlite/vocabulary_projections.py`, `secrets_api.py`, `replay.py`, `seckit taxonomy` CLI, `docs/TAXONOMY.md`, tests.
- **What changed:** Canonical **taxonomy** registry on `__taxonomy_registry__` (flat JSON: types, kinds, tags). Bundled seeds under `taxonomy/builtin/`. `canonical_taxonomy_name()` collapses spelling variants (`API_Key`, `api-key` → `api_key`) for stable UUIDs; CLI prompts or `--accept-normalized` / `--force-raw-name` (dev). SQLite emits `vocabulary.entry_type/kind.upsert` before `secret.set`; tables remain projections only. `seckit taxonomy list|show|export|install`. No `PRAGMA user_version` bump.

### 2026-05-26 — SQLite entry type, kind, and tag tables

- **Scope:** `backends/sqlite/schema.py`, `backends/sqlite/taxonomy.py`, `projections.py`, architecture docs, tests.
- **What changed:** Added normalized `entry_types`, `entry_kinds`, `secret_tags`, and `secret_tag_assignments` tables. Each vocabulary row uses a **UUID primary key** (`entry_type_id`, `entry_kind_id`, `tag_id`) plus a unique **`name`** (CLI/metadata label). `secrets` references type/kind by UUID; transaction payloads still carry string names resolved at projection time. Bootstrap seeds built-in vocabulary with deterministic UUIDs. No migration framework — unreleased bootstrap DDL only (`PRAGMA user_version` remains 2).

### 2026-05-26 — Typed metadata schemas (JSON registry)

- **Scope:** `secrets_kit/schemas/`, `secrets_kit/system_objects.py`, `secrets_kit/metadata/merge.py`, `seckit schema` CLI, tests, `docs/METADATA_SCHEMAS.md`.
- **What changed:** Canonical **metadata** schema registry (JSON descriptors with per-`schema_id` `schema_version`) lives on the `schema_registry` system locator (Keychain comment / SQLite secret row). Bundled seeds merge at `seckit init` / `seckit schema install` with add-only field union, collision fail unless `--replace`, and reference-safe field removal (`__undefined__` sentinel). `EntryMetadata` gains `schema_id`; writes use `merge_entry_metadata` and custom validation. Operator `seckit list` excludes system locators. **No SQLite `PRAGMA user_version` bump, migrations, or DDL changes** — existing Phase 2 database layout unchanged.

### 2026-05-26 — Remove remaining iCloud Keychain references

- **Scope:** `src/secrets_kit/backends/common.py`, `backends/keychain/`, `docs/ICLOUD_SYNC_VALIDATION.md` (deleted), `README.md`, `docs/DEFAULTS.md`, `scripts/seckit_launchd_smoke.sh`, tests.
- **What changed:** Dropped `ICLOUD_BACKEND_REMOVED_MESSAGE`, the iCloud-specific backend rejection path, and `docs/ICLOUD_SYNC_VALIDATION.md`. Unknown backend ids (including legacy `icloud` / `icloud-helper`) now fail with the generic unsupported-backend error. README and ops docs no longer mention iCloud Keychain sync or removed backends.

### 2026-05-26 — `seckit info` command and `init`

- **Scope:** `cli/commands/info.py`, `cli/commands/init_cmd.py`, parsers, locales, tests, README/QUICKSTART.
- **What changed:** Replaced the `version` subcommand with **`seckit info`** (human status by default, `--json` for automation). Keychain probes run only on **macOS**; Linux shows SQLite status and marks Keychain unsupported. **`seckit -v`** still prints the package version. Added **`seckit init`** / **`seckit init sqlite`** with destructive-operation confirmation (`-y` to skip). `seckit init` defaults to **sqlite** backend on non-macOS platforms.

### 2026-05-26 — Code quality refactor (registry, dispatch, module splits)

- **Scope:** `src/secrets_kit/registry/`, `src/secrets_kit/backends/dispatch.py`, `src/secrets_kit/cli/metadata_build.py`, `src/secrets_kit/backends/sqlite/{gate,secrets_api}.py`, `src/secrets_kit/backends/keychain/{comment_codec,security_run}.py`, CLI commands, tests, docs.
- **What changed:** Split flat `registry.py` into `registry/storage.py` + `registry/resolve.py`; moved argparse metadata construction to `cli/metadata_build.py`; added `backends/dispatch.py` for backend-neutral CRUD; consolidated import commands via `_run_import`; split SQLite backend into gate + secrets API and Keychain subprocess helpers into `security_run.py`; added `tests/test_import_layer_guards.py` and `tests/test_backend_dispatch.py`; Makefile targets `test-sqlite-unit` and extended `test-fast`.

### 2026-05-26 — First-class `secrets_kit.crypto` package

- **Scope:** `src/secrets_kit/crypto/`, CLI export/import commands, SQLite backend, tests.
- **What changed:** Replaced top-level `secrets_kit/crypto.py` and `backends/sqlite/crypto.py` with `secrets_kit.crypto.cli` (encrypted JSON export/import) and `secrets_kit.crypto.storage.sqlite` (SQLite column codec). Transport and other backends can import crypto boundaries without reaching through CLI or backend shim modules.

### 2026-05-26 — Lint tooling and compatibility layer removal

- **Scope:** `pyproject.toml`, `Makefile`, `src/secrets_kit/backends/`, `src/secrets_kit/cli/`, tests, `scripts/run_local_validation.sh`, `.github/workflows/ci.yml`, `README.md`.
- **What changed:** `make lint` now runs ruff on `src` and `tests` plus basedpyright for import resolution (`pip install -e ".[dev]"`). Removed `secrets_kit.keychain_backend` imports and other compatibility surfaces: no `BACKEND_SECURE` / `is_secure_backend`, no `secure`/`local` backend CLI aliases, no `--allow-insecure-sqlite` flag (use `--sqlite-dev-mode` only), no keychain re-exports from `secrets_kit.cli`, and no `require_insecure_sqlite_ack` wrapper. Canonical backend ids are `keychain` and `sqlite` only.

### 2026-05-25 — SQLite Phase 5A standalone CLI integration

- **Scope:** SQLite backend selection, standalone SQLite adapter, `set` / `get` / `list` / `delete` CLI paths, SQLite CLI tests, architecture/status docs.
- **What changed:** Added development-gated standalone SQLite CLI support for local `set`, `get`, `list`, and `delete`. SQLite writes now append canonical transactions and apply only the new projection atomically; reads inspect active projections only and never replay or auto-heal. SQLite remains non-production for secret material until encryption-at-rest is implemented and requires `--sqlite-dev-mode` or `SECKIT_SQLITE_DEVELOPER_MODE=1`; `--allow-insecure-sqlite` remains a compatibility alias.

### 2026-05-25 — SQLite Phase 4 local replay and projection materialization

- **Scope:** `src/secrets_kit/backends/sqlite/replay.py`, `src/secrets_kit/backends/sqlite/projections.py`, SQLite exports, replay tests, architecture/status docs.
- **What changed:** Added bounded standalone SQLite replay for `secret.set` and `secret.delete`, materializing the derived `secrets` projection from canonical transactions in deterministic local `rowid` order. Unsupported transaction types fail explicitly, invalid base64 projection payloads fail before projection writes, envelopes remain ignored by replay, and SQLite remains non-user-facing with no CLI/backend resolver integration.

### 2026-05-25 — SQLite Phase 3 object model semantics

- **Scope:** `docs/OBJECT_MODEL_AND_SCHEMA_SEMANTICS.md`, SQLite architecture/status docs, `CHANGELOG.md`.
- **What changed:** Added the semantic authority for future SQLite object identity, transaction lineage, projection semantics, schema identity, hashing boundaries, locator semantics, authoritative-state boundaries, lifecycle vocabulary, and replay invariants. This is documentation only; replay, projection materialization, envelope lifecycle behavior, daemon/sync integration, encryption implementation, migrations, and CLI integration remain unimplemented.

### 2026-05-25 — SQLite Phase 1/2 transaction foundation and schema skeleton

- **Scope:** `src/secrets_kit/backends/sqlite/`, `tests/test_sqlite_transactions.py`, architecture/status docs.
- **What changed:** Added an isolated SQLite transaction foundation with explicit connection setup, schema bootstrap, deterministic transaction serialization and hashing, append-only transaction insertion, transaction retrieval, and existence checks. Expanded bootstrap to the canonical Phase 2 schema skeleton and added schema-only state vocabulary constraints for derived `secrets` projection rows and reserved/inert `envelopes` rows. This is isolated transaction persistence and schema foundation only; SQLite is not a user-facing backend yet.

### 2026-05-23 — JSON-only imports and PyYAML dependency removal

- **Scope:** `pyproject.toml`, `src/secrets_kit/importers.py`, CLI parser/help text, validation script, active docs, tests.
- **What changed:** Removed YAML/YML file import support and the declared `PyYAML` runtime dependency. `seckit import file` now accepts JSON input only; existing JSON parsing and validation behavior is unchanged.

### 2026-05-23 — CLI command decomposition repair

- **Scope:** `src/secrets_kit/cli/commands/`, `src/secrets_kit/cli/*.py`, `tests/test_cli_commands.py`, `CHANGELOG.md`.
- **What changed:** Moved command implementations and shared CLI helpers out of the temporary `cli/runtime.py` holding module into command-owned modules and focused helper modules, updated parser dispatch to import command handlers directly, preserved compatibility exports through `secrets_kit.cli`, and removed the misleading `EXIT_USAGE` alias.

### 2026-05-23 — CLI/backend decomposition, locale table, and helper surface removal

- **Scope:** `src/secrets_kit/cli/`, `src/secrets_kit/backends/`, `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/locale.py`, `src/secrets_kit/errors.py`, `src/secrets_kit/logging.py`, tests, docs, `pyproject.toml`.
- **What changed:** Converted the monolithic CLI module into a package with compatibility exports and `python -m secrets_kit.cli` support, moved the macOS `security` backend under `backends/keychain/` while keeping `secrets_kit.keychain_backend` imports working, added a static `en_US` message table plus POSIX-oriented error helpers and central logging helpers, and removed the obsolete native-helper command/code/test/package-data surface.

### 2026-05-13 — v1.2.3 security scan hardening for CLI output, launchd smoke paths, and GitHub Actions

- **Scope:** `src/secrets_kit/cli.py`, `scripts/seckit_launchd_agent_simulator.py`, `scripts/seckit_launchd_smoke.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `pyproject.toml`, `CHANGELOG.md`
- **What changed:** Isolated explicit `seckit get --raw` secret materialization behind a dedicated stdout helper while keeping normal `get` output redacted, with a narrow CodeQL suppression documenting that this is intentional CLI materialization rather than diagnostic logging. Removed user-controlled output path arguments from the launchd smoke-test child; proof files now use fixed `/tmp/seckit-launchd-smoke/<mode>-result.txt` paths derived from an allowlisted launch mode. Added explicit read-only `GITHUB_TOKEN` permissions to CI and pinned the PyPI publish action to a full upstream commit SHA.

### 2026-05-05 — Remove Swift iCloud helper: `secure` + `security` CLI only

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/native_helper.py`, `src/secrets_kit/native_helper_src/` (deleted), `pyproject.toml`, `scripts/build_bundled_helper_for_wheel.sh`, `scripts/package_release_wheels.sh`, `scripts/run_local_validation.sh`, `scripts/seckit_launchd_smoke.sh`, `.github/workflows/release.yml`, tests, `docs/*`, `setup.cfg`.
- **What changed:** **`--backend icloud` / `icloud-helper`** now **error** with a clear “removed” message. **Native Swift helper**, **wheel bundling**, and **CI bundled-helper job** are **gone**. **`helper status`** returns a **stub JSON** (`helper.removed: true`). Release wheels are **Python-only** (plus `native_helper_bundled/README.md` for layout). Local validation no longer runs SwiftPM.

### 2026-05-04 — Position: `--backend icloud` / `icloud-helper` is unsupported (docs + runtime warning)

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/native_helper.py`, `native_helper_bundled/README.md`, `README.md`, `docs/ICLOUD_SYNC_VALIDATION.md`, `docs/SECURITY_MODEL.md`, `docs/DEFAULTS.md`, `docs/README.md`, `docs/plans/icloud-two-host-checklist.md`, `tests/test_native_helper.py`, `CHANGELOG.md`
- **What changed:** The synchronizable Keychain helper path is documented as **not a supported, reliable feature**; **`--backend secure`** + **export/import** are the supported cross-host story. Resolving **`NativeKeychainStore`** prints a **one-time stderr warning**. **`icloud_backend_error()`** and related docs state the same. Code and wheels may retain the helper for **legacy experimentation** only.

### 2026-05-04 — CI: wheel smoke on every matrix Python; add 3.13 to GitHub matrices

- **Scope:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/GITHUB_RELEASE_BUILD.md`, `scripts/package_release_wheels.sh`, `CHANGELOG.md`
- **What changed:** **`ci`** tests (and **`release`** wheel builds) now include **Python 3.13** alongside **3.9–3.12**. Release **`wheel`** smoke install runs for **each** matrix interpreter so every built wheel is exercised with a matching `python`, not only 3.12. Docs clarify that **PR/push CI** is the full multi-Python matrix; **`release`** **`validate`** stays a single fast job on 3.12.

### 2026-05-03 — v1.2.0 pre-release: `version --json` / `--info`, SIGKILL recovery hint, CI preflight + wheel smoke

- **Scope:** `src/secrets_kit/cli.py`, `src/secrets_kit/native_helper.py`, `src/secrets_kit/native_helper_src/.../main.swift`, `src/secrets_kit/native_helper_bundled/README.md`, `scripts/release_preflight.sh`, `.github/workflows/release.yml`, `docs/GITHUB_RELEASE_BUILD.md`, `tests/test_cli_commands.py`, `tests/test_native_helper.py`, `CHANGELOG.md`
- **What changed:** **`seckit version --json`** and **`--info`** add machine- and human-readable diagnostics (platform, Python, safe defaults subset, helper status) while the default **`seckit version`** line stays a single package version for scripting. **`NativeHelperError`** after helper **SIGKILL** appends a short pointer to **`docs/ICLOUD_SYNC_VALIDATION.md`** and **`--backend secure`** + encrypted export. **`scripts/release_preflight.sh`** runs in the release **`validate`** job on tag **`v*`** to enforce **`pyproject.toml`** **`version`** match (optional **`CHANGELOG.md`** warning). **`wheel`** matrix builds a **`.whl`** per Python; **2026-05-04** extended smoke install to **every** matrix interpreter (was initially **3.12**-only to save minutes). Swift **`getSecret`** best-effort clears the **`Data`** copy holding the password before JSON (documented as **not** a full-memory crypto guarantee).

### 2026-05-03 — Honest iCloud positioning; `.gitignore` `.DS_Store` / `secrets*` / helper `.zip`

- **Scope:** `.gitignore`, `docs/ICLOUD_SYNC_VALIDATION.md`, `README.md`, `docs/SECURITY_MODEL.md`, `docs/plans/icloud-two-host-checklist.md`, `native_helper_bundled/README.md`, `CHANGELOG.md`
- **What changed:** **`**/secrets*`** matched the package directory **`secrets_kit`**, so **`!src/secrets_kit/**`** re-included **everything** under the package—including **`.DS_Store`**—overriding ignore rules. Replaced with **`**/secrets`**, **`**/secrets.*`**, **`**/.secrets`** and **dropped** the broad negation. Ignore **`native_helper_bundled/*.zip`** (artifact only). Docs/README now put **encrypted export/import** first for **cross-host** reliability; **iCloud** backend described as **conditional on the OS running the helper** (Apple **SIGKILL** / **-413** caveat).

### 2026-05-03 — Release hygiene: `.gitignore`, local validation, subprocess `HOME` test

- **Scope:** `.gitignore`, `scripts/run_local_validation.sh`, `tests/test_disposable_keychain_flow.py`, `docs/CROSS_HOST_VALIDATION.md`
- **What changed:** Restored **`!scripts/`** / **`!scripts/**`** under Virtualenv’s `[Ss]cripts` rule so new files under `scripts/` are not ignored. **`run_local_validation.sh`** requires a `PYTHON`/`python3` that can `import yaml` (hint: `pip install -e .`). Disposable-keychain **`seckit run`** test now appends the **real user-site** path to **`PYTHONPATH`** when **`HOME`** is overridden (fixes `ModuleNotFoundError: yaml` with Apple `python3` + `--user` installs). Doc note: **iCloud Drive** file sync vs **iCloud Keychain** + encrypted export path.

### 2026-05-02 — Docs: SIGKILL (-9) and MDM / taskgated / AMFI -413 on managed Macs

- **Scope:** `docs/ICLOUD_SYNC_VALIDATION.md`
- **What changed:** Documented that **`helper was terminated by SIGKILL (-9)`** can be **ManagedClient / taskgated** (*no eligible provisioning profiles*) with **AMFI -413**, which **notarization does not override**; points readers at org IT vs non-managed testing.

### 2026-05-02 — `notarize_bundled_helper.sh`: treat stapler Error 73 as OK for bare Mach-O

- **Scope:** `scripts/notarize_bundled_helper.sh`, `docs/GITHUB_RELEASE_BUILD.md`
- **What changed:** Apple **`stapler`** cannot embed notary tickets in **standalone Mach-O** files (only `.app` / `.dmg` / `.pkg`). **`notarytool` Accepted** still applies; script continues after Error 73 with an explanatory note. Docs clarify online Gatekeeper lookup.

### 2026-05-02 — Restore release scripts + `setup.cfg`

- **Scope:** `scripts/build_bundled_helper_for_wheel.sh`, `scripts/package_release_wheels.sh`, `setup.cfg`, `docs/GITHUB_RELEASE_BUILD.md`
- **What changed:** Re-added maintainer flow: universal helper build → optional notarize/staple → wheels/sdist; `[bdist_wheel] plat_name` for `macosx_13_0_universal2`. Documented in GITHUB release doc.

### 2026-05-02 — Restore `docs/GITHUB_RELEASE_BUILD.md` and `scripts/notarize_bundled_helper.sh`

- **Scope:** docs, scripts, README documentation index
- **What changed:** Re-added release workflow + PyPI notes, notarization / `spctl` / AMFI context, and a standalone `notarize_bundled_helper.sh` (keychain profile, API key, or Apple ID + app-specific password). Linked from README under validation docs.

### 2026-05-02 — v1.1.0 launchd runtime validation and release workflow

- **Scope:** `Secrets-Kit/scripts/`, `Secrets-Kit/docs/`, `Secrets-Kit/tests/`, `Secrets-Kit/.github/workflows/`, `Secrets-Kit/src/secrets_kit/`
- **Category:** `launchd`, `runtime`, `testing`, `documentation`, `release`
- **What changed:**
  - Added a multi-mode launchd smoke workflow for user LaunchAgents, dedicated service-keychain LaunchAgents, and service-keychain LaunchDaemons.
  - Added a standalone `scripts/seckit_launchd_agent_simulator.py` child process so validation proves `seckit run` launches another process with secrets in its environment.
  - Added explicit launchd cleanup verification after normal smoke-test runs.
  - Added CI/local validation and release workflow support for repeatable pre-release checks.
  - Updated launchd, security-model, quickstart, usage, integration, and validation documentation around the supported runtime-launch paths.
- **Why:**
  - Make Secrets Kit release-ready for real agent/service launch workflows where secrets must be injected into child processes without exposing values on the command line.

### 2026-04-18 — Parent-side `seckit run` env injection for child processes

- **Scope:** `Secrets-Kit/src/secrets_kit/cli.py`, `Secrets-Kit/tests/test_cli_commands.py`
- **Category:** `cli`, `integration`, `testing`
- **What changed:**
  - Added `seckit run` so selected or filtered secrets can be resolved in the parent process, injected into a child environment map, and then handed off with `exec`.
  - Added explicit child-command parsing and validation so runtime wrappers can use `seckit run -- <command>` safely from non-interactive launch paths.
  - Added regression coverage to confirm that requested secrets are injected into the child env and that a missing target command fails clearly.
- **Why:**
  - Support application launch workflows that need parent-side secret injection instead of relying on child-side `.env` rereads or shell-eval export patterns.

### 2026-04-16 — Cross-host validation expansion, helper packaging, and backend plumbing follow-through

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `Secrets-Kit/.github/workflows/ci.yml`, `Secrets-Kit/.gitignore`, `Secrets-Kit/pyproject.toml`
- **Category:** `cli`, `native-helper`, `testing`, `documentation`
- **What changed:**
  - Expanded the native-helper packaging and installation groundwork, including helper source layout, helper bridge code, helper-focused tests, and backend-resolution coverage.
  - Added repo-local cross-host validation docs and disposable-keychain oriented test coverage to make transfer and helper flows easier to verify outside a live login-keychain session.
  - Added crypto/helper plumbing and CLI/default handling refinements needed to support the newer export/import and backend-selection paths cleanly.
  - Tightened pre-release docs, examples, defaults, and ignore/CI configuration around those validation workflows.
- **Why:**
  - Make pre-release validation more reproducible and keep the helper-backed backend work coherent enough to test before a broader release.

### 2026-04-15 — Reverted iCloud backend to the single-helper design

- **Update 2026-05-02:** `seckit helper install-icloud` now keeps the single-helper executable model but signs that executable with synchronizable Keychain entitlements instead of acting as an `install-local` alias. Local/ad-hoc entitlement signing was tested and macOS terminates that helper with `SIGKILL`; synchronizable Keychain support therefore requires a project-distributed signed helper or developer validation with an Apple signing identity.

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`
- **Category:** `cli`, `native-helper`, `documentation`
- **What changed:**
  - Removed the separate signed-iCloud-agent discovery and capability model from the Python layer.
  - Restored `backend=icloud` to use the installed `seckit-keychain-helper` directly.
  - Kept `seckit helper install-local` as the ad-hoc local helper path and restored `seckit helper install-icloud` as the entitlement-signing path for synchronizable Keychain validation.
  - Updated the Swift helper so synchronizable reads, deletes, and metadata queries match with `kSecAttrSynchronizableAny`.
  - Removed `kSecUseDataProtectionKeychain` from the helper queries and cleared the helper entitlements plist back to an empty file.
  - Kept helper-backed local operations opt-in via `SECKIT_USE_LOCAL_HELPER=1`, while the default local backend remains the `security` CLI path.
- **Why:**
  - The signed-agent split added complexity and broke the intended single-helper install model.
  - The simpler experiment is to use the existing helper plus synchronizable Keychain APIs before revisiting a heavier app/agent architecture.

### 2026-04-15 — Native helper groundwork, backend selection, and validation flow updates

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/scripts/`, `Secrets-Kit/docs/`
- **Category:** `cli`, `testing`, `documentation`
- **What changed:**
  - Added `--keychain PATH` support across normal data operations, including import, export, explain, doctor, and metadata migration.
  - Added active backend selection via defaults/env/CLI with `local` and `icloud`.
  - Added a SwiftPM-native local helper scaffold plus `seckit helper status`, `seckit helper install-local`, a universal local-helper build for Apple Silicon and Intel, and a signed-agent requirement for `backend=icloud`.
  - Added disposable-keychain integration coverage for direct transfer and locked-destination failure.
  - Replaced the earlier login-keychain SSH validation helpers with disposable-keychain helpers, plus an optional `ssh localhost` transport helper.
  - Reworked the cross-host and iCloud docs to split automated disposable-keychain validation from manual login-keychain and iCloud validation.
  - Added a repo-local validation script and wired CI to use the same CI-safe validation path.
  - Hard-failed unsigned `backend=icloud` usage after confirming Apple entitlement requirements block synchronizable writes from the plain helper.
  - Expanded the checklist to separate automated validation, future helper-install checks, and manual-only login-keychain and iCloud sync work.
- **Why:**
  - Make transfer regression testing stable and automatable without relying on macOS GUI keychain session state.
  - Keep iCloud and login-keychain checks explicit and manual where Apple session behavior controls the outcome.

### 2026-04-14 — Keychain-first metadata, defaults.json, and regression hardening

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `Secrets-Kit/pyproject.toml`
- **Category:** `cli`, `security`, `testing`, `documentation`
- **What changed:**
  - Moved authoritative metadata reads to the keychain item comment, stored as structured JSON.
  - Expanded entry metadata to include schema version, renewal source fields, rotation policy, expiry, domains, and custom metadata.
  - Added `~/.config/seckit/defaults.json` as the persistent defaults file, while keeping legacy config compatibility.
  - Added `seckit migrate metadata` for backfilling older registry-first entries into keychain comment metadata.
  - Added status warnings for rotation and expiry in `list`, `explain`, and `doctor`.
  - Added isolated temporary keychain regression coverage for CRUD plus metadata handling.
  - Added cross-host validation helpers and live markdown checklists for SSH transfer and iCloud sync testing.
  - Aligned package version target to `v1.0.0`.
- **Why:**
  - Reduce host-to-host metadata drift by making the keychain item the primary metadata carrier.
  - Keep inventory and recovery support without relying on the local registry as the source of truth.
  - Prepare the project for manual iCloud sync validation and a tighter `v1.0.0` release.

### 2026-04-13 — Encrypted export, placeholder dotenv, comments

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`, `.pre-commit-config.yaml`
- **Category:** `cli`, `security`, `documentation`
- **What changed:**
  - Added encrypted export/import (`--format encrypted-json`) with optional `cryptography` extra.
  - Added placeholder dotenv export (`--format dotenv`).
  - Added optional metadata `comment` field.
  - Added warn-only pre-commit secret scan hook.
- **Why:**
  - Enable cross-host recovery without plaintext secrets.
  - Provide safe placeholder `.env` generation.
  - Improve metadata clarity and prevent accidental leaks.

### 2026-03-31 — Keychain relock command

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `cli`, `documentation`, `testing`
- **What changed:**
  - Added `seckit lock` as a wrapper around the backend relock flow for the configured macOS keychain.
  - Added backend support for `security lock-keychain`.
  - Added CLI coverage for dry-run and successful keychain relock flows.
  - Documented the normal unlock/lock lifecycle in the README and quickstart docs.
- **Why:**
  - Give operators an explicit, symmetric way to relock the login keychain after a session instead of relying only on timeout policy or external tooling.

### 2026-04-11 — Defaults, examples, and CLI UX polish

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/docs/`, `Secrets-Kit/README.md`
- **Category:** `cli`, `documentation`
- **What changed:**
  - Added CLI defaults via env vars and `~/.config/seckit/config.json` to shorten common commands.
  - Added `seckit explain` for metadata-only inspection.
  - Added `seckit list --stale` for age-based filtering.
  - Expanded docs with integrations, usage, defaults, and runnable examples.
  - Generalized integration guidance beyond OpenClaw.
  - Added macOS GitHub Actions CI matrix and optional pre-commit hooks.
- **Why:**
  - Make Secrets-Kit release-ready for general operators, not just one stack.
  - Reduce friction for day-to-day use without changing the security model.

### 2026-03-12 — Keychain UX and policy visibility

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `runtime`, `documentation`, `integration`
- **What changed:**
  - Added `seckit unlock` as a wrapper around the backend unlock flow, with visible command output and no password capture inside `seckit`.
  - Added `seckit keychain-status` to report keychain accessibility and current lock-policy posture.
  - Added `--version` / `version` and improved command help output.
  - Added optional keychain hardening guidance for long-lived unlocked sessions.
- **Why:**
  - Make keychain interaction clearer and safer for typical operators.
  - Warn users when their macOS keychain posture is too relaxed for long-lived secret access.

### 2026-03-10 — Core hardening, Keychain workflow clarity, and LLM-Ops integration support

- **Scope:** `Secrets-Kit/src/secrets_kit/`, `Secrets-Kit/tests/`, `Secrets-Kit/README.md`, `Secrets-Kit/docs/`
- **Category:** `security`, `runtime`, `documentation`, `integration`
- **What changed:**
  - Added metadata/keychain drift detection to `doctor`.
  - Added a backend helper for checking whether a managed secret exists in Keychain.
  - Added test coverage for doctor drift reporting and command behavior.
  - Clarified the identity model and namespace semantics:
    - `service`
    - `account`
    - `name`
  - Documented the v1 trust model more explicitly:
    - macOS-only backend
    - login Keychain usage
    - unlocked Keychain requirement
    - shell export as runtime handoff
  - Added explicit quickstart guidance for unlocking the login Keychain when macOS blocks interaction.
  - Separated internal planning/security TODO work into `docs/internal/`.
  - Aligned project naming and install docs with the public repo name `Secrets-Kit` while keeping the CLI command as `seckit`.
- **Why:**
  - Make the v1 Keychain-backed workflow understandable and safer to operate.
  - Support optional runtime secret loading from `LLM-Ops-Kit` without pretending this is a generic cross-host secret manager yet.
