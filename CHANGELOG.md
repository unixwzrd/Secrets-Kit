# Secrets-Kit Changelog

**Created**: 2026-03-10  
**Updated**: 2026-05-12

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### 2026-05-12 — Remove stub helper build/notarize scripts

- **Scope:** deleted `scripts/build_bundled_helper_for_wheel.sh`, `scripts/notarize_bundled_helper.sh`; `scripts/run_local_validation.sh`, `scripts/package_release_wheels.sh`, `docs/GITHUB_RELEASE_BUILD.md`, `docs/CROSS_HOST_CHECKLIST.md`, `CHANGELOG.md`.
- **What changed:** Dropped historical **stub** entry points for the removed native helper; **local validation** no longer syntax-checks those files. Release docs/checklist updated so maintainers are not pointed at deleted scripts.

### 2026-05-12 — Phase 6B0: stock-user bootstrap hardening (env contract, cwd-agnostic, fail-fast)

- **Scope:** `scripts/install.sh`, `scripts/bootstrap_peer.sh`, `scripts/reset_peer.sh`, `scripts/bootstrap_vm_smoke.sh`; archived planning notes; `CHANGELOG.md`.
- **What changed:** **`env.sh`** exports **`SECKIT_ENV_FILE`** and **`SECKIT_REPO_ROOT`** so `seckit` and smoke work from **any cwd** after `source`; **python3-first** interpreter selection with optional **Conda** last; **git** / **venv** / **pip** fail-fast messages; **`pip install -e`** no longer silenced; **`mkdir`** without brace expansion; **reset** runtime clear uses **`find -exec rm -rf {} \\;`** (BSD/GNU portable); **`SECKIT_ENV_FILE`** preferred in smoke/reset discovery; scripts resolve **`SCRIPT_DIR`** via **`CDPATH='' cd -- "$(dirname -- "$0")"`**.

### 2026-05-12 — Phase 6B0 + 6B: disposable peer bootstrap and operational validation

- **Scope:** `scripts/install.sh` (thin `exec` wrapper), `scripts/bootstrap_peer.sh` (peer-root layout, Python selection PATH → `CONDA_PREFIX`, `repo/` + `pip install -e`, pinned `--git` + `--branch` / `--ref`, `env.sh` with `HOME` = peer isolation), `scripts/reset_peer.sh`, `scripts/bootstrap_vm_smoke.sh`; archived planning notes; `docs/README.md` links.
- **What changed:** Operator-facing **relocatable peer roots** with explicit venv contract, **no** auto-update / self-update, **manual trust** after `identity init` / public export to `state/public/`; validation notes for restart, duplicate, tombstone, peer transport interruption, SQLite snapshot, stale lineage, diagnosis, convergence, checklist. **Non-goals:** orchestration and fleet CI/CD.

### 2026-05-12 — Phase 6A operational hardening: test helpers, fixtures, verify, smoke docs

- **Scope:** `tests/support/ops_reconcile.py`; `tests/reconciliation/fixtures/*.json`, `test_operational_fixture_replay.py`; `tests/reconciliation/test_sqlite_verify_operational.py`; `sync/sqlite_verify.py` (``secrets_row_locator_collision``, optional ``content_hash_empty_on_active``); `cli` reconcile ``verify --strict-content-hash``; `scripts/replay_import_sequence.py`, `scripts/reconcile_two_db_compare.sh`; peer/local boundary tests; archived planning notes; stabilization tests wired to helpers.
- **What changed:** Mechanical **projection/import** helpers for reconciliation tests; **JSON-driven** deterministic replay fixtures; read-only verify **corruption/info** codes; local IPC tests confirming structured tails and no merge authority; **manual** replay CLI and **two-DB compare** shell; operator docs for primitive multi-peer smoke and authority boundaries.

### 2026-05-12 — Phase 6A stabilization: reasons, trace, reconcile CLI, verify, tests

- **Scope:** `src/secrets_kit/sync/reconcile_reasons.py`, `merge.py` (`merge_explanation_v2`, `explain_incoming_sync_row`, `apply_peer_sync_import` trace), `sync/sqlite_verify.py`, `backends/sqlite.py` (`fetch_entry_reconcile_index`), `cli/commands/reconcile_tools.py`, `cli/parser/base.py`, `cli/commands/sync_bundle.py` (`--reconcile-trace`), `cli/commands/diagnostics.py` (doctor hint); `tests/reconciliation/test_stabilization_*.py`; `docs/PEER_SYNC.md`, `docs/SECURITY_MODEL.md`.
- **What changed:** Semi-stable **`reason`** strings alongside merge **`decision`**; optional **secret-safe** import trace on stderr; **read-only** `seckit reconcile inspect|lineage|explain|verify` (verify is report-only, no repair); SQLite-focused invariant helper; stabilization tests (failure injection rollback, restart-style replay, ordering, convergence).

### 2026-05-12 — Phase 6A test matrix: convergence, canonical record, e2e lineage

- **Scope:** `tests/reconciliation/test_phase6a_convergence.py`, `test_canonical_record.py`; `test_phase6a_merge.py` (rename metadata case); `tests/test_peer_sync_e2e_sqlite.py`; archived planning notes.
- **What changed:** Integration coverage for stale-gen **skip**, **duplicate** echo **unchanged**, **tombstone** replay; canonical hash invariants; merge **rename** decision; e2e bundle with **generation** / **tombstone_generation** on inner entry.

### 2026-05-12 — Phase 6A follow-up: capability flags + hash conflict diagnostics

- **Scope:** `src/secrets_kit/backends/base.py`, `schemas/backend.py`, SQLite/Keychain adapters; `sync/canonical_record.py`, `sync/merge.py`; `docs/PEER_SYNC.md`; tests.
- **What changed:** **`supports_peer_lineage_merge`** / **`supports_reconcile_transaction`** on :class:`BackendCapabilities` (SQLite true, Keychain false). Import stats **`hash_conflict_details`** lists structured wire-hash mismatch evidence (no secrets). **`metadata_stripped_for_peer_hash_verify`** / **`computed_peer_row_content_hash`** helpers.

### 2026-05-11 — Phase 6A: canonical hash, SQLite `content_hash`, transactional apply

- **Scope:** `src/secrets_kit/sync/canonical_record.py`; `src/secrets_kit/sync/merge.py`; `src/secrets_kit/backends/sqlite.py`; `src/secrets_kit/cli/commands/sync_bundle.py`; `tests/reconciliation/`; archived planning notes.
- **What changed:** Top-level **`content_hash`** on bundle rows (export + optional verify); **SHA-256** canonical record; equal-generation **declared hash** divergence → conflict; **entry_id-first** SQLite authority; **rename + set** and **tombstone** applies under **`run_reconcile_transaction`**; import stats **`hash_conflicts`**. Wire verify uses only top-level `content_hash` (not metadata-only); ignores injected sync-origin custom key when hashing.

### 2026-05-05 — Phase 6A (core): peer sync merge ladder, tombstones, replay suppression (SQLite-first)

- **Scope:** `src/secrets_kit/sync/merge.py` (`merge_decision_v2`, bundle row `disposition` / `generation` / `tombstone_generation`); `src/secrets_kit/importers.py` (`ImportCandidate` extended); `src/secrets_kit/models/lineage.py`; `src/secrets_kit/backends/sqlite.py` (`read_lineage_snapshot`, `bump_tombstone_lineage`); `src/secrets_kit/cli/commands/sync_bundle.py` (SQLite export annotates lineage fields); tests under `tests/reconciliation/`.
- **What changed:** Deterministic **tombstone** application when `incoming.tombstone_generation >= local.generation` (SQLite); **replay_suppressed** for stale **active** after local delete; **generation** ordering for active rows when bundle carries lineage; legacy `(updated_at, origin)` merge when lineage fields absent; **entry_id** conflict only in lineage mode. Tombstone delete resolves locator via `entry_id` when the peer metadata renamed. **Non-goals in this slice:** content-hash column, canonical hash module, `BackendStore` transactional apply API, triggers/history tables.

### 2026-05-12 — Phase 5D: local runtime stabilization and SQLite debug tooling

- **Scope:** local `seckitd` runtime files, daemon/diagnostics CLI wiring, SQLite debug support, local runtime tests, `docs/SECURITY_MODEL.md`, `docs/README.md`, and CLI help formatting.
- **What changed:** Optional in-process local transport for tests, bounded-retry coordinator ticker, structured local runtime log lines without payloads, `seckit daemon sync-status`, and `seckit sqlite-inspect`. **`SECKIT_SQLITE_PLAINTEXT_DEBUG`** supports non-production SQLite joint-plaintext rows. **Non-goals:** no daemon merge authority and no `sync/bundle.py` crypto redesign.

### 2026-05-11 — Phase 5C: private hosted transport planning

- **Scope:** private hosted transport planning documents, now separated from the public documentation set.
- **What changed:** Public docs no longer expose private hosted transport architecture. Peer-local authority and bundle behavior remain public.

### 2026-05-10 — Phase 5A: local `seckitd` (Unix socket, no network)

- **Scope:** `src/secrets_kit/seckitd/` (paths, framing, protocol, server, client, subprocess bridge), `seckit daemon …` + `seckitd` script in [pyproject.toml](pyproject.toml); `seckit sync import -` reads stdin; [docs/IMPORT_LAYER_RULES.md](docs/IMPORT_LAYER_RULES.md); [tests/test_seckitd_phase5a.py](tests/test_seckitd_phase5a.py).
- **What changed:** User-scoped Unix socket (0700 runtime dir, 0600 socket), one request per connection, length-prefixed JSON. Local peer/runtime ops include `ping`, `status`, outbound local receipt, and inbound import through `seckit sync import` on stdin. **Non-goals:** no TCP/API/MCP product or hosted sync reconciliation.
- **2026-05-05 follow-up (audit):** Phase 5 plan doc expanded (IPC authority, queue governance, resilience/export framing, future integrity notes, rollback); [docs/README.md](docs/README.md) testing/CI note; framing max-frame + `sync import` stdin parity tests; clearer `OSError` text when `file` is `-`.

### 2026-05-05 — Phase 5B: `seckitd` local hardening (peer creds, IPC redaction, docs)

- **Scope:** `src/secrets_kit/seckitd/peer_cred.py`, `ipc_redact.py`; wire in [`server.py`](src/secrets_kit/seckitd/server.py), [`protocol.py`](src/secrets_kit/seckitd/protocol.py), [`bridge.py`](src/secrets_kit/seckitd/bridge.py); [`docs/OPERATOR_LIFECYCLE.md`](docs/OPERATOR_LIFECYCLE.md), [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md); [`tests/test_seckitd_phase5b.py`](tests/test_seckitd_phase5b.py); `seckit daemon serve` epilog for env vars.
- **What changed:** After `accept()`, Unix stream peers must match daemon **euid** (Linux `SO_PEERCRED`, macOS/BSD `getpeereid`) unless **`SECKITD_INSECURE_SKIP_PEER_CRED=1`** (**unsafe**). Local IPC subprocess tails are redacted by default; **`SECKITD_VERBOSE_IPC=1`** enables verbose tails (**sensitive**). **Non-goals:** no network/MCP product and no `sync/bundle.py` crypto changes.

### 2026-05-05 — Phase 4: enrollment + transport message wrapper (docs, `identity/enrollment`, `sync/envelope`, schemas)

- **Scope:** archived architecture notes; [docs/IMPORT_LAYER_RULES.md](docs/IMPORT_LAYER_RULES.md); `src/secrets_kit/identity/enrollment.py`, `src/secrets_kit/sync/envelope.py`, `src/secrets_kit/schemas/enrollment.py`, `src/secrets_kit/schemas/envelope.py`; [tests/test_phase4_enrollment_envelope.py](tests/test_phase4_enrollment_envelope.py).
- **What changed:** Public enrollment **dict** builders and minimal peer transport message wrapper helpers separate from bundle v1; Pydantic mirrors (`extra="forbid"`, enrollment denylist). **Non-goals:** No daemon/network product, no `sync/bundle.py` crypto/manifest changes, no `correlation_id` or `priority`, no `sync/replay.py` / `sync/routing.py` / `identity/trust.py`.

### 2026-05-05 — Phase 3: model/backend contract stabilization (`schemas/`, inventory, BackendStore doc)

- **Scope:** [docs/BACKEND_STORE_CONTRACT.md](docs/BACKEND_STORE_CONTRACT.md); `pydantic==2.13.2` in [pyproject.toml](pyproject.toml); `src/secrets_kit/schemas/` (`base`, `metadata`, `index`, `backend`, `sync_bundle`, `identity_public`, `runtime` stub); optional `SECKIT_VALIDATE_REGISTRY_METADATA` path in [registry/core.py](src/secrets_kit/registry/core.py); [docs/IMPORT_LAYER_RULES.md](docs/IMPORT_LAYER_RULES.md); tests in [tests/test_schemas_phase3.py](tests/test_schemas_phase3.py).
- **What changed:** Mirror schemas validate dict shapes for tests and drift detection only (`model_dump` is **not** a production emitter). Default registry load behavior is unchanged; strict mirror validation is opt-in via env. Operator-visible JSON, crypto, and persistence formats are unchanged.


- **Scope:** Move `cmd_*` handlers into `src/secrets_kit/cli/commands/*.py`; shared non-domain helpers into `src/secrets_kit/cli/support/*.py` (`defaults`, `interaction`, `args`, `metadata_selection`, `env_exec`, `version_info`, `peer_sync_errors`). Relocate **`_read_metadata`** verbatim to **`src/secrets_kit/registry/resolve.py`**; `sync.merge` and CLI use it—**no** `sync` → `cli` import. **`cli/main.py`** is **`main()`** only (parse, `_apply_defaults`, dispatch). **`cli/parser/base.py`** imports handlers and support symbols explicitly (**no** `cli.main` lazy import). Tests patch/import **defining** modules; add `tests/test_import_layer_guards.py` and `scripts/check_import_cycles.py` + `scripts/import_cycles_baseline.txt`. Update [docs/IMPORT_LAYER_RULES.md](docs/IMPORT_LAYER_RULES.md).
- **What changed:** Operator-visible behavior, flags, JSON shapes, crypto, SQLite schema, registry on-disk format, and bundle formats are unchanged. Monkeypatch paths for moved symbols updated in tests.

### 2026-05-09 — Phase 1: subpackage layout (`models/`, `backends/`, `cli/`, etc.)

- **Scope:** Mechanical `git mv` of flat `src/secrets_kit/*.py` into subpackages; import path updates in `src/`, `tests/`, `docs/METADATA_REGISTRY.md`, `pyproject.toml` (`secrets_kit.cli.main:main`), `scripts/package_release_wheels.sh`, [docs/IMPORT_LAYER_RULES.md](docs/IMPORT_LAYER_RULES.md), `CHANGELOG.md`, `AGENTS.md`.
- **What changed:** Code lives under `secrets_kit/models/core.py`, `registry/core.py`, `identity/core.py`, `backends/*.py`, `cli/main.py`, `utils/helper_status.py` (verbatim from removed `native_helper.py`), `sync/`, `runtime/`, `recovery/`; top-level **`importers.py` unchanged**. **`native_helper.py`** and **`native_helper_bundled/`** removed; **`[tool.setuptools.package-data]`** dropped. Console scripts and **`python -m secrets_kit.cli`** unchanged for operators. Behavior and public symbol names are unchanged aside from module paths.

### 2026-05-08 — Runtime session + IPC semantics ADRs, documentary runtime_ipc

- **Scope:** `docs/RUNTIME_SESSION_ADR.md`, `docs/IPC_SEMANTICS_ADR.md`, `src/secrets_kit/runtime_ipc.py`, `tests/test_runtime_ipc_contract.py`, `docs/RUNTIME_AUTHORITY_ADR.md`, `docs/README.md`, `docs/Secrets-Kit-Glossary-of-Terms.md`, `CHANGELOG.md`.
- **What changed:** Pre-daemon local session semantics (user-scoped local mediator, same-host authority, injection lineage, ephemeral cache, fail-closed restart, and `seckitd` / `seckit` / `BackendStore` roles). IPC ADR covers same-user local IPC, materialization boundaries, minimalist Unix/stream bias, documentary runtime types, envelopes, and error enums — no stable wire protocol. Static contract tests only (repr, naming, enums). Authority ADR links session/IPC docs and clarifies IPC materialization bullets.

### 2026-05-05 — Runtime authority ADR, vocabulary types, stdout/stderr invariant tests

- **Scope:** `docs/RUNTIME_AUTHORITY_ADR.md`, `src/secrets_kit/runtime_authority.py`, `src/secrets_kit/backend_store.py` (`ResolvedEntry` redacting repr + docstrings), `src/secrets_kit/cli_parser.py`, `src/secrets_kit/cli_help.py`, `docs/CONCEPTS.md`, `docs/CLI_ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/WORKFLOWS.md`, `docs/CLI_REFERENCE.md`, `docs/README.md`, `tests/leakage_needles.py`, `tests/test_runtime_authority_invariants.py`, `tests/test_cli_help_consistency.py`, `CHANGELOG.md`.
- **What changed:** Semantics-first documentation for **protected authority handling**, **resolve / materialize / inject / exported**, **resolved-within-handling**, implicit-materialization guard, anti-daemon scope, and non-contract **`RuntimeAccessResult`** / **`RuntimeLease`** placeholders. **`BACKEND_INTERFACE_EXPOSURE`** maps `BackendStore` abstract methods to descriptive exposure levels (drift tests only). **`seckit run --help`** carries the canonical **inject** sentence and **environment inheritance** note. New tests lock **no plaintext on stdout/stderr** for non-materialization CLI paths (SQLite harness) and **`repr(ResolvedEntry)`** redaction.

### 2026-05-07 — CLI UX: modular parser docs, taxonomy help, workflows split

- **Scope:** `src/secrets_kit/cli.py`, new `cli_parser.py`, `cli_help.py`, `cli_groups.py`, `docs/CONCEPTS.md`, `docs/CLI_ARCHITECTURE.md`, `docs/CLI_STYLE_GUIDE.md`, `docs/CLI_REFERENCE.md`, `docs/WORKFLOWS.md`, slimmed `docs/USAGE.md`, `docs/QUICKSTART.md`, `docs/README.md`, root `README.md`, `tests/test_cli_help_consistency.py`, `CHANGELOG.md`.
- **What changed:** Split **`build_parser()`** into **`cli_parser`** with shared **`cli_help`** / **`cli_groups`**; root **`seckit --help`** uses **command taxonomy**, compatibility note, and **JSON/automation** pointer; primary subcommands gain concise **Examples** epilogs (`list` uses **`parents=[common]`** like other scope commands). New operator docs cover **resolve vs materialize**, **`backend-index` semantics**, **safe defaults**, and **CLI style** (JSON stability, error classes, cross-platform wording). **`docs/USAGE.md`** is a short index to the new set; **`WORKFLOWS.md`** adds a **common operator flows** appendix. **`tests/test_cli_help_consistency.py`** asserts taxonomy anchors, **Examples** blocks, and narrow forbidden internals without golden help files.

### 2026-05-07 — BackendStore alignment: `IndexRow`, version triple, `rebuild_index`, `Locator`

- **Scope:** `src/secrets_kit/backend_store.py`, `sqlite_backend.py`, `keychain_backend_store.py`, `models.py`, `cli.py`, `registry_journal.py`, `docs/METADATA_SEMANTICS_ADR.md`, `docs/README.md`, `tests/test_backend_store_contract.py`, `tests/test_leakage_invariants.py`, `tests/leakage_needles.py`, `tests/__init__.py`, `CHANGELOG.md`.
- **What changed:** Safe **`IndexRow`** drops plaintext locator fields from the transport type and adds **`index_schema_version`**, **`payload_schema_version`**, **`backend_impl_version`**, optional opaque **`payload_ref`**, and SQLite corruption flags. **`BackendCapabilities.supports_selective_resolve`**. **`BackendStore.rebuild_index()`** plus optional **`migrate_entry` / `export_authority` / `import_authority`** stubs. SQLite adds **`corrupt`** / **`corrupt_reason` / **`last_validation_at`**, decrypt-free **`iter_index`** column set, and explicit **`BackendStore`** inheritance. Keychain **`iter_index`** uses a **temporary** UUID-from-comment shim (not full JSON parse). CLI:**`seckit rebuild-index`** and **`_read_metadata`** prefers **`resolve_by_locator`**. Registry journal docs state **non-authoritative** operation. Shared contract and leakage tests (incl. **repr**/JSON safe checks).

### 2026-05-05 — CLI: richer `--help`, `defaults` as alias for `config`

- **Scope:** `src/secrets_kit/cli.py`, `tests/test_cli_commands.py`, `CHANGELOG.md`.
- **What changed:** Top-level help uses a formatter that preserves newlines and lists typical `~/.config/seckit/` paths, command groups, and doc pointers. **`config`** documents subcommands (`show` / `set` / `unset` / **`path`**) vs secrets/registry. **`defaults`** is a subcommand alias for **`config`**; **`main()`** skips **`_apply_defaults`** when the invoked command is **`config`** or **`defaults`** so preference edits do not require service defaults. Tests cover the **`defaults`** parse shape (**`args.command` == `"defaults"`**).

### 2026-05-07 — `registry.json` v2 slim index (no operational metadata duplication)

- **Scope:** `src/secrets_kit/registry.py`, `src/secrets_kit/cli.py` (`list`, `_select_entries`), `tests/test_registry_slim.py`, `tests/test_peer_sync_*.py`, `docs/METADATA_REGISTRY.md`, `docs/METADATA_SEMANTICS_ADR.md`, `src/secrets_kit/registry_v2.py` (docstring), `CHANGELOG.md`.
- **What changed:** Registry file **version 2** persists only **locator + `entry_id` + timestamps** and optional **`sync_origin_host`** (peer merge vector); tags, source, URLs, kinds, domains, comments, and other custom keys are **not** written to disk (except that single sync field). **v1** files auto-migrate on load. **v2** entries with extra keys are rejected. **`list`** / **`sync export`** selection filters **type** / **kind** / **tag** against metadata **from the backend** after resolve. Peer bundle tests build inner metadata from **SQLite authority**, not the slim registry row.

### 2026-05-07 — `keychain_dev_seed.sh`: synthetic fixture import for login Keychain

- **Scope:** `scripts/keychain_dev_seed.sh`, `docs/EXAMPLES.md`, `CHANGELOG.md`.
- **What changed:** New helper mirrors **`sqlite_dev_seed.sh`** but runs **`seckit import env --backend secure`** against **`fixtures/synthetic-sample.env`**. Documents **`SECKIT_PYTHON`** when system Python lacks PyNaCl.

### 2026-05-07 — BackendStore alignment: ADR, keychain adapter, leakage tests, journal CLI

- **Scope:** `src/secrets_kit/backend_store.py` (`resolve_backend_store`), `keychain_backend_store.py`, `registry_journal.py`, `sync_merge.py`, `sqlite_backend.py`, `cli.py` (`backend-index`, `journal append`, `doctor` posture for secure), `docs/METADATA_SEMANTICS_ADR.md`, `docs/METADATA_REGISTRY.md`, `docs/SECURITY_MODEL.md`, `tests/test_leakage_invariants.py`, `tests/test_peer_sync_dry_run.py`, `CHANGELOG.md`.
- **What changed:** Documented generation/tombstone/conflict/atomicity in **`docs/METADATA_SEMANTICS_ADR.md`**. **`KeychainBackendStore`** implements **`BackendStore`** with honest posture (metadata in Keychain comments is not encrypted). **`resolve_backend_store`** selects SQLite vs Keychain. SQLite **`set_entry`** preserves caller **`metadata.updated_at`** when set. Peer **`apply_peer_sync_import`** merges registry vs store metadata by stronger **`(updated_at, origin)`** vector. **`seckit backend-index`** emits **`IndexRow`** JSON lines; **`seckit journal append`** writes **`registry_events.jsonl`**. Leakage tests assert sensitive markers stay out of SQLite index columns and **`IndexRow.to_safe_dict()`** payloads.

### 2026-05-06 — Document SQLite path; `scripts/sqlite_dev_seed.sh` for dev vault

- **Scope:** `fixtures/synthetic-sample.env`, `docs/DEFAULTS.md`, `scripts/sqlite_dev_seed.sh`, `src/secrets_kit/cli.py`, `CHANGELOG.md`.
- **What changed:** **`fixtures/synthetic-sample.env`** (tracked) + **`scripts/sqlite_dev_seed.sh`** uses built-in test passphrase **`seckit-dev-synthetic-vault`**; no env required for a normal demo import. Import / migrate **plan:** previews use the same fixed-width table helper as **`seckit list`** (tabs previously broke alignment when **`SOURCE`** held long paths).

### 2026-05-06 — `recover`: SQLite backend, dry-run table / `--json`, launchd temp keychains

- **Scope:** `src/secrets_kit/recover_sources.py`, `src/secrets_kit/sqlite_backend.py` (`iter_secrets_plaintext_index`), `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/cli.py`, `tests/test_cli_commands.py`, `tests/test_sqlite_backend.py`, `tests/test_launchd_run_flow.py`, `docs/METADATA_REGISTRY.md`, `CHANGELOG.md`.
- **What changed:** **`seckit recover`** / **`migrate recover-registry`** support **`--backend sqlite`** (plaintext **`secrets`** index; same metadata JSON as Keychain comments). **`recover_sources.iter_recover_candidates`** centralizes secure vs sqlite enumeration. Human **`--dry-run`** prints a **`seckit list`‑style table** then a JSON summary with **`skipped_bad_names`** (and duplicate / missing-secret keys). **`--json`** prints one machine-readable document including **`recovered_entries`**. Tests: unprotected temp keychains (**`make_temp_keychain(password=""`)**) for launchd agent flows that read secrets non-interactively.

### 2026-05-06 — Recover lost `registry.json` from Keychain (`migrate recover-registry`)

- **Scope:** `src/secrets_kit/keychain_inventory.py`, `src/secrets_kit/cli.py`, `tests/test_keychain_inventory.py`, `tests/test_cli_commands.py`, `docs/METADATA_REGISTRY.md`, `CHANGELOG.md`.
- **What changed:** New **`seckit recover`** rebuilds **`registry.json`** from **`security dump-keychain`** (generic-password rows with seckit **`svce`** `service:name`), with **`--keychain`**, optional **`--service`**, **`--dry-run`**. Reuses comment JSON when it matches the tuple; otherwise writes minimal metadata with **`source`** **`recovered-keychain`**. **`migrate recover-registry`** calls the same handler. **`migrate`** does not global-require **`--service`** for **`recover-registry`** only.

### 2026-05-06 — Legacy `icloud` backend strings: normalize + rewrite operator JSON

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/registry.py`, `src/secrets_kit/cli.py`, `tests/test_backend_resolution.py`, `tests/test_cli_commands.py`, `tests/test_operator_config_migration.py`, `docs/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md`, `docs/DEFAULTS.md`, `CHANGELOG.md`.
- **What changed:** **`normalize_backend`** maps **`icloud`** / **`icloud-helper`** to **`secure`**. When loading **`defaults.json`** or legacy **`config.json`**, those legacy **`backend`** values are rewritten to **`secure`** on disk (when permissions ≤ 0600). **`--backend`** argparse choices unchanged. **`docs/DEFAULTS.md`**: **`seckit list`** uses **`registry.json`**, not a full Keychain dump.

### 2026-05-06 — Stub `notarize_bundled_helper.sh`; drop stale gitignore exception

- **Scope:** `scripts/notarize_bundled_helper.sh`, `scripts/package_release_wheels.sh`, `docs/GITHUB_RELEASE_BUILD.md`, `.gitignore`, `CHANGELOG.md`.
- **What changed:** **`scripts/notarize_bundled_helper.sh`** now matches **`build_bundled_helper_for_wheel.sh`**: it exits with an error (no Mach-O to notarize). Removed obsolete notary pointers from **`package_release_wheels.sh`** comments. **`.gitignore`**: removed dead un-ignore for a deleted plan file; clarified helper section. Runtime **`secrets_kit`** already uses only the **`security`** CLI for **`--backend secure`**; any **`seckit-keychain-helper`** on **`PATH`** is unused by current wheels — remove it locally if old installers dropped it in **`~/bin`** or similar.

### 2026-05-06 — Helper status: drop `helper.removed`; neutral CLI and packaging copy

- **Scope:** `src/secrets_kit/native_helper.py`, `src/secrets_kit/cli.py`, `tests/test_native_helper.py`, `src/secrets_kit/native_helper_bundled/README.md`, `README.md`, `docs/CROSS_HOST_CHECKLIST.md`, `scripts/package_release_wheels.sh`, `tests/test_launchd_run_flow.py`, `docs/LAUNCHD_VALIDATION.md`, `CHANGELOG.md`.
- **What changed:** **`seckit helper status`** / **`version --json`** no longer include **`helper.removed`**. Rely on **`helper.installed`** (false for wheels) plus **`path`** / **`bundled_path`**. Argparse help for **`seckit helper`** and the bundled layout README describe the current model without “removed Swift helper” framing. **Breaking** for JSON consumers that read **`helper.removed`**. Login-keychain launchd test teardown deletes the fixture item only if **`secret_exists`** (clearer failure when **`cmd_set`** cannot write the login keychain from SSH). **`docs/LAUNCHD_VALIDATION.md`**: document that the login-keychain unittest needs a GUI Keychain session (**User interaction is not allowed** over SSH-only).

### 2026-05-06 — Remove iCloud-helper docs and unified unsupported-backend errors

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/native_helper.py`, `tests/test_backend_resolution.py`, `tests/test_cli_commands.py`, `tests/test_native_helper.py`, `scripts/build_bundled_helper_for_wheel.sh`, `scripts/package_release_wheels.sh`, `scripts/seckit_launchd_smoke.sh`, `README.md`, `AGENTS.md`, public docs, deleted `docs/ICLOUD_SYNC_VALIDATION.md`, archived historical planning notes, `CHANGELOG.md`.
- **What changed:** Legacy **`icloud` / `icloud-helper`** ids are rejected like any unknown backend (**`unsupported backend`**)—no dedicated long removal string or doc link. **`seckit helper status`** `backend_availability` now lists only **`secure`**, **`local`**, and **`sqlite`** (breaking change for JSON clients that expected **`icloud`** keys). Removed iCloud-helper validation docs and rewired remaining docs to **secure/sqlite**, export/import, and **peer sync** only.

### 2026-05-06 — Phase 1B: peer identities and signed encrypted sync bundles

- **Scope:** `src/secrets_kit/identity.py`, `peers.py`, `sync_bundle.py`, `sync_merge.py`, `cli.py` (`identity`, `peer`, `sync` subcommands), `tests/test_identity.py`, `tests/test_peers.py`, `tests/test_sync_bundle.py`, `tests/test_sync_merge.py`, `docs/PEER_SYNC.md`, `docs/SECURITY_MODEL.md`, `docs/README.md`, `README.md`, `CHANGELOG.md`.
- **What changed:** Local **Ed25519** (sign) + **X25519** (Box) host identity under `~/.config/seckit/identity/`; **`peers.json`** trust registry; **`seckit.peer_bundle` v1** (PyNaCl-only): canonical signed payload, per-recipient wrapped CEK, SecretBox inner JSON, forward-compatible **`manifest`** extra keys limited to **`x_*`** prefix; deterministic merge on import; **`--domain` / `--domains`** filtering on export and import. **Non-goals:** no network/daemon, no change to SQLite unlock/DEK story beyond normal CLI wiring.

### 2026-05-06 — Phase 1B hardening: E2E tests, dry-run, peer sync CLI errors

- **Scope:** `src/secrets_kit/cli.py` (`_peer_sync_cli_error`), `tests/test_peer_sync_e2e_sqlite.py`, `tests/test_peer_sync_dry_run.py`, `docs/PEER_SYNC.md`, `CHANGELOG.md`.
- **What changed:** Two-HOME **SQLite** end-to-end peer bundle export/verify/import test (plus wrong-recipient case); **dry-run** import tests asserting no DB/registry writes via merge and correct **created/skipped/conflict** counts; **`apply_peer_sync_import`** optional **`home=`** so tests/tooling target ``~/.config/seckit`` without mutating process **`HOME`** (CLI unchanged); **Peer sync:** user-facing error hints (missing identity, unknown peer, wrong recipient/`--signer`, corrupt bundle, SQLite unlock); **PEER_SYNC** walkthrough (two machines, public exchange, scp/rsync, `sync import --dry-run` then `--yes`). Peer sync modules remain **transport-agnostic** (no sockets, daemon, relay, or discovery).

### 2026-05-05 — SQLite unlock providers (`passphrase` vs `keychain`) + launchd coverage

- **Scope:** `src/secrets_kit/sqlite_unlock.py` (new), `sqlite_backend.py`, `keychain_backend.py` (`resolve_secret_store` + `kek_keychain_path`), `cli.py` (`--keychain` allowed with `--backend sqlite`, `_backend_access_kwargs`), `tests/test_sqlite_unlock.py`, `tests/test_launchd_run_flow.py`, `README.md`, `docs/DEFAULTS.md`, `docs/LAUNCHD_VALIDATION.md`, `CHANGELOG.md`.
- **What changed:** SQLite vaults can use **`SECKIT_SQLITE_UNLOCK=passphrase`** (default, legacy Argon2id metadata) or **`keychain`** on macOS: KEK in Keychain wraps the DEK stored in `vault_meta`. **`SECKIT_SQLITE_KEK_KEYCHAIN`** or **`--keychain`** with sqlite selects the KEK keychain file. **`clear_sqlite_crypto_cache`** clears unlock/passphrase/KEK caches. **Launchd:** optional **`SECKIT_RUN_LAUNCHD_SQLITE_TESTS=1`** runs **`test_launch_agent_sqlite_backend_injects_env`**; **`test_launch_agent_backend_secure_explicit_uses_temp_keychain`** asserts **`--backend secure`** under launchd. **`scripts/seckit_launchd_smoke.sh`** remains focused on **`secure`**; sqlite launchd is covered by the Python test.

### 2026-05-06 — Portable encrypted SQLite backend (`--backend sqlite`)

- **Scope:** `src/secrets_kit/sqlite_backend.py`, `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/cli.py`, `src/secrets_kit/native_helper.py`, `pyproject.toml` (PyNaCl), `tests/test_sqlite_backend.py`, `tests/test_backend_resolution.py`, `tests/test_native_helper.py`, `README.md`, `docs/DEFAULTS.md`.
- **What changed:** New **`sqlite`** backend: SQLite file with **Argon2id** KDF and **SecretBox** for secret values; row metadata includes **`updated_at`**, **`crypto_version`**, **`origin_host`**, and optional **`metadata_json`**. CLI **`--db`**, env **`SECKIT_SQLITE_PASSPHRASE`**, **`SECKIT_SQLITE_DB`**, **`SECKIT_ORIGIN_HOST`**, defaults key **`sqlite_db`**. **`doctor`** with **`sqlite`** does not require the macOS **`security`** CLI. **`helper status`** reports **`backend_availability.sqlite`** when PyNaCl imports. **No** sync, relay, or daemon for the DB file.

### 2026-05-05 — Remove Swift iCloud helper: `secure` + `security` CLI only

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/native_helper.py`, `src/secrets_kit/native_helper_src/` (deleted), `pyproject.toml`, `scripts/build_bundled_helper_for_wheel.sh`, `scripts/package_release_wheels.sh`, `scripts/run_local_validation.sh`, `scripts/seckit_launchd_smoke.sh`, `.github/workflows/release.yml`, tests, `docs/*`, `setup.cfg`.
- **What changed:** **`--backend icloud` / `icloud-helper`** now **error** with a clear “removed” message. **Native Swift helper**, **wheel bundling**, and **CI bundled-helper job** are **gone**. **`helper status`** returns a **stub JSON** (`helper.removed: true`). Release wheels are **Python-only** (plus `native_helper_bundled/README.md` for layout). Local validation no longer runs SwiftPM.

### 2026-05-04 — Position: `--backend icloud` / `icloud-helper` is unsupported (docs + runtime warning)

- **Scope:** `src/secrets_kit/keychain_backend.py`, `src/secrets_kit/native_helper.py`, `native_helper_bundled/README.md`, `README.md`, `docs/ICLOUD_SYNC_VALIDATION.md`, `docs/SECURITY_MODEL.md`, `docs/DEFAULTS.md`, `docs/README.md`, archived historical planning notes, `tests/test_native_helper.py`, `CHANGELOG.md`
- **What changed:** The synchronizable Keychain helper path is documented as **not a supported, reliable feature**; **`--backend secure`** + **export/import** are the supported cross-host story. Resolving **`NativeKeychainStore`** prints a **one-time stderr warning**. **`icloud_backend_error()`** and related docs state the same. Code and wheels may retain the helper for **legacy experimentation** only.

### 2026-05-04 — CI: wheel smoke on every matrix Python; add 3.13 to GitHub matrices

- **Scope:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/GITHUB_RELEASE_BUILD.md`, `scripts/package_release_wheels.sh`, `CHANGELOG.md`
- **What changed:** **`ci`** tests (and **`release`** wheel builds) now include **Python 3.13** alongside **3.9–3.12**. Release **`wheel`** smoke install runs for **each** matrix interpreter so every built wheel is exercised with a matching `python`, not only 3.12. Docs clarify that **PR/push CI** is the full multi-Python matrix; **`release`** **`validate`** stays a single fast job on 3.12.

### 2026-05-03 — v1.2.0 pre-release: `version --json` / `--info`, SIGKILL recovery hint, CI preflight + wheel smoke

- **Scope:** `src/secrets_kit/cli.py`, `src/secrets_kit/native_helper.py`, `src/secrets_kit/native_helper_src/.../main.swift`, `src/secrets_kit/native_helper_bundled/README.md`, `scripts/release_preflight.sh`, `.github/workflows/release.yml`, `docs/GITHUB_RELEASE_BUILD.md`, `tests/test_cli_commands.py`, `tests/test_native_helper.py`, `CHANGELOG.md`
- **What changed:** **`seckit version --json`** and **`--info`** add machine- and human-readable diagnostics (platform, Python, safe defaults subset, helper status) while the default **`seckit version`** line stays a single package version for scripting. **`NativeHelperError`** after helper **SIGKILL** appends a short pointer to **`docs/ICLOUD_SYNC_VALIDATION.md`** and **`--backend secure`** + encrypted export. **`scripts/release_preflight.sh`** runs in the release **`validate`** job on tag **`v*`** to enforce **`pyproject.toml`** **`version`** match (optional **`CHANGELOG.md`** warning). **`wheel`** matrix builds a **`.whl`** per Python; **2026-05-04** extended smoke install to **every** matrix interpreter (was initially **3.12**-only to save minutes). Swift **`getSecret`** best-effort clears the **`Data`** copy holding the password before JSON (documented as **not** a full-memory crypto guarantee).

### 2026-05-03 — Honest iCloud positioning; `.gitignore` `.DS_Store` / `secrets*` / helper `.zip`

- **Scope:** `.gitignore`, `docs/ICLOUD_SYNC_VALIDATION.md`, `README.md`, `docs/SECURITY_MODEL.md`, archived historical planning notes, `native_helper_bundled/README.md`, `CHANGELOG.md`
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
