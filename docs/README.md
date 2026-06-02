# Secrets Kit documentation

**Created:** 2026-03-10
**Updated:** 2026-05-26

Use this page as the public documentation map. The root [README](../README.md) stays short; day-to-day detail lives here.

- [Secrets Kit documentation](#secrets-kit-documentation)
  - [Operators](#operators)
  - [CLI documentation set](#cli-documentation-set)
  - [Peer sync](#peer-sync)
  - [Testing and CI](#testing-and-ci)
  - [Packaging and maintainers](#packaging-and-maintainers)
  - [Internal public references](#internal-public-references)

## Operators

| Doc | Purpose |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | Shortest path: install, unlock keychain, set/list/run |
| [USAGE.md](USAGE.md) | Entry point + links to CLI docs (minimal examples) |
| [DEFAULTS.md](DEFAULTS.md) | `defaults.json`, env vars, `seckit config` |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | What the tool does and does not protect |
| [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md) | Export/resilience policy, manual uninstall |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Patterns for apps, agents, and runtimes (includes legacy OpenClaw examples) |
| [EXAMPLES.md](EXAMPLES.md) | Small scripts and command snippets |
| [examples/](examples/) | Runnable shell examples |

## CLI documentation set

| Doc | Purpose |
|-----|---------|
| [CONCEPTS.md](CONCEPTS.md) | Operator mental model; resolve vs materialize; compatibility summary |
| [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) | Protected authority handling; inject/export wording; invariants |
| [REMOTE_SECRET_SYNC_ADR.md](REMOTE_SECRET_SYNC_ADR.md) | RSS terminology; peer-authoritative synchronization; optional transport assistance |
| [PACKAGE_VERSION.md](PACKAGE_VERSION.md) | Version authority, unknown sentinel, editable/checkout behavior |
| [DOCSTRING_CONTRACT.md](DOCSTRING_CONTRACT.md) | Contributor expectations for public functions and CLI handlers (S3.5) |
| [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) | Local peer/runtime session semantics |
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | Local IPC and peer-side `seckitd` semantics |
| [RUNTIME_NAMESPACE_ARCHITECTURE.md](RUNTIME_NAMESPACE_ARCHITECTURE.md) | Ephemeral runtime directories, multi-instance namespace, endpoint registry |
| [PROTOCOL_TRANSPORT_ARCHITECTURE.md](PROTOCOL_TRANSPORT_ARCHITECTURE.md) | Transport framing, envelopes, signing, identity layers |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Full command reference |
| [WORKFLOWS.md](WORKFLOWS.md) | Recipes and common operator flows |
| [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) | Authority vs index; `backend-index`; safe output policy |
| [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) | Help style, JSON output stability, error classes |

## Peer Sync

| Doc | Purpose |
|-----|---------|
| [PEER_SYNC.md](PEER_SYNC.md) | Signed encrypted peer bundles; manual transport only |

## Testing And CI

GitHub Actions runs `scripts/run_local_validation.sh` on macOS. For local work, install dev dependencies once (`pip install -e ".[dev]"` in your active Python environment — see [README Contributing](../README.md#contributing)), then use `make` / `make help` for validation targets. Start with `make validate-fast`; use `make validate-full` or `make make-all` when you also want integration and launchd layers. `make lint` requires **ruff** and **basedpyright** from the `dev` optional dependency group in `pyproject.toml`. `make test-keychain` runs the Keychain integration path, `make test-sqlite` runs the SQLite developer-mode integration path, and `make test-integration` runs both. Some tests require interactive Keychain access or PyNaCl; others use SQLite-only harnesses.

## Packaging And Maintainers

| Doc | Purpose |
|-----|---------|
| [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md) | Universal wheel, sdist, GitHub release assets, local packaging checks |

## Internal Public References

| Doc | Purpose |
|-----|---------|
| [SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md](archive/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md) | Historical public rework notes |
| [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md) | Index/tombstone/generation, safe index, authority vs registry |
| [METADATA_REGISTRY.md](METADATA_REGISTRY.md) | Registry schema |
| [SECRET_STORE_CONTRACT.md](SECRET_STORE_CONTRACT.md) | SecretStore behavior and local storage contract |
| [IMPORT_LAYER_RULES.md](IMPORT_LAYER_RULES.md) | Public import/export boundary guidance |

Remote synchronization transport details are intentionally outside this public documentation index.
