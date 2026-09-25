# Secrets Kit documentation

**Created:** 2026-03-10
**Updated:** 2026-08-20

Use this page as the public documentation map. The root [README](../README.md) stays short; day-to-day detail lives here.

- [Secrets Kit documentation](#secrets-kit-documentation)
  - [Operators](#operators)
  - [CLI And Metadata](#cli-and-metadata)
  - [Development Checks](#development-checks)

## Operators

| Doc                                            | Purpose                                                                     |
| ---------------------------------------------- | --------------------------------------------------------------------------- |
| [QUICKSTART.md](QUICKSTART.md)                 | Shortest path: install, unlock keychain, set/list/run                       |
| [USAGE.md](USAGE.md)                           | Entry point + links to CLI docs (minimal examples)                          |
| [DEFAULTS.md](DEFAULTS.md)                     | `defaults.json`, env vars, `seckit config`                                  |
| [SECURITY_MODEL.md](SECURITY_MODEL.md)         | What the tool does and does not protect                                     |
| [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md) | Export/resilience policy and current/next-RC uninstall contract              |
| [INTEGRATIONS.md](INTEGRATIONS.md)             | Patterns for apps, agents, and runtimes (includes legacy OpenClaw examples) |
| [EXAMPLES.md](EXAMPLES.md)                     | Small scripts and command snippets                                          |
| [examples/](examples/)                         | Runnable shell examples                                                     |

## CLI And Metadata

| Doc                                        | Purpose                                                              |
| ------------------------------------------ | -------------------------------------------------------------------- |
| [CONCEPTS.md](CONCEPTS.md)                 | Operator mental model; resolve vs materialize; compatibility summary |
| [CLI_REFERENCE.md](CLI_REFERENCE.md)       | Full command reference                                               |
| [LOCALIZATION.md](LOCALIZATION.md) | Language selection and adding translations |
| [WORKFLOWS.md](WORKFLOWS.md)               | Recipes and common operator flows                                    |
| [TAXONOMY.md](TAXONOMY.md)                 | Entry types, kinds, and tags                                         |
| [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) | Custom metadata field descriptors                                    |

## Development Checks

GitHub Actions runs `scripts/run_local_validation.sh` on macOS. For local work, install dev dependencies once (`pip install -e ".[dev]"` in your active Python environment — see [README Contributing](../README.md#contributing)), then use `make` / `make help` for validation targets. Start with `make validate-fast`; use `make validate-full` or `make make-all` when you also want integration and launchd layers. `make lint` requires **ruff** and **basedpyright** from the `dev` optional dependency group in `pyproject.toml`. `make test-keychain` runs the Keychain integration path, `make test-sqlite` runs the SQLite integration path, and `make test-integration` runs both. Some tests require interactive Keychain access or PyNaCl; others use SQLite-only harnesses.
