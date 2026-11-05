> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# Usage

**Created**: 2026-03-10

**Updated**: 2026-07-12

Status: Redirect entry point. Prefer [QUICKSTART.md](QUICKSTART.md) for the shortest operator path and [CLI_REFERENCE.md](CLI_REFERENCE.md) for complete command coverage.

This file is retained for older links. Full command coverage and policies live in the split CLI docs:

| Doc                                        | Use it for                                                      |
| ------------------------------------------ | --------------------------------------------------------------- |
| [CLI_REFERENCE.md](CLI_REFERENCE.md)       | All `seckit` subcommands in taxonomy order                      |
| [WORKFLOWS.md](WORKFLOWS.md)               | Recipes and **common operator flows** appendix                  |
| [CONCEPTS.md](CONCEPTS.md)                 | Mental model, resolve vs **materialize**, compatibility summary |
| [QUICKSTART.md](QUICKSTART.md)             | Shortest install/set/list/run path                       |
| [TAXONOMY.md](TAXONOMY.md)                 | Entry types, kinds, tags (`seckit taxonomy`)                    |
| [METADATA_SCHEMAS.md](METADATA_SCHEMAS.md) | Custom field descriptors (`seckit schema`)                      |

## Minimal examples

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
seckit list --service my-stack --account local-dev
seckit get --name OPENAI_API_KEY --service my-stack --account local-dev
seckit run --service my-stack --account local-dev -- python3 app.py
```

**Elevated disclosure:** `get --raw`, `export`, and `run` **materialize** secrets outside default redaction—see [CONCEPTS.md](CONCEPTS.md).

Operator defaults (`defaults.json`): [DEFAULTS.md](DEFAULTS.md) and `seckit config --help`.
