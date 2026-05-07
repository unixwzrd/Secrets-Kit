# Usage

**Created**: 2026-03-10  
**Updated**: 2026-05-07

This file is a **short entry point**. Full command coverage and policies live in the split CLI docs:

| Doc | Use it for |
|-----|------------|
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | All `seckit` subcommands in taxonomy order |
| [WORKFLOWS.md](WORKFLOWS.md) | Recipes and **common operator flows** appendix |
| [CONCEPTS.md](CONCEPTS.md) | Mental model, resolve vs **materialize**, compatibility summary |
| [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) | Authority, safe index, `backend-index`, `list` semantics |
| [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) | Help conventions, **JSON stability**, error classes |
| [QUICKSTART.md](QUICKSTART.md) | Shortest install/unlock/set/list/run path |

## Minimal examples

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
seckit list --service my-stack --account local-dev
seckit get --name OPENAI_API_KEY --service my-stack --account local-dev
seckit run --service my-stack --account local-dev -- python3 app.py
```

**Elevated disclosure:** `get --raw`, `export`, and `run` **materialize** secrets outside default redaction—see [CONCEPTS.md](CONCEPTS.md).

Operator defaults (`defaults.json`): [DEFAULTS.md](DEFAULTS.md) and `seckit config --help`.
