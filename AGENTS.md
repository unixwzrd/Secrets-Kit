# AGENTS.md — Secrets-Kit

**Created**: 2026-05-02  
**Updated**: 2026-05-09

Guidance for humans and coding agents working in this repository.

## Environment

- Use the **same Python environment** for development, tests, and tooling as in the IDE (**Command Palette → Python: Select Interpreter**), e.g. Conda **`venvutil`**.
- Some setups wrap **`conda`** and **`pip`** in shell functions (e.g. via `do_wrapper`) to log installs/uninstalls and other venv-changing commands. Prefer a shell where those hooks run when changing dependencies; one-off automation should still target the same interpreter (e.g. `conda run -n venvutil …`) so it matches the selected environment.

## Scope

- Prefer changes that stay aligned with [docs/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md](docs/SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md) and [CHANGELOG.md](CHANGELOG.md).
- macOS **launchd** and login-keychain checks remain partly manual; see [docs/LAUNCHD_VALIDATION.md](docs/LAUNCHD_VALIDATION.md).

## Tests

From the repo root, with the project env active:

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
```

(or `conda run -n venvutil python -m unittest discover -s tests -q` when hooks are non-interactive.)
