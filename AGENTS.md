# AGENTS.md — Secrets-Kit

**Created**: 2026-05-02  
**Updated**: 2026-05-09

Guidance for humans and coding agents working in this repository.

## Publishing and git discipline

This project handles **secrets and credentials** (Keychain, encrypted stores, sync). **Broken or careless releases can harm operators**: failed access to secrets, unstable tooling, or worse if behavior around crypto, storage, or trust boundaries is wrong. Treat every public release as **security- and reliability-critical**: verify behavior, run tests, and do not ship work you have not consciously validated.

- **Ship only when it is demonstrably whole.** A known-good release (for example **v1.2.0**) is the bar: new work should reach **tests green**, **CLI smoke OK**, and **operator workflows** you care about before anything is treated as publishable.
- **Local commits are normal; public history is not a scratch pad.** Many incremental or experimental commits are fine **on your machine**. **Do not `git push`** (and do not ask the maintainer to push) until the tree is in a state they are willing to stand behind—half-working snapshots erode trust and create real risk for anyone who installs them.
- **Agents must not push.** Coding agents: **never** run `git push`, change `origin`, or open PRs that imply publishing unless the human **explicitly** asks for that step.
- **Documentation that should not ship:** Draft architecture, internal to-do lists, scratch plans, or personal planning trees may live in the repo during development. Before any push or release, the **maintainer** decides what belongs in the **published** artifact (e.g. relocate, trim, or exclude from the distribution); do not assume every file under `docs/` or `docs/plans/` is intended for end users or PyPI README consumers.
- **Before a push or tag:** Remove or relocate anything that must not ship, squash or reorganize history if desired, bump version and changelog deliberately, and re-run the full test command in [Tests](#tests).

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
