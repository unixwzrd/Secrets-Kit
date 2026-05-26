# Package version semantics

**Created**: 2026-05-05  
**Updated**: 2026-05-05  

## Authoritative version

The **released** package version is defined in `pyproject.toml` (`[project].version`) and exposed at runtime via **installed** distribution metadata (`importlib.metadata.version("seckit")`).

## Checkouts and editable installs

When the `seckit` distribution is **not** installed (for example running with `PYTHONPATH=src` from a bare checkout), `secrets_kit` reports **`0.0.0+unknown`** via :func:`secrets_kit.version_meta.package_version_string`. This is explicit and documented; it replaces the legacy misleading `0.1.0` fallback.

Install the project in editable mode or use a wheel/sdist build when you need the real version string to match `pyproject.toml`.

## Single implementation path

- :func:`~secrets_kit.version_meta.package_version_string` is the canonical reader.
- :data:`secrets_kit.__version__` and :func:`secrets_kit.cli.support.version_info._cli_version` delegate to it.

## Human-facing strings vs JSON

Changing the displayed version string or UNKNOWN sentinel may be user-visible; **`--json` output field names** (e.g. `"version"`) are a separate stability contract and must not change without an ADR.
