# Contributing

Use this file for developer workflow only.

## Setup

```bash
bash ./scripts/install_dev_deps.sh
```

## Fast local checks

```bash
make lint
make test-fast
make test-sqlite-unit
```

## Broader validation

```bash
make validate-fast
make validate-full
bash ./scripts/run_local_validation.sh
```

## Documentation ownership

- `README.md`: project overview + install/quickstart links
- `docs/INSTALL.md`: install/upgrade/troubleshooting/flags
- `docs/QUICKSTART.md`: operator unlock/set/list/run/lock flow
- `docs/CLI_REFERENCE.md`: exhaustive command/flag reference
- `docs/DEFAULTS.md`: configuration/defaults reference
- `docs/MAINTAINER_RELEASE.md`: release engineering only
