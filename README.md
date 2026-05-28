# Secrets Kit

Secrets Kit is a local secrets CLI.  
Default operator workflow is Keychain-first on macOS. Linux currently defaults to SQLite (pre-release behavior).

## Install

See [INSTALL.md](docs/INSTALL.md).

## Quickstart

See [QUICKSTART.md](docs/QUICKSTART.md).

## First Commands

```bash
seckit unlock
echo 'example' | seckit set --name DEMO_KEY --stdin --kind generic --service my-stack --account local-dev
seckit list --service my-stack --account local-dev
seckit run --service my-stack --account local-dev -- python3 app.py
seckit lock
```

## Mental Model

- Secret values live in the backend store (Keychain on macOS).
- `registry.json` is inventory metadata, not secret authority.
- `seckit run` injects secrets into child process environment at runtime.

## Docs

Documentation index: [docs/README.md](docs/README.md)  
Full command reference: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
