# Quickstart

**Updated**: 2026-05-27

Install first: [INSTALL.md](INSTALL.md)

## 1) Unlock

```bash
seckit unlock
```

## 2) Set

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
echo 'hunter2' | seckit set --name ADMIN_PASSWORD --stdin --kind password --service my-stack --account local-dev
```

## 3) List

```bash
seckit list --service my-stack --account local-dev
```

## 4) Run

```bash
seckit run --service my-stack --account local-dev -- python3 app.py
```

## 5) Lock

```bash
seckit lock
```

Next: [DEFAULTS.md](DEFAULTS.md) · [CLI_REFERENCE.md](CLI_REFERENCE.md)
