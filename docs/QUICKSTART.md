# Quickstart

**Created**: 2026-03-01  
**Updated**: 2026-03-01

## 1) Install

```bash
cd ~/projects/seckit
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
```

Optional YAML file-import support:

```bash
python -m pip install -e '.[yaml]'
```

Deactivate when done:

```bash
deactivate
```

## 2) Store a secret

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service openclaw --account miafour
echo 'hunter2' | seckit set --name ADMIN_PASSWORD --stdin --kind password --service openclaw --account miafour
```

## 3) Verify registry (redacted)

```bash
seckit list --service openclaw --account miafour
```

## 4) Export for current shell

```bash
eval "$(seckit export --format shell --service openclaw --account miafour --all)"
```

[Back to README](../README.md)
