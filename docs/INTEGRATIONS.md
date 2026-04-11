# Agent & Application Integrations

**Created**: 2026-04-11  
**Updated**: 2026-04-11

Secrets-Kit is not tied to any single stack. The only requirement is a local runtime that can `eval` exported shell variables.

## OpenClaw

Recommended flow:

```bash
eval "$(seckit export --format shell --service openclaw --account miafour --all)"
~/bin/openclaw-stack restart all
```

If you are using LLM-Ops-Kit runtime wrappers:

```bash
cat >> ~/.llm-ops/config.env <<'EOF'
LLMOPS_USE_SECKIT=1
LLMOPS_SECKIT_SERVICE=openclaw
LLMOPS_SECKIT_ACCOUNT=miafour
EOF
```

## Hermes

Recommended flow:

```bash
eval "$(seckit export --format shell --service hermes --account miafour --all)"
~/bin/hermes-stack restart all
```

If you keep separate scopes for environments:

```bash
seckit list --service hermes --account miafour-prod
```

## Any LLM stack

General pattern:

```bash
eval "$(seckit export --format shell --service my-stack --account default --all)"
./start-my-stack.sh
```

If you want shorter commands, define defaults:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=default
```

[Back to README](../README.md)
