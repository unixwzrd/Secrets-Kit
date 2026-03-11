# OpenClaw Integration

**Created**: 2026-03-01  
**Updated**: 2026-03-01

## Recommended flow

```bash
eval "$(seckit export --format shell --service openclaw --account miafour --all)"
~/bin/openclaw-stack restart all
```

For `LLM-Ops-Kit`, the preferred runtime integration is now:

```bash
cat >> ~/.llm-ops/config.env <<'EOF'
LLMOPS_USE_SECKIT=1
LLMOPS_SECKIT_SERVICE=openclaw
LLMOPS_SECKIT_ACCOUNT=miafour
EOF
```

Then start `gateway`, `model-proxy`, or `tts-bridge` normally. The shared runtime loader will import `seckit` exports during startup.

## Migration from dotenv

```bash
seckit migrate dotenv --dotenv ~/.openclaw/.env --service openclaw --account miafour --yes --archive ~/.openclaw/.env.bak
```

This imports values into Keychain and rewrites `.env` values to `${VAR}` placeholders.

[Back to README](../README.md)
