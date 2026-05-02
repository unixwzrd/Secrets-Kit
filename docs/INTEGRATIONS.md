# Integrations

- [Integrations](#integrations)
  - [Generic local stack](#generic-local-stack)
  - [Local UI or web application](#local-ui-or-web-application)
  - [Agent runtime or automation script](#agent-runtime-or-automation-script)
  - [Hermes example](#hermes-example)
  - [OpenClaw example](#openclaw-example)
  - [What not to assume](#what-not-to-assume)
  - [Back to README](#back-to-readme)

Secrets Kit is not tied to one framework, agent, or stack. The preferred process-launch pattern is simple:

1. keep the values in Keychain
2. run the target process through `seckit run`
3. let the child process inherit only the selected environment variables

If a tool can read environment variables from the shell that launches it, it can work with Secrets Kit.

## Generic local stack

```bash
seckit run --service my-stack --account local-dev -- ./start-my-stack.sh
```

If you run that stack often, define defaults first:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
```

Then the handoff becomes shorter:

```bash
seckit run -- ./start-my-stack.sh
```

## Local UI or web application

```bash
seckit run --service my-ui -- npm run dev
```

This is a good fit when a development server expects tokens or API keys in the current shell but you do not want them sitting in a checked-in `.env` file.

## Agent runtime or automation script

```bash
seckit run --service agents --account local-dev -- ./run-agents.sh
```

That model works for local agent runners, orchestrators, and shell-based automation that load credentials from environment variables at startup.

## Hermes example

```bash
seckit run --service hermes --account local-dev -- ~/bin/hermes-stack restart all
```

If you keep separate environments, use separate scopes:

```bash
seckit list --service hermes --account prod
```

## OpenClaw example

```bash
seckit run --service openclaw --account local-dev -- ~/bin/openclaw-stack restart all
```

If you need to create a new service scope from an existing one:

```bash
seckit service copy --from-service openclaw --to-service hermes --dry-run
seckit service copy --from-service openclaw --to-service hermes
```

If you use wrappers that already know how to pull from Secrets Kit, keep those wrappers as the integration point and let them handle `run` during startup.

## What not to assume

Secrets Kit does not change the security model of the runtime you start afterward. Once a process inherits secrets in its environment, that process can access what it needs to access. Secrets Kit is about reducing secret sprawl and improving local hygiene, not about creating a hardened isolation boundary around every downstream tool.

## [Back to README](../README.md)

**Created**: 2026-04-11  
**Updated**: 2026-04-12
