#!/usr/bin/env bash
# Select the build-time operator URL from the CI repository/ref, never the host.
set -euo pipefail

repository="${GITHUB_REPOSITORY:-}"
ref="${GITHUB_REF:-}"
case "$repository:$ref" in
  unixwzrd/Secrets-Kit-Private:refs/heads/dev) channel=dev ;;
  unixwzrd/Secrets-Kit-Private:refs/heads/qa) channel=qa ;;
  unixwzrd/Secrets-Kit:refs/heads/beta) channel=beta ;;
  unixwzrd/Secrets-Kit:refs/heads/main) channel=production ;;
  *)
    if [[ "$repository" == "unixwzrd/Secrets-Kit-Private" && "$ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+a[0-9]+$ ]]; then
      channel=dev
    elif [[ "$repository" == "unixwzrd/Secrets-Kit-Private" && "$ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+b[0-9]+$ ]]; then
      channel=qa
    elif [[ "$repository" == "unixwzrd/Secrets-Kit" && "$ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+b[0-9]+$ ]]; then
      channel=beta
    elif [[ "$repository" == "unixwzrd/Secrets-Kit" && "$ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      channel=production
    else
      printf 'Unsupported release repository/ref: %s:%s\n' "$repository" "$ref" >&2
      exit 1
    fi
    ;;
esac

case "$channel" in
  dev) url="${RSS_OPERATOR_URL_DEV:-}" ;;
  qa) url="${RSS_OPERATOR_URL_QA:-}" ;;
  beta) url="${RSS_OPERATOR_URL_BETA:-}" ;;
  production) url="${RSS_OPERATOR_URL_PRODUCTION:-}" ;;
esac
[[ -n "$url" ]] || { printf 'Missing RSS operator URL for %s\n' "$channel" >&2; exit 1; }
printf '%s\n' "$url"
