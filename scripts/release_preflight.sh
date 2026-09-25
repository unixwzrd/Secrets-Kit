#!/usr/bin/env bash
# Validate local tag/version identity and fail closed on CI release channels.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf 'ERROR: release preflight: %s\n' "$1" >&2
  exit 1
}

project_version() {
  awk '
    /^[[:space:]]*\[/ {
      in_project = ($0 ~ /^[[:space:]]*\[project\][[:space:]]*$/)
    }
    in_project && /^[[:space:]]*version[[:space:]]*=/ {
      value = $0
      sub(/^[[:space:]]*version[[:space:]]*=[[:space:]]*"/, "", value)
      sub(/"[[:space:]]*(#.*)?$/, "", value)
      if (value == $0 || value == "") {
        exit 2
      }
      print value
      found += 1
    }
    END {
      if (found != 1) {
        exit 2
      }
    }
  ' pyproject.toml
}

PYVER="$(project_version)" || fail "could not parse one [project] version from pyproject.toml"
REF="${GITHUB_REF:-}"
if [[ "${GITHUB_ACTIONS:-}" != "true" && -n "${SECKIT_RELEASE_TAG:-}" ]]; then
  REF="refs/tags/${SECKIT_RELEASE_TAG#refs/tags/}"
fi

if [[ "$REF" =~ ^refs/tags/v(.+)$ ]]; then
  TAG="${REF#refs/tags/}"
  VER="${TAG#v}"
  [[ "$VER" == "$PYVER" ]] || fail "git tag '$TAG' (version $VER) does not match pyproject.toml project.version '$PYVER'"
  printf 'OK: tag %s matches pyproject.toml version %s\n' "$TAG" "$PYVER"
  if [[ -f CHANGELOG.md ]] && ! grep -qF "$VER" CHANGELOG.md; then
    printf "WARNING: CHANGELOG.md has no line containing '%s' — update before release if intentional\n" "$VER" >&2
  fi
elif [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  printf 'release_preflight: not a version tag ref (%s); skipping tag/pyproject check.\n' "${REF:-local}"
  exit 0
fi

[[ "${GITHUB_ACTIONS:-}" == "true" ]] || exit 0
command -v jq >/dev/null 2>&1 || fail "jq is required to validate GitHub event metadata"
[[ -n "${GITHUB_EVENT_PATH:-}" && -f "$GITHUB_EVENT_PATH" ]] || fail "GITHUB_EVENT_PATH is missing or unreadable"
[[ -n "${GITHUB_EVENT_NAME:-}" ]] || fail "GITHUB_EVENT_NAME is missing"
[[ -n "${GITHUB_REPOSITORY:-}" ]] || fail "GITHUB_REPOSITORY is missing"
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA is not an exact commit"
[[ "$REF" =~ ^refs/(heads|tags)/[-A-Za-z0-9_./]+$ ]] || fail "GITHUB_REF is missing or unsupported"
HEAD_COMMIT="$(git rev-parse HEAD)" || fail "checkout HEAD does not resolve to a commit"
[[ "$HEAD_COMMIT" == "$GITHUB_SHA" ]] || fail "checkout HEAD does not match GITHUB_SHA"

jq -e '.repository.private | type == "boolean"' "$GITHUB_EVENT_PATH" >/dev/null \
  || fail "event repository privacy metadata is missing or invalid"
EVENT_REPOSITORY="$(jq -er '.repository.full_name | select(type == "string" and test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))' "$GITHUB_EVENT_PATH")" \
  || fail "event repository identity is missing or invalid"
[[ "$EVENT_REPOSITORY" == "$GITHUB_REPOSITORY" ]] || fail "event repository does not match GITHUB_REPOSITORY"
PRIVATE="$(jq -r '.repository.private' "$GITHUB_EVENT_PATH")"
EVENT_REF="$(jq -er '.ref | select(type == "string" and length > 0)' "$GITHUB_EVENT_PATH")" \
  || fail "event ref metadata is missing or invalid"

case "$GITHUB_EVENT_NAME" in
  push)
    [[ "$EVENT_REF" == "$REF" ]] || fail "push event ref does not match GITHUB_REF"
    [[ "$(jq -r '.deleted // false' "$GITHUB_EVENT_PATH")" == "false" ]] || fail "deleted refs cannot produce release artifacts"
    EVENT_AFTER="$(jq -er '.after | select(type == "string" and test("^[0-9a-f]{40}$"))' "$GITHUB_EVENT_PATH")" \
      || fail "push event object metadata is missing or invalid"
    if [[ "$REF" == refs/tags/* ]]; then
      git show-ref --verify --quiet "$REF" || fail "tag ref '$REF' is unavailable in the checkout"
      TAG_OBJECT="$(git rev-parse "$REF")" || fail "tag ref '$REF' does not resolve to an object"
      [[ "$EVENT_AFTER" == "$TAG_OBJECT" ]] || fail "push event object does not match tag ref"
      TAG_COMMIT="$(git rev-parse "$REF^{commit}")" || fail "tag ref '$REF' does not resolve to a commit"
      [[ "$TAG_COMMIT" == "$GITHUB_SHA" ]] || fail "tag commit does not match GITHUB_SHA"
    else
      [[ "$EVENT_AFTER" == "$GITHUB_SHA" ]] || fail "push event commit does not match GITHUB_SHA"
    fi
    ;;
  workflow_dispatch)
    REF_NAME="${REF#refs/heads/}"
    REF_NAME="${REF_NAME#refs/tags/}"
    [[ "$EVENT_REF" == "$REF" || "$EVENT_REF" == "$REF_NAME" ]] \
      || fail "workflow dispatch ref does not match GITHUB_REF"
    ;;
  *)
    fail "unsupported GitHub event '$GITHUB_EVENT_NAME'"
    ;;
esac

is_alpha() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+a[0-9]+$ ]]; }
is_beta() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+b[0-9]+$ ]]; }
is_stable() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

require_tag_source() {
  branch="$1"
  git show-ref --verify --quiet "$REF" || fail "tag ref '$REF' is unavailable in the checkout"
  TAG_COMMIT="$(git rev-parse "$REF^{commit}")" || fail "tag ref '$REF' does not resolve to a commit"
  [[ "$TAG_COMMIT" == "$GITHUB_SHA" ]] || fail "tag commit does not match GITHUB_SHA"
  git show-ref --verify --quiet "refs/remotes/origin/$branch" \
    || fail "origin/$branch is unavailable; checkout full history before preflight"
  git merge-base --is-ancestor "$TAG_COMMIT" "refs/remotes/origin/$branch" \
    || fail "tag commit is not an ancestor of origin/$branch"
}

case "$REF" in
  refs/heads/dev)
    [[ "$PRIVATE" == "true" ]] || fail "dev artifacts require a private repository"
    is_alpha "$PYVER" || fail "dev artifacts require an X.Y.ZaN project version"
    ;;
  refs/heads/qa)
    [[ "$PRIVATE" == "true" ]] || fail "qa artifacts require a private repository"
    is_beta "$PYVER" || fail "qa artifacts require an X.Y.ZbN project version"
    ;;
  refs/heads/beta)
    [[ "$PRIVATE" == "false" ]] || fail "public beta artifacts require a public repository"
    is_beta "$PYVER" || fail "public beta artifacts require an X.Y.ZbN project version"
    ;;
  refs/heads/main)
    [[ "$PRIVATE" == "false" ]] || fail "main artifacts require a public repository"
    is_stable "$PYVER" || fail "main artifacts require an X.Y.Z project version"
    ;;
  refs/heads/*)
    is_alpha "$PYVER" || fail "feature branch artifacts require an X.Y.ZaN project version"
    ;;
  refs/tags/v*)
    if is_alpha "$PYVER"; then
      [[ "$PRIVATE" == "true" ]] || fail "alpha tags require a private repository"
      require_tag_source dev
    elif is_beta "$PYVER"; then
      if [[ "$PRIVATE" == "true" ]]; then
        require_tag_source qa
      else
        require_tag_source beta
      fi
    elif is_stable "$PYVER"; then
      [[ "$PRIVATE" == "false" ]] || fail "stable tags require a public repository"
      require_tag_source main
    else
      fail "tag version must be stable, X.Y.ZaN, or X.Y.ZbN"
    fi
    ;;
  *)
    fail "unsupported CI ref '$REF'"
    ;;
esac

printf 'OK: release channel permits %s at %s (private=%s)\n' "$PYVER" "$REF" "$PRIVATE"
