#!/usr/bin/env bash
# Derive release metadata from pyproject.toml and publish only after qualification.
# --sync-metadata updates only current public-beta README installer links.
# --push-branch triggers one branch CI run; --publish requires its exact SHA to
# pass before pushing an immutable annotated tag. --publish also verifies the
# exact branch artifact and retained installed-qualification evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { printf 'prepare-release-tag: %s\n' "$*" >&2; exit 1; }

mode="${1:---check}"
[[ "$mode" == "--sync-metadata" || "$mode" == "--check" || "$mode" == "--push-branch" || "$mode" == "--publish" || "$mode" == "--verify-tag" ]] \
  || die "usage: scripts/prepare-release-tag.sh [--sync-metadata|--check|--push-branch|--publish EVIDENCE.json|--verify-tag EVIDENCE.json]"
[[ $# -le 2 ]] || die "usage: scripts/prepare-release-tag.sh [--sync-metadata|--check|--push-branch|--publish EVIDENCE.json|--verify-tag EVIDENCE.json]"
if [[ "$mode" == "--publish" || "$mode" == "--verify-tag" ]]; then
  [[ $# -eq 2 ]] || die "$mode requires an installed qualification evidence file"
else
  [[ $# -le 1 ]] || die "only --publish and --verify-tag accept an evidence file"
fi

version="$(python3 -c 'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')" \
  || die "cannot read project.version from pyproject.toml"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b)[0-9]+)?$ ]] \
  || die "unsupported project version: $version"
tag="v$version"
branch="$(git symbolic-ref --quiet --short HEAD)" || die "a release tag requires a branch checkout"
origin="$(git remote get-url origin)" || die "origin is unavailable"
case "$origin" in
  "https://github.com/unixwzrd/Secrets-Kit-Private"|"https://github.com/unixwzrd/Secrets-Kit-Private.git"|\
  "git@github.com:unixwzrd/Secrets-Kit-Private"|"git@github.com:unixwzrd/Secrets-Kit-Private.git"|\
  "ssh://git@github.com/unixwzrd/Secrets-Kit-Private"|"ssh://git@github.com/unixwzrd/Secrets-Kit-Private.git"|\
  /*/Secrets-Kit-Private.git) repository=private ;;
  "https://github.com/unixwzrd/Secrets-Kit"|"https://github.com/unixwzrd/Secrets-Kit.git"|\
  "git@github.com:unixwzrd/Secrets-Kit"|"git@github.com:unixwzrd/Secrets-Kit.git"|\
  "ssh://git@github.com/unixwzrd/Secrets-Kit"|"ssh://git@github.com/unixwzrd/Secrets-Kit.git"|\
  /*/Secrets-Kit.git) repository=public ;;
  *) die "unrecognized release origin: $origin" ;;
esac
case "$version:$repository" in
  *a[0-9]*:private) channel=dev ;;
  *b[0-9]*:private) channel=qa ;;
  *b[0-9]*:public) channel=beta ;;
  *a[0-9]*:public) die "$tag cannot be released from the public repository" ;;
  *:public) channel=main ;;
  *) die "$tag cannot be released from the $repository repository" ;;
esac
case "$branch" in
  "$channel"|"$channel"-*) ;;
  *) die "$tag belongs on the $channel candidate branch, not $branch" ;;
esac
grep -Eq "^## ${version}([[:space:]]|$)" CHANGELOG.md \
  || die "CHANGELOG.md needs a $version release heading"
if [[ "$mode" == "--sync-metadata" ]]; then
  if [[ "$channel" == "beta" ]]; then
    python3 scripts/sync-release-metadata.py "$tag"
  else
    printf 'No derived README version fields for %s; changelog heading verified.\n' "$channel"
  fi
  exit 0
fi
[[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "tracked working tree is not clean"

# A public beta README describes an immutable installer, not the private
# channel's independent version. Check only the three current-release links;
# historical references and the frozen tester guide are never rewritten here.
if [[ "$channel" == "beta" ]]; then
  grep -Fq "For the current public beta (\`$tag\`)" README.md \
    || die "README.md current public beta must name $tag"
  [[ "$(grep -Fc "/releases/download/$tag/install.sh" README.md)" -eq 2 ]] \
    || die "README.md must contain curl and wget links for $tag"
fi

head_commit="$(git rev-parse HEAD)"
remote_commit="$(git ls-remote --heads origin "$channel" | awk '{print $1}')" \
  || die "cannot verify origin/$channel"
[[ -n "$remote_commit" ]] || die "origin/$channel is missing"
if [[ "$mode" == "--push-branch" ]]; then
  git merge-base --is-ancestor "$remote_commit" "$head_commit" \
    || die "HEAD is not a fast-forward of origin/$channel"
  git push origin "HEAD:refs/heads/$channel"
  printf 'Pushed %s at %s; wait for exact-commit CI and installed qualification before --publish.\n' "$channel" "$head_commit"
  exit 0
fi
[[ "$head_commit" == "$remote_commit" ]] \
  || die "HEAD differs from origin/$channel; push and qualify the branch first"
remote_tag="$(git ls-remote --refs --tags origin "refs/tags/$tag")" \
  || die "cannot verify remote tag $tag"
if [[ "$mode" == "--verify-tag" ]]; then
  [[ -n "$remote_tag" ]] || die "$tag has not been published"
else
  [[ -z "$remote_tag" ]] || die "$tag already exists on origin"
fi

local_tag_exists=false
if git show-ref --verify --quiet "refs/tags/$tag"; then
  [[ "$mode" == "--publish" || "$mode" == "--verify-tag" ]] || die "$tag already exists locally"
  [[ "$(git rev-parse "refs/tags/$tag^{commit}")" == "$head_commit" ]] \
    || die "local $tag does not point at HEAD"
  [[ "$(git cat-file -t "refs/tags/$tag")" == "tag" ]] \
    || die "local $tag is not annotated"
  local_tag_exists=true
fi
if [[ "$mode" == "--verify-tag" ]]; then
  [[ "$local_tag_exists" == true ]] || die "local annotated $tag is missing"
  [[ "${remote_tag%%$'\t'*}" == "$(git rev-parse "refs/tags/$tag")" ]] \
    || die "remote $tag differs from the local annotated tag"
fi

printf 'Verified %s at %s on origin/%s\n' "$tag" "$head_commit" "$channel"
if [[ "$mode" == "--publish" ]]; then
  python3 scripts/verify-release-qualification.py --evidence "$2" \
    --version "$version" --channel "$channel" --repository "$repository" --commit "$head_commit" \
    || die "exact-artifact installed qualification is missing or failed; do not publish"
  command -v gh >/dev/null 2>&1 || die "gh is required to verify exact-commit CI"
  command -v jq >/dev/null 2>&1 || die "jq is required to verify exact-commit CI"
  runs="$(gh run list --workflow ci.yml --branch "$channel" --commit "$head_commit" --json headSha,conclusion,event --limit 20)" \
    || die "cannot inspect CI for $head_commit"
  jq -e --arg sha "$head_commit" 'any(.[]; .headSha == $sha and .conclusion == "success" and .event == "push")' <<< "$runs" >/dev/null \
    || die "no successful branch-push CI for $head_commit; do not publish"
  if [[ "$local_tag_exists" == false ]]; then
    git tag -a "$tag" -m "Secrets Kit $tag"
  fi
  git push origin "refs/tags/$tag"
  printf 'Published %s at %s; verify the tag-triggered release artifacts before handoff.\n' "$tag" "$head_commit"
elif [[ "$mode" == "--verify-tag" ]]; then
  python3 scripts/verify-release-qualification.py --phase tagged --evidence "$2" \
    --version "$version" --channel "$channel" --repository "$repository" --commit "$head_commit" \
    || die "tagged-asset qualification is missing or failed; do not hand off"
  printf 'Qualified tagged assets for %s at %s; review the exact tester guide before handoff.\n' "$tag" "$head_commit"
fi
