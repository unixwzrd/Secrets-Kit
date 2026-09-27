#!/usr/bin/env python3
"""Fail closed when a release candidate changes qualified product inputs.

Run against committed refs before pushing a destination branch. Channel-specific
version and public documentation are deliberately checked by separate gates.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PRODUCT_PATHS = (
    "src/", "tests/", "scripts/", "dependencies/", "integrations/", ".github/workflows/"
)
PRODUCT_FILES = {
    "install.sh", "Makefile", "MANIFEST.in", "requirements.txt", "pytest.ini",
    "pyrightconfig.json", ".pre-commit-config.yaml",
}
NEXT_STAGE = {"dev": "qa", "qa": "beta", "beta": "main"}
VERSION = re.compile(r"^(\d+\.\d+\.\d+)(?:(a|b)(\d+))?$")


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def commit(repo: Path, ref: str) -> str:
    return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()


def tree(repo: Path, ref: str) -> dict[str, tuple[bytes, bytes]]:
    entries: dict[str, tuple[bytes, bytes]] = {}
    for entry in git(repo, "ls-tree", "-r", "-z", "--full-tree", ref).split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        path = name.decode("utf-8", errors="surrogateescape")
        if path in PRODUCT_FILES or path.startswith(PRODUCT_PATHS):
            mode, _kind, object_id = metadata.split(b" ", 2)
            entries[path] = (mode, object_id)
    return entries


def project(repo: Path, ref: str) -> dict:
    data = git(repo, "show", f"{ref}:pyproject.toml")
    return tomllib.loads(data.decode("utf-8"))


def check(
    source_repo: Path, source_ref: str, source_stage: str,
    target_repo: Path, target_ref: str, target_stage: str,
) -> list[str]:
    if NEXT_STAGE.get(source_stage) != target_stage:
        return [f"invalid promotion: {source_stage} -> {target_stage}"]
    source_ref = commit(source_repo, source_ref)
    target_ref = commit(target_repo, target_ref)
    source_tree = tree(source_repo, source_ref)
    target_tree = tree(target_repo, target_ref)
    errors = []
    if not source_tree or not target_tree:
        errors.append("product input tree is empty")
    for path in sorted(source_tree.keys() | target_tree.keys()):
        if source_tree.get(path) != target_tree.get(path):
            errors.append(f"product input differs: {path}")

    source_project = project(source_repo, source_ref)
    target_project = project(target_repo, target_ref)
    source_version = source_project["project"].pop("version")
    target_version = target_project["project"].pop("version")
    if source_project != target_project:
        errors.append("pyproject.toml differs beyond project.version")
    source_match = VERSION.fullmatch(source_version)
    target_match = VERSION.fullmatch(target_version)
    if source_match is None or target_match is None:
        errors.append("invalid project.version")
    else:
        base, kind, number = source_match.groups()
        target_base, target_kind, target_number = target_match.groups()
        if base != target_base:
            errors.append("target changes the base version")
        if source_stage == "dev" and (kind != "a" or target_kind != "b"):
            errors.append("DEV -> QA requires alpha -> beta versions")
        if source_stage == "qa" and (
            kind != "b" or target_kind != "b" or number != target_number
        ):
            errors.append("QA -> public beta requires the same beta version")
        if source_stage == "beta" and (kind != "b" or target_kind is not None):
            errors.append("public beta -> main requires beta -> stable versions")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-stage", choices=NEXT_STAGE, required=True)
    parser.add_argument("--target-repo", type=Path, required=True)
    parser.add_argument("--target-ref", required=True)
    parser.add_argument("--target-stage", choices=("qa", "beta", "main"), required=True)
    args = parser.parse_args()
    try:
        errors = check(
            args.source_repo, args.source_ref, args.source_stage,
            args.target_repo, args.target_ref, args.target_stage,
        )
    except (ValueError, KeyError, OSError) as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"verify-promotion: {error}", file=sys.stderr)
        return 1
    print(f"Verified product inputs: {args.source_stage} {args.source_ref} -> {args.target_stage} {args.target_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
