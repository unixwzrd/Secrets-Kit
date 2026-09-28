#!/usr/bin/env python3
"""Verify installed candidate or exact tagged-asset qualification.

The evidence file is operator-controlled and stays outside the release tree. It
binds observed checks to the branch artifact that was installed, not merely to
source CI. A candidate gate precedes the tag; the tagged-asset gate precedes
tester handoff. Neither substitutes for reviewing the retained observations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


REQUIRED_CANDIDATE = {
    "dev": ("artifact_verified", "installed_health", "installed_sync"),
    "qa": ("artifact_verified", "installed_health", "installed_sync", "preserving_upgrade"),
    "beta": ("artifact_verified", "installed_health", "installed_sync", "qa_tag_customer_workflow"),
    "main": ("artifact_verified", "production_code_review", "beta_tag_customer_workflow"),
}
REQUIRED_TAGGED = {
    "dev": ("artifact_verified", "installed_health"),
    "qa": ("artifact_verified", "installed_health", "ssh_install_user_host",
           "ssh_install_at_host", "fresh_peer_authorization", "preserving_reinstall"),
    "beta": ("artifact_verified", "fresh_first_machine", "ssh_install_user_host",
             "ssh_install_at_host", "fresh_peer_authorization", "bidirectional_sync",
             "preserving_reinstall"),
    "main": ("artifact_verified", "installed_health", "production_code_review"),
}
REPOSITORIES = {"private": "unixwzrd/Secrets-Kit-Private", "public": "unixwzrd/Secrets-Kit"}


def verify(path: Path, *, version: str, channel: str, repository: str,
           commit: str, phase: str = "candidate") -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("qualification evidence must be an existing regular file")
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if evidence.get("schema") != 1:
        raise ValueError("unsupported qualification evidence schema")
    artifact = evidence.get("artifact")
    if not isinstance(artifact, dict):
        raise ValueError("missing qualified artifact")
    directory = Path(artifact.get("directory", ""))
    if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink():
        raise ValueError("qualified artifact directory must be an existing absolute path")
    installer = directory / "install.sh"
    if not installer.is_file() or installer.is_symlink():
        raise ValueError("qualified installer is absent or a symlink")
    manifest = directory / "manifest.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        raise ValueError("qualified artifact manifest is absent or a symlink")
    verified = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_+.-]+)", line)
        if match is None or match.group(2) in verified:
            raise ValueError("qualified artifact manifest has an invalid or duplicate entry")
        expected_digest, name = match.groups()
        member = directory / name
        if not member.is_file() or member.is_symlink():
            raise ValueError(f"qualified artifact manifest member is absent or a symlink: {name}")
        if hashlib.sha256(member.read_bytes()).hexdigest() != expected_digest:
            raise ValueError(f"qualified artifact manifest digest mismatch: {name}")
        verified.add(name)
    if not {"install.sh", "release-origin.json"}.issubset(verified):
        raise ValueError("qualified artifact manifest omits installer or origin")
    origin = json.loads((directory / "release-origin.json").read_text(encoding="utf-8"))
    source_ref = f"refs/heads/{channel}" if phase == "candidate" else f"refs/tags/v{version}"
    release_channel = "prerelease" if re.search(r"(?:a|b)[0-9]+$", version) else "release"
    install_ref = commit if phase == "candidate" else f"v{version}"
    expected_origin = {"repository": REPOSITORIES[repository], "source_ref": source_ref,
                       "source_commit": commit, "install_ref": install_ref,
                       "version": version, "channel": release_channel}
    for field, value in expected_origin.items():
        if origin.get(field) != value:
            raise ValueError(f"artifact origin {field} does not match this candidate")
    checks = evidence.get("checks")
    if not isinstance(checks, dict):
        raise ValueError("missing installed qualification checks")
    required = REQUIRED_CANDIDATE if phase == "candidate" else REQUIRED_TAGGED
    for name in required[channel]:
        result = checks.get(name)
        if not isinstance(result, dict) or result.get("result") != "PASS":
            raise ValueError(f"required installed qualification is not PASS: {name}")
        log = result.get("evidence")
        if (not isinstance(log, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", log)
                or any(part in {".", ".."} for part in Path(log).parts)):
            raise ValueError(f"invalid retained evidence path for: {name}")
        log_path = path.parent / log
        if not log_path.is_file() or log_path.is_symlink():
            raise ValueError(f"missing retained evidence for: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--channel", choices=REQUIRED_CANDIDATE, required=True)
    parser.add_argument("--repository", choices=REPOSITORIES, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--phase", choices=("candidate", "tagged"), default="candidate")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("commit must be a full Git SHA-1")
    try:
        verify(args.evidence, version=args.version, channel=args.channel,
               repository=args.repository, commit=args.commit, phase=args.phase)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"verify-release-qualification: {exc}", file=sys.stderr)
        return 1
    print(f"Verified installed {args.channel} {args.phase} qualification for v{args.version} at {args.commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
