"""
secrets_kit.cli.commands.install_cmd

Operator install, upgrade, and remote SSH wrapper.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path

from secrets_kit.cli.install_check import run_install_check
from secrets_kit.cli.install_constants import DEFAULT_INSTALL_URL
from secrets_kit.cli.io import _fatal


def _repo_install_sh() -> Path | None:
    """Return install.sh next to repo root when running from a checkout."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "install.sh"
        if candidate.is_file() and (parent / "pyproject.toml").is_file():
            return candidate
    return None


def _install_sh_path() -> Path:
    found = _repo_install_sh()
    if found is not None:
        return found
    return Path(__file__).resolve().parents[4] / "install.sh"


def _build_install_sh_argv(*, args: argparse.Namespace) -> list[str]:
    script = _install_sh_path()
    if not script.is_file():
        raise FileNotFoundError(f"install.sh not found: {script}")
    argv = [str(script)]
    if args.ref:
        argv.extend(["--ref", args.ref])
    if args.repo_url:
        argv.extend(["--repo-url", args.repo_url])
    if args.upgrade:
        argv.append("--upgrade")
    if args.yes:
        argv.append("--yes")
    if args.no_init:
        argv.append("--no-init")
    if args.no_verify:
        argv.append("--no-verify")
    if args.dry_run:
        argv.append("--dry-run")
    if args.json:
        argv.append("--json")
    if args.dev:
        argv.append("--dev")
    return argv


def _remote_ssh_command(*, host: str, args: argparse.Namespace) -> list[str]:
    install_url = args.install_url or DEFAULT_INSTALL_URL
    remote_args: list[str] = []
    if args.ref:
        remote_args.extend(["--ref", args.ref])
    if args.upgrade:
        remote_args.append("--upgrade")
    if args.yes:
        remote_args.append("--yes")
    if args.no_init:
        remote_args.append("--no-init")
    if args.no_verify:
        remote_args.append("--no-verify")
    if args.dry_run:
        remote_args.append("--dry-run")

    remote_cmd = f"curl -fsSL {shlex.quote(install_url)} | bash -s --"
    if remote_args:
        remote_cmd += " " + " ".join(shlex.quote(part) for part in remote_args)

    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        host,
        remote_cmd,
    ]


def cmd_install(*, args: argparse.Namespace) -> int:
    if args.remote_host:
        ssh_argv = _remote_ssh_command(host=args.remote_host, args=args)
        if args.dry_run:
            print(" ".join(shlex.quote(part) for part in ssh_argv))
            return 0
        completed = subprocess.run(ssh_argv, check=False)
        return completed.returncode

    if args.upgrade or args.dev or args.ref or args.repo_url:
        try:
            argv = _build_install_sh_argv(args=args)
        except FileNotFoundError as exc:
            return _fatal(message=str(exc), code=1)
        if args.dry_run:
            print(" ".join(shlex.quote(part) for part in argv))
            return 0
        completed = subprocess.run(argv, check=False)
        return completed.returncode

    check = run_install_check()
    print(json.dumps(check, indent=2, sort_keys=True))
    install_url = args.install_url or DEFAULT_INSTALL_URL
    print()
    print("Install:")
    print(f"  curl -fsSL {install_url} | bash")
    print()
    print("Upgrade:")
    print(f"  curl -fsSL {install_url} | bash -s -- --upgrade")
    print()
    print("Remote:")
    print("  seckit install user@host")
    return 0 if check.get("ok") else 1


__all__ = ["cmd_install"]
