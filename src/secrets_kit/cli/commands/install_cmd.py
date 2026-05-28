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


def _flag(args: argparse.Namespace, name: str) -> bool:
    return bool(getattr(args, name, False))


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
    ref = getattr(args, "ref", None)
    repo_url = getattr(args, "repo_url", None)
    if ref:
        argv.extend(["--ref", ref])
    if repo_url:
        argv.extend(["--repo-url", repo_url])
    if _flag(args, "upgrade"):
        argv.append("--upgrade")
    if _flag(args, "repair"):
        argv.append("--repair")
    if _flag(args, "yes"):
        argv.append("--yes")
    if _flag(args, "no_init"):
        argv.append("--no-init")
    if _flag(args, "no_verify"):
        argv.append("--no-verify")
    if _flag(args, "dry_run"):
        argv.append("--dry-run")
    if _flag(args, "json"):
        argv.append("--json")
    if _flag(args, "verbose"):
        argv.append("--verbose")
    if _flag(args, "safe"):
        argv.append("--safe")
    if _flag(args, "no_shell_profile"):
        argv.append("--no-shell-profile")
    if _flag(args, "shell_profile_force"):
        argv.append("--shell-profile-force")
    if _flag(args, "allow_uv_download"):
        argv.append("--allow-uv-download")
    if _flag(args, "dev"):
        argv.append("--dev")
    return argv


def _remote_ssh_command(*, host: str, args: argparse.Namespace) -> list[str]:
    install_url = getattr(args, "install_url", None) or DEFAULT_INSTALL_URL
    remote_args: list[str] = []
    ref = getattr(args, "ref", None)
    if ref:
        remote_args.extend(["--ref", ref])
    if _flag(args, "upgrade"):
        remote_args.append("--upgrade")
    if _flag(args, "repair"):
        remote_args.append("--repair")
    if _flag(args, "yes"):
        remote_args.append("--yes")
    if _flag(args, "no_init"):
        remote_args.append("--no-init")
    if _flag(args, "no_verify"):
        remote_args.append("--no-verify")
    if _flag(args, "dry_run"):
        remote_args.append("--dry-run")
    if _flag(args, "verbose"):
        remote_args.append("--verbose")
    if _flag(args, "safe"):
        remote_args.append("--safe")
    if _flag(args, "no_shell_profile"):
        remote_args.append("--no-shell-profile")
    if _flag(args, "shell_profile_force"):
        remote_args.append("--shell-profile-force")
    if _flag(args, "allow_uv_download"):
        remote_args.append("--allow-uv-download")

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
    remote_host = getattr(args, "remote_host", None)
    if remote_host:
        ssh_argv = _remote_ssh_command(host=remote_host, args=args)
        if _flag(args, "dry_run"):
            print(" ".join(shlex.quote(part) for part in ssh_argv))
            return 0
        completed = subprocess.run(ssh_argv, check=False)
        return completed.returncode

    if (
        _flag(args, "upgrade")
        or _flag(args, "repair")
        or _flag(args, "dev")
        or bool(getattr(args, "ref", None))
        or bool(getattr(args, "repo_url", None))
        or _flag(args, "yes")
        or _flag(args, "no_init")
        or _flag(args, "no_verify")
        or _flag(args, "dry_run")
        or _flag(args, "json")
        or _flag(args, "verbose")
        or _flag(args, "safe")
        or _flag(args, "no_shell_profile")
        or _flag(args, "shell_profile_force")
        or _flag(args, "allow_uv_download")
    ):
        try:
            argv = _build_install_sh_argv(args=args)
        except FileNotFoundError as exc:
            return _fatal(message=str(exc), code=1)
        if _flag(args, "dry_run"):
            print(" ".join(shlex.quote(part) for part in argv))
            return 0
        completed = subprocess.run(argv, check=False)
        return completed.returncode

    check = run_install_check()
    print(json.dumps(check, indent=2, sort_keys=True))
    install_url = getattr(args, "install_url", None) or DEFAULT_INSTALL_URL
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
