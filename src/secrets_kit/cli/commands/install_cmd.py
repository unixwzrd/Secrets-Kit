"""
secrets_kit.cli.commands.install_cmd

Operator install, upgrade, and remote SSH wrapper.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
from pathlib import Path

from secrets_kit import __version__
from secrets_kit.cli.install_check import run_install_check
from secrets_kit.cli.install_constants import DEFAULT_INSTALL_URL


def _flag(args: argparse.Namespace, name: str) -> bool:
    return bool(getattr(args, name, False))


def _local_ssh_username() -> str:
    for key in ("USER", "LOGNAME"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return getpass.getuser()


class InstallTargetError(ValueError):
    """Invalid remote install SSH target."""


def _normalize_ssh_target(target: str) -> str:
    """Return user@host for SSH.

    ``@host`` uses the local ``$USER``; ``user@host`` keeps an explicit user.
    A bare hostname is rejected so ``@`` always marks a remote install.
    """
    trimmed = target.strip()
    if not trimmed:
        return trimmed
    if trimmed.startswith("@"):
        host_part = trimmed[1:].strip()
        if not host_part:
            raise InstallTargetError("remote target is empty after '@'")
        if "@" in host_part:
            raise InstallTargetError("use user@host or @host (not @user@host)")
        return f"{_local_ssh_username()}@{host_part}"
    if "@" in trimmed:
        user, _, host = trimmed.partition("@")
        if not user or not host:
            raise InstallTargetError("use user@host or @host")
        return trimmed
    raise InstallTargetError(
        f"remote install requires '@' in the target (try @{trimmed} or user@{trimmed})"
    )


def _prepare_remote_install(*, args: argparse.Namespace) -> str | None:
    """Normalize SSH target and default to non-interactive remote install."""
    raw = getattr(args, "remote_host", None)
    if not raw:
        return None
    try:
        host = _normalize_ssh_target(raw)
    except InstallTargetError as exc:
        raise SystemExit(f"seckit install: error: {exc}") from exc
    args.remote_host = host
    if not _flag(args, "yes"):
        args.yes = True
    return host


def _current_ref() -> str:
    return f"v{__version__}"

def _effective_ref(*, args: argparse.Namespace, for_remote: bool = False) -> str | None:
    explicit = getattr(args, "ref", None)
    if explicit:
        return explicit
    if for_remote:
        return _current_ref()
    return None


def _remote_version_pin_env(*, args: argparse.Namespace) -> str:
    """Pin remote install to caller version without --ref (release wheel, not git)."""
    if getattr(args, "ref", None):
        return ""
    pin = _effective_ref(args=args, for_remote=True)
    if not pin:
        return ""
    return f"SECKIT_REF={shlex.quote(pin)} "

def _remote_install_script_path() -> Path | None:
    """Return local install.sh path for SSH streaming when available."""
    try:
        script = _install_sh_path()
    except Exception:
        return None
    return script if script.is_file() else None


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
    ref = _effective_ref(args=args, for_remote=False)
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
    if _flag(args, "skip_verify_if_unchanged"):
        argv.append("--skip-verify-if-unchanged")
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
    if _flag(args, "no_uv_download"):
        argv.append("--no-uv-download")
    if _flag(args, "dev"):
        argv.append("--dev")
    return argv


def _remote_installer_argv(*, args: argparse.Namespace) -> list[str]:
    """Flags forwarded to install.sh on the remote host (--yes is always included)."""
    remote_args: list[str] = ["--yes"]
    explicit_ref = getattr(args, "ref", None)
    if explicit_ref:
        remote_args.extend(["--ref", explicit_ref])
    if _flag(args, "upgrade"):
        remote_args.append("--upgrade")
    if _flag(args, "repair"):
        remote_args.append("--repair")
    if _flag(args, "no_init"):
        remote_args.append("--no-init")
    if _flag(args, "no_verify"):
        remote_args.append("--no-verify")
    if _flag(args, "skip_verify_if_unchanged"):
        remote_args.append("--skip-verify-if-unchanged")
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
    if _flag(args, "no_uv_download"):
        remote_args.append("--no-uv-download")
    return remote_args


def _remote_ssh_command(*, host: str, args: argparse.Namespace) -> list[str]:
    remote_args = _remote_installer_argv(args=args)

    remote_cmd = f"{_remote_version_pin_env(args=args)}bash -s --"
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

def _remote_ssh_command_fetch(*, host: str, args: argparse.Namespace) -> list[str]:
    """Fallback SSH command that fetches install.sh remotely."""
    install_url = getattr(args, "install_url", None) or DEFAULT_INSTALL_URL
    remote_args = _remote_installer_argv(args=args)
    fetch = (
        "if command -v curl >/dev/null 2>&1; then "
        f"curl -fsSL {shlex.quote(install_url)}; "
        "elif command -v wget >/dev/null 2>&1; then "
        f"wget -qO- {shlex.quote(install_url)}; "
        "elif command -v python3 >/dev/null 2>&1; then "
        f"python3 -c \"import sys, urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('{install_url}').read())\"; "
        "else echo 'seckit install: need curl, wget, or python3 on remote host' >&2; exit 1; fi"
    )
    pin_env = _remote_version_pin_env(args=args)
    remote_cmd = f"{fetch} | {pin_env}bash -s --"
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

def _local_install_url_command(*, args: argparse.Namespace) -> str:
    install_url = getattr(args, "install_url", None) or DEFAULT_INSTALL_URL
    install_args: list[str] = []
    ref = _effective_ref(args=args, for_remote=False)
    repo_url = getattr(args, "repo_url", None)
    if ref:
        install_args.extend(["--ref", ref])
    if repo_url:
        install_args.extend(["--repo-url", repo_url])
    if _flag(args, "upgrade"):
        install_args.append("--upgrade")
    if _flag(args, "repair"):
        install_args.append("--repair")
    if _flag(args, "yes"):
        install_args.append("--yes")
    if _flag(args, "no_init"):
        install_args.append("--no-init")
    if _flag(args, "no_verify"):
        install_args.append("--no-verify")
    if _flag(args, "skip_verify_if_unchanged"):
        install_args.append("--skip-verify-if-unchanged")
    if _flag(args, "dry_run"):
        install_args.append("--dry-run")
    if _flag(args, "verbose"):
        install_args.append("--verbose")
    if _flag(args, "safe"):
        install_args.append("--safe")
    if _flag(args, "no_shell_profile"):
        install_args.append("--no-shell-profile")
    if _flag(args, "shell_profile_force"):
        install_args.append("--shell-profile-force")
    if _flag(args, "no_uv_download"):
        install_args.append("--no-uv-download")
    if _flag(args, "dev"):
        install_args.append("--dev")
    fetch = (
        "if command -v curl >/dev/null 2>&1; then "
        f"curl -fsSL {shlex.quote(install_url)}; "
        "elif command -v wget >/dev/null 2>&1; then "
        f"wget -qO- {shlex.quote(install_url)}; "
        "elif command -v python3 >/dev/null 2>&1; then "
        f"python3 -c \"import sys, urllib.request; sys.stdout.buffer.write(urllib.request.urlopen('{install_url}').read())\"; "
        "else echo 'seckit install: need curl, wget, or python3 locally' >&2; exit 1; fi"
    )
    cmd = f"{fetch} | bash -s --"
    if install_args:
        cmd += " " + " ".join(shlex.quote(part) for part in install_args)
    return cmd


def cmd_install(*, args: argparse.Namespace) -> int:
    remote_host = _prepare_remote_install(args=args)
    if remote_host:
        local_script = _remote_install_script_path()
        ssh_argv = _remote_ssh_command(host=remote_host, args=args)
        if _flag(args, "dry_run"):
            rendered = " ".join(shlex.quote(part) for part in ssh_argv)
            if local_script is not None:
                print(f"{rendered} < {shlex.quote(str(local_script))}")
            else:
                print(" ".join(shlex.quote(part) for part in _remote_ssh_command_fetch(host=remote_host, args=args)))
            return 0
        if local_script is not None:
            payload = local_script.read_text(encoding="utf-8")
            completed = subprocess.run(ssh_argv, input=payload, text=True, check=False)
            return completed.returncode
        completed = subprocess.run(_remote_ssh_command_fetch(host=remote_host, args=args), check=False)
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
        or _flag(args, "skip_verify_if_unchanged")
        or _flag(args, "dry_run")
        or _flag(args, "json")
        or _flag(args, "verbose")
        or _flag(args, "safe")
        or _flag(args, "no_shell_profile")
        or _flag(args, "shell_profile_force")
        or _flag(args, "no_uv_download")
    ):
        try:
            argv = _build_install_sh_argv(args=args)
        except FileNotFoundError:
            fallback = _local_install_url_command(args=args)
            if _flag(args, "dry_run"):
                print(fallback)
                return 0
            completed = subprocess.run(["bash", "-lc", fallback], check=False)
            return completed.returncode
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
    print(f"  wget -qO- {install_url} | bash")
    print()
    print("Upgrade:")
    print(f"  curl -fsSL {install_url} | bash -s -- --upgrade")
    print(f"  wget -qO- {install_url} | bash -s -- --upgrade")
    print()
    print("Remote:")
    print("  seckit install @host")
    print("  seckit install user@host")
    return 0 if check.get("ok") else 1


__all__ = [
    "InstallTargetError",
    "cmd_install",
    "_normalize_ssh_target",
    "_prepare_remote_install",
]
