"""
secrets_kit.cli.commands.install_cmd

Operator install, upgrade, and remote SSH wrapper.

For tagged remote installs, the initiating account resolves and verifies the
release installer with its own GitHub authorization before streaming the
installer over SSH. GitHub credentials and client private keys are never sent
to the target by this wrapper. The normal customer path then verifies mutual
peer admission and a connected route; explicit install-only opts out.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from secrets_kit import __version__
from secrets_kit.cli.commands.install_peer import pair_installed_peer, verify_authorized_route
from secrets_kit.cli.install_check import run_install_check
from secrets_kit.cli.update_check import (
    MAX_INSTALLER_BYTES,
    _github_token,
    _safe_install_state,
    download_release_installer,
    release_installer_asset,
    update_context,
)


def _flag(args: argparse.Namespace, name: str) -> bool:
    return bool(getattr(args, name, False))


def _installer_url(*, args: argparse.Namespace) -> str:
    """Select this installation's repository/tag, never a hard-coded branch."""
    explicit = getattr(args, "install_url", None)
    if explicit:
        return str(explicit)
    repository, _ = update_context()
    reference = getattr(args, "ref", None) or _safe_install_state().get("ref") or _current_ref()
    if not isinstance(reference, str) or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", reference):
        raise ValueError("branch_build_requires_explicit_installer_url")
    return f"https://github.com/{repository}/releases/download/{reference}/install.sh"


def _verified_remote_installer(*, args: argparse.Namespace) -> Path:
    """Fetch the caller's exact release with local GitHub auth and verify its digest.

    Only the public installer bytes cross SSH. GitHub credentials stay on the
    initiating machine; the target does not need repository access.
    """
    repository, _ = update_context()
    reference = getattr(args, "ref", None) or _safe_install_state().get("ref") or _current_ref()
    if not isinstance(reference, str) or not re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", reference
    ):
        raise ValueError("remote_install_requires_release_tag")
    url, digest = release_installer_asset(repository=repository, reference=reference)
    return download_release_installer(url=url, digest=digest)


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
    assignments: list[str] = []
    if not getattr(args, "ref", None):
        pin = _effective_ref(args=args, for_remote=True)
        if pin:
            assignments.append(f"SECKIT_REF={shlex.quote(pin)}")
    # Preserve the release context used by the caller.  This is essential for
    # private qualification: the remote installer must query the same release
    # repository and channel rather than silently falling back to defaults.
    for name in (
        "SECKIT_GITHUB_REPO",
        "SECKIT_RELEASE_CHANNEL",
        "SECKIT_RELEASE_BASE",
        "SECKIT_WHEEL_URL",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            assignments.append(f"{name}={shlex.quote(value)}")
    return " ".join(assignments) + (" " if assignments else "")

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
    script = Path(getattr(args, "install_script", None) or _install_sh_path())
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
    repo_url = getattr(args, "repo_url", None)
    if repo_url:
        remote_args.extend(["--repo-url", repo_url])
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


def _matching_remote_receipt(*, host: str, args: argparse.Namespace) -> bool:
    """Recognize a verified, matching installed release without target GitHub access."""
    if getattr(args, "install_url", None) or any(
        _flag(args, name) for name in ("upgrade", "repair", "dev")
    ):
        return False
    try:
        repository, _ = update_context()
        reference = getattr(args, "ref", None) or _safe_install_state().get("ref") or _current_ref()
    except ValueError:
        return False
    if not isinstance(reference, str) or not re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", reference
    ):
        return False
    completed = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
         '"$HOME/.local/bin/seckit" install --receipt-json'],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if completed.returncode:
        return False
    try:
        receipt = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    return isinstance(receipt, dict) and (
        receipt.get("version") == reference.removeprefix("v")
        and receipt.get("github_repo") == repository
        and receipt.get("ref") == reference
        and receipt.get("verified") is True
    )


class _PrivateRedirect(urllib.request.HTTPRedirectHandler):
    """Do not forward a GitHub credential to a release-asset redirect host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise ValueError("installer_redirect_requires_https")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and target.netloc != urllib.parse.urlsplit(req.full_url).netloc:
            for header_map in (redirected.headers, redirected.unredirected_hdrs):
                for name in tuple(header_map):
                    if name.casefold() == "authorization":
                        header_map.pop(name)
        return redirected


def _download_explicit_installer(*, install_url: str) -> Path:
    """Fetch one caller-selected HTTPS script locally; never send credentials over SSH."""
    parsed = urllib.parse.urlsplit(install_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("invalid_installer_url")
    headers = {"Accept": "application/octet-stream", "User-Agent": "seckit-install"}
    if parsed.hostname in {"api.github.com", "raw.githubusercontent.com"}:
        token = _github_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(install_url, headers=headers)
    with urllib.request.build_opener(_PrivateRedirect()).open(request, timeout=30) as response:
        payload = response.read(MAX_INSTALLER_BYTES + 1)
    if len(payload) > MAX_INSTALLER_BYTES or not payload.startswith(b"#!"):
        raise ValueError("invalid_installer_asset")
    fd, raw = tempfile.mkstemp(prefix="seckit-install-", suffix=".sh")
    path = Path(raw)
    try:
        os.fchmod(fd, 0o700)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, check=False, timeout=10)
        if result.returncode:
            raise ValueError("invalid_installer_syntax")
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _local_installer_argv(*, args: argparse.Namespace) -> list[str]:
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
    return install_args


def cmd_install(*, args: argparse.Namespace) -> int:
    if _flag(args, "receipt_json"):
        if getattr(args, "remote_host", None):
            print("seckit install: --receipt-json is local only", file=sys.stderr)
            return 2
        try:
            state = _safe_install_state()
        except ValueError as exc:
            print(f"seckit install: invalid installed release receipt: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "version": __version__,
            "github_repo": state.get("github_repo"),
            "ref": state.get("ref"),
            "verified": state.get("verified") is True,
        }, sort_keys=True))
        return 0
    remote_host = _prepare_remote_install(args=args)
    if remote_host:
        pair_after_install = not any(
            _flag(args, name) for name in ("upgrade", "repair", "no_init", "install_only")
        )
        if _flag(args, "dry_run"):
            command = _remote_ssh_command(host=remote_host, args=args)
            print(" ".join(shlex.quote(part) for part in command))
            return 0
        if pair_after_install and not sys.stdin.isatty():
            print(
                "seckit install: peer setup needs an interactive terminal; "
                "use --install-only for software installation without pairing",
                file=sys.stderr,
            )
            return 1
        if pair_after_install and _matching_remote_receipt(host=remote_host, args=args):
            try:
                pair_installed_peer(host=remote_host)
                verify_authorized_route(host=remote_host)
            except (OSError, ValueError, subprocess.SubprocessError, EOFError) as exc:
                print(f"seckit install: existing remote release found, peer setup incomplete: {exc}", file=sys.stderr)
                return 1
            return 0
        try:
            installer = (
                _download_explicit_installer(install_url=args.install_url)
                if getattr(args, "install_url", None)
                else _verified_remote_installer(args=args)
            )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            print(
                f"seckit install: cannot retrieve the verified private release ({exc}); "
                "sign in on this machine with 'gh auth login --web' and retry",
                file=sys.stderr,
            )
            return 1
        try:
            with installer.open("rb") as stream:
                completed = subprocess.run(
                    _remote_ssh_command(host=remote_host, args=args),
                    stdin=stream,
                    check=False,
                )
            if completed.returncode or not pair_after_install:
                return completed.returncode
            try:
                pair_installed_peer(host=remote_host)
                verify_authorized_route(host=remote_host)
            except (OSError, ValueError, subprocess.SubprocessError, EOFError) as exc:
                print(f"seckit install: remote software installed, peer setup incomplete: {exc}", file=sys.stderr)
                return 1
            return 0
        finally:
            installer.unlink(missing_ok=True)

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
            if _flag(args, "dry_run"):
                print("bash <verified release installer> " + " ".join(shlex.quote(part) for part in _local_installer_argv(args=args)))
                return 0
            try:
                installer = (
                    _download_explicit_installer(install_url=args.install_url)
                    if getattr(args, "install_url", None)
                    else _verified_remote_installer(args=args)
                )
            except (OSError, ValueError, urllib.error.URLError) as exc:
                print(f"seckit install: cannot retrieve installer ({exc})", file=sys.stderr)
                return 1
            try:
                return subprocess.run(["bash", str(installer), *_local_installer_argv(args=args)], check=False).returncode
            finally:
                installer.unlink(missing_ok=True)
        if _flag(args, "dry_run"):
            print(" ".join(shlex.quote(part) for part in argv))
            return 0
        completed = subprocess.run(argv, check=False)
        return completed.returncode

    check = run_install_check()
    print(json.dumps(check, indent=2, sort_keys=True))
    install_url = _installer_url(args=args)
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
