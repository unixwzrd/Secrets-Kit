"""
secrets_kit.cli.update_check

Bounded, value-free GitHub release checks for the installed distribution.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from secrets_kit import __version__
from secrets_kit.cli.install_check import install_state_path

CHECK_TTL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_INSTALLER_BYTES = 16 * 1024 * 1024
_RELEASE_SOURCE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/releases/download/")


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_install_state(*, home: Path | None = None) -> dict[str, Any]:
    base = (home or Path.home()).absolute()
    path = install_state_path(home=base)
    if not path.exists() and not path.is_symlink():
        return {}
    current = path.parent
    while current != base:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("unsafe_install_repository_state")
        current = current.parent
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("unsafe_install_repository_state")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid_install_repository_state") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError("invalid_install_repository_state")
    return value


def _require_admin_owned(path: Path, *, directory: bool) -> None:
    """Reject writable, non-root, or unexpected shared-runtime path components."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("unsafe_shared_release_origin") from exc
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe_shared_release_origin")


def _require_admin_link(path: Path) -> None:
    """Require the active generation selector to be an administrator-owned link."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("unsafe_shared_release_origin") from exc
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise ValueError("unsafe_shared_release_origin")


def _shared_release_state(*, runtime: Path | None = None) -> dict[str, Any] | None:
    """Read release identity only from the active administrator-owned generation.

    A shared user may retain an older per-user receipt. The active shared code,
    not that receipt, owns repository and version selection for remote installs.
    The launcher executes the physical generation, so require it to match the
    administrator-owned current link before trusting the embedded origin.
    """
    installed = runtime or Path(sys.prefix)
    environment = installed / "seckit-environment"
    origin = installed / "seckit-release-origin.json"
    if not any(path.exists() or path.is_symlink() for path in (environment, origin)):
        return None
    if installed.parent.name != "runtime":
        raise ValueError("unsafe_shared_release_origin")
    if installed.name == "current":
        current = installed
    elif installed.name.startswith("runtime-"):
        current = installed.parent / "current"
    else:
        raise ValueError("unsafe_shared_release_origin")
    prefix = current.parent.parent
    component = Path("/")
    for name in prefix.parts[1:]:
        component /= name
        _require_admin_owned(component, directory=True)
    _require_admin_owned(current.parent, directory=True)
    _require_admin_link(current)
    try:
        generation = current.resolve(strict=True)
        installed_generation = installed.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("unsafe_shared_release_origin") from exc
    if (generation.parent != current.parent.resolve(strict=True)
            or not generation.name.startswith("runtime-")
            or installed_generation != generation):
        raise ValueError("unsafe_shared_release_origin")
    _require_admin_owned(generation, directory=True)
    _require_admin_owned(generation / environment.name, directory=False)
    _require_admin_owned(generation / origin.name, directory=False)
    try:
        payload = json.loads(origin.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid_shared_release_origin") from exc
    if not isinstance(payload, dict) or payload.get("verified") is not True:
        raise ValueError("invalid_shared_release_origin")
    if payload.get("version") != __version__:
        raise ValueError("shared_release_version_mismatch")
    try:
        installed_environment = environment.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("invalid_shared_release_origin") from exc
    if payload.get("environment") != installed_environment:
        raise ValueError("shared_release_environment_mismatch")
    source_ref = payload.get("source_ref")
    source_commit = payload.get("source_commit")
    if (not isinstance(source_commit, str)
            or not re.fullmatch(r"[0-9a-f]{40}", source_commit)
            or not isinstance(source_ref, str)
            or not (source_ref == f"refs/tags/v{__version__}"
                    or source_ref.startswith("refs/heads/"))):
        raise ValueError("invalid_shared_release_origin")
    ref = payload.get("ref")
    if ref != (f"v{__version__}" if source_ref.startswith("refs/tags/") else source_commit):
        raise ValueError("invalid_shared_release_origin")
    repo = payload.get("github_repo")
    channel = payload.get("release_channel")
    if (not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or not isinstance(ref, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?|[0-9a-f]{40}", ref)
            or channel not in {"release", "prerelease"}):
        raise ValueError("invalid_shared_release_origin")
    return payload


def _release_context(*, home: Path | None = None) -> tuple[str, str]:
    """Resolve repository and channel from explicit environment or install receipt."""
    shared = _shared_release_state()
    state = shared if shared is not None else _safe_install_state(home=home)
    repo = "" if shared is not None else os.environ.get("SECKIT_GITHUB_REPO", "").strip()
    if not repo:
        recorded = state.get("github_repo")
        if isinstance(recorded, str) and recorded.strip():
            repo = recorded.strip()
        else:
            source = state.get("package_source")
            match = _RELEASE_SOURCE.match(source) if isinstance(source, str) else None
            if match:
                repo = match.group(1)
            else:
                raise ValueError("unknown_install_repository")
    channel = "" if shared is not None else os.environ.get("SECKIT_RELEASE_CHANNEL", "").strip()
    if not channel:
        recorded_channel = state.get("release_channel")
        if recorded_channel in {"release", "prerelease"}:
            channel = recorded_channel
        else:
            channel = "prerelease" if any(char.isalpha() for char in __version__) else "release"
    if channel not in {"release", "prerelease"}:
        raise ValueError("unsupported_release_channel")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid_github_repository")
    return repo, channel


def update_context(*, home: Path | None = None) -> tuple[str, str]:
    """Return the validated, non-secret repository and release channel."""
    return _release_context(home=home)


def _github_token() -> str:
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    try:
        completed = subprocess.run(
            ["gh", "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _api_object(*, repo: str, path: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "seckit-update-check"},
    )
    token = _github_token()
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("release_response_too_large")
    return json.loads(raw)


def _installer_asset(release: dict[str, Any]) -> tuple[str, str]:
    for asset in release.get("assets", []):
        if isinstance(asset, dict) and asset.get("name") == "install.sh":
            url = asset.get("url")
            digest = asset.get("digest")
            if (
                isinstance(url, str)
                and url.startswith("https://api.github.com/repos/")
                and isinstance(digest, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            ):
                return url, digest
    raise ValueError("installer_asset_unavailable")


def _latest_release(
    *, repo: str, channel: str, installed_stage: str | None
) -> tuple[str, str, str]:
    """Return the first syntactically valid release in the installed version family."""
    releases = _api_object(repo=repo, path="releases?per_page=30")
    if not isinstance(releases, list):
        raise ValueError("invalid_release_response")
    for release in releases:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        prerelease = bool(release.get("prerelease"))
        if (channel == "prerelease") != prerelease:
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            continue
        try:
            stage = _version_stage(tag)
        except ValueError:
            continue
        if stage != installed_stage:
            continue
        url, digest = _installer_asset(release)
        return tag, url, digest
    raise ValueError("no_release_for_channel")


def _cache_path(*, home: Path | None = None) -> Path:
    base = home or Path.home()
    return base / ".cache" / "seckit" / "update-check.json"


def _read_cache(*, home: Path | None = None) -> dict[str, Any]:
    path = _cache_path(home=home)
    if not path.exists() and not path.is_symlink():
        return {}
    base = (home or Path.home()).absolute()
    try:
        current = path.parent
        while current != base:
            info = current.lstat()
            if current.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
                return {}
            current = current.parent
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            return {}
    except OSError:
        return {}
    return _read_object(path)


def _write_cache(*, path: Path, result: dict[str, Any]) -> None:
    home = Path.home().resolve()
    if path.is_symlink() or home not in path.resolve().parents:
        raise OSError("unsafe_cache_path")
    for directory in (path.parent.parent, path.parent):
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if directory.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise OSError("unsafe_cache_directory")
    if path.exists():
        info = path.lstat()
        if not path.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("unsafe_cache_file")
    fd, raw = tempfile.mkstemp(prefix=".update-check.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def check_for_update(*, refresh: bool = False, home: Path | None = None) -> dict[str, Any]:
    """Return a bounded update result without modifying the installed runtime."""
    cache = _cache_path(home=home)
    cached = _read_cache(home=home)
    now = int(time.time())
    current = f"v{__version__}"
    try:
        repo, channel = _release_context(home=home)
        current_stage = _version_stage(current)
    except ValueError as exc:
        return {"status": "unavailable", "reason": str(exc), "current": current}
    if (
        not refresh
        and cached.get("repository") == repo
        and cached.get("channel") == channel
        and isinstance(cached.get("checked_at"), int)
        and cached.get("current") == current
        and 0 <= now - cached["checked_at"] < CHECK_TTL_SECONDS
        and _cached_candidate_matches(
            cached=cached,
            installed_stage=current_stage,
        )
    ):
        return cached
    try:
        latest, installer_url, installer_digest = _latest_release(
            repo=repo,
            channel=channel,
            installed_stage=current_stage,
        )
        result: dict[str, Any] = {
            "status": "available" if _version_key(latest) > _version_key(current) else "current",
            "current": current,
            "latest": latest,
            "installer_url": installer_url,
            "installer_digest": installer_digest,
            "repository": repo,
            "channel": channel,
            "checked_at": now,
        }
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
        result = {
            "status": "unavailable",
            "current": current,
            "repository": repo,
            "channel": channel,
            "checked_at": now,
        }
    try:
        _write_cache(path=cache, result=result)
    except OSError:
        pass
    return result


def release_installer_asset(*, repository: str, reference: str) -> tuple[str, str]:
    """Resolve the immutable install.sh asset for one exact GitHub release tag."""
    release = _api_object(repo=repository, path=f"releases/tags/{reference}")
    if not isinstance(release, dict) or release.get("tag_name") != reference:
        raise ValueError("release_tag_mismatch")
    return _installer_asset(release)


def download_release_installer(*, url: str, digest: str) -> Path:
    """Download, hash-check and syntax-check one bounded release installer."""
    if not url.startswith("https://api.github.com/repos/") or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", digest
    ):
        raise ValueError("invalid_installer_asset")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "seckit-upgrade"},
    )
    token = _github_token()
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = response.read(MAX_INSTALLER_BYTES + 1)
    if len(payload) > MAX_INSTALLER_BYTES or not payload.startswith(b"#!"):
        raise ValueError("invalid_installer_asset")
    if hashlib.sha256(payload).hexdigest() != digest.removeprefix("sha256:"):
        raise ValueError("installer_digest_mismatch")
    fd, raw = tempfile.mkstemp(prefix="seckit-upgrade-", suffix=".sh")
    path = Path(raw)
    try:
        os.fchmod(fd, 0o700)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        try:
            completed = subprocess.run(
                ["bash", "-n", str(path)], check=False, capture_output=True, timeout=10
            )
        except subprocess.SubprocessError as exc:
            raise ValueError("installer_syntax_check_failed") from exc
        if completed.returncode != 0:
            raise ValueError("invalid_installer_syntax")
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _version_key(value: str) -> tuple[int, int, int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?", value)
    if not match:
        raise ValueError("invalid_release_tag")
    major, minor, patch, stage, serial = match.groups()
    return (
        int(major), int(minor), int(patch),
        {"a": 0, "b": 1, "rc": 2, None: 3}[stage], int(serial or 0),
    )


def _version_stage(value: str) -> str | None:
    """Return a validated version tag's prerelease family, if any."""
    match = re.fullmatch(r"v?\d+\.\d+\.\d+(?:(a|b|rc)\d+)?", value)
    if not match:
        raise ValueError("invalid_release_tag")
    return match.group(1)


def _cached_candidate_matches(
    *, cached: dict[str, Any], installed_stage: str | None
) -> bool:
    """Reject cached release entries outside the installed version family."""
    if cached.get("status") not in {"available", "current"}:
        return True
    latest = cached.get("latest")
    if not isinstance(latest, str):
        return False
    try:
        stage = _version_stage(latest)
    except ValueError:
        return False
    return stage == installed_stage


def cached_update_available(*, home: Path | None = None) -> str | None:
    """Return the cached newer tag, without network activity, when one is known."""
    cached = _read_cache(home=home)
    if cached.get("status") != "available":
        return None
    latest = cached.get("latest")
    if not isinstance(latest, str):
        return None
    try:
        current_stage = _version_stage(f"v{__version__}")
        latest_stage = _version_stage(latest)
    except ValueError:
        return None
    return latest if latest_stage == current_stage else None


__all__ = [
    "cached_update_available", "check_for_update", "download_release_installer",
    "release_installer_asset", "update_context",
]
