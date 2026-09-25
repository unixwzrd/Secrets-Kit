"""secrets_kit.cli.update_service: same-user daily update-check scheduling."""

from __future__ import annotations

import os
import plistlib
import shlex
import subprocess
import sys
from pathlib import Path

from secrets_kit.locale import msg

LABEL = "net.unixwzrd.secrets-kit.update-check"
CHECK_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"


def _launcher() -> Path:
    expected = Path.home() / ".local" / "bin" / "seckit"
    if not expected.is_symlink() and expected.is_file() and os.access(expected, os.X_OK):
        return expected.resolve(strict=True)
    raise RuntimeError("stable_launcher_unavailable")


def _run(argv: list[str]) -> int:
    try:
        return subprocess.run(
            argv, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 125


def _mac_definition(*, launcher: Path) -> tuple[Path, bytes]:
    path = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    payload = {
        "Label": LABEL,
        "ProgramArguments": [str(launcher), "upgrade", "--check", "--refresh"],
        "StartInterval": 86400,
        "RunAtLoad": True,
        "ProcessType": "Background",
        "EnvironmentVariables": {"HOME": str(Path.home()), "PATH": CHECK_PATH},
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }
    return path, plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def _linux_definitions(*, launcher: Path) -> tuple[Path, str, Path, str]:
    directory = Path.home() / ".config" / "systemd" / "user"
    service = directory / "secrets-kit-update-check.service"
    timer = directory / "secrets-kit-update-check.timer"
    executable = shlex.quote(str(launcher)).replace("%", "%%")
    service_text = (
        "[Unit]\nDescription=Secrets Kit update availability check\n\n"
        "[Service]\nType=oneshot\n"
        f"Environment=PATH={CHECK_PATH}\n"
        f"ExecStart={executable} upgrade --check --refresh\n"
    )
    timer_text = (
        "[Unit]\nDescription=Daily Secrets Kit update availability check\n\n"
        "[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=30m\n"
        "Unit=secrets-kit-update-check.service\n\n[Install]\nWantedBy=timers.target\n"
    )
    return service, service_text, timer, timer_text


def _atomic_write(path: Path, data: bytes) -> None:
    missing: list[Path] = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_definition_path(path: Path) -> bool:
    """Return true only for an owner-controlled, non-linked definition path."""
    home = Path.home().absolute()
    current = path.parent
    try:
        while current != home:
            if current.exists() or current.is_symlink():
                info = current.lstat()
                if current.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o022:
                    return False
            current = current.parent
        if path.is_symlink():
            return False
        if path.exists():
            info = path.lstat()
            return path.is_file() and info.st_uid == os.getuid() and not info.st_mode & 0o022
    except OSError:
        return False
    return True


def manage_update_service(*, action: str) -> int:
    """Install, inspect, or remove a daily same-user update-check timer."""
    if action == "uninstall":
        if sys.platform == "darwin":
            existing = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
            if not existing.exists() and not existing.is_symlink():
                return 0
        elif sys.platform.startswith("linux"):
            directory = Path.home() / ".config" / "systemd" / "user"
            if not any((directory / name).exists() or (directory / name).is_symlink() for name in (
                "secrets-kit-update-check.service", "secrets-kit-update-check.timer"
            )):
                return 0
    try:
        launcher = _launcher()
    except RuntimeError:
        print(msg("cli.upgrade.service_launcher_unavailable"))
        return 2
    if sys.platform == "darwin":
        path, content = _mac_definition(launcher=launcher)
        if not _safe_definition_path(path):
            print(msg("cli.upgrade.service_foreign"))
            return 2
        domain = f"user/{os.getuid()}"
        if action == "status":
            active = path.is_file() and _run(["launchctl", "print", f"{domain}/{LABEL}"]) == 0
            print(msg("cli.upgrade.service_status", installed=str(path.is_file()).lower(), active=str(active).lower()))
            return 0 if active else 1
        if action == "uninstall":
            if path.exists() and (path.is_symlink() or path.read_bytes() != content):
                print(msg("cli.upgrade.service_foreign"))
                return 2
            target = f"{domain}/{LABEL}"
            loaded_status = _run(["launchctl", "print", target])
            if loaded_status not in {0, 113}:
                print(msg("cli.upgrade.service_remove_failed"))
                return 1
            if loaded_status == 0 and _run(["launchctl", "bootout", target]) != 0:
                print(msg("cli.upgrade.service_remove_failed"))
                return 1
            path.unlink(missing_ok=True)
            print(msg("cli.upgrade.service_removed"))
            return 0
        if path.exists() and (path.is_symlink() or path.read_bytes() != content):
            print(msg("cli.upgrade.service_foreign"))
            return 2
        _atomic_write(path, content)
        _run(["launchctl", "bootout", domain, str(path)])
        if _run(["launchctl", "bootstrap", domain, str(path)]) != 0:
            print(msg("cli.upgrade.service_install_failed"))
            return 1
        print(msg("cli.upgrade.service_installed"))
        return 0
    if sys.platform.startswith("linux"):
        service, service_text, timer, timer_text = _linux_definitions(launcher=launcher)
        if not _safe_definition_path(service) or not _safe_definition_path(timer):
            print(msg("cli.upgrade.service_foreign"))
            return 2
        if action == "status":
            active = service.is_file() and timer.is_file() and _run(
                ["systemctl", "--user", "is-active", "secrets-kit-update-check.timer"]
            ) == 0
            print(msg("cli.upgrade.service_status", installed=str(service.is_file() and timer.is_file()).lower(), active=str(active).lower()))
            return 0 if active else 1
        if action == "uninstall":
            expected = ((service, service_text), (timer, timer_text))
            if any(path.exists() and (path.is_symlink() or path.read_text() != text) for path, text in expected):
                print(msg("cli.upgrade.service_foreign"))
                return 2
            if (service.exists() or timer.exists()) and _run(
                ["systemctl", "--user", "disable", "--now", "secrets-kit-update-check.timer"]
            ) != 0:
                print(msg("cli.upgrade.service_remove_failed"))
                return 1
            if (service.exists() or timer.exists()) and _run(
                ["systemctl", "--user", "stop", "secrets-kit-update-check.service"]
            ) not in {0, 5}:
                print(msg("cli.upgrade.service_remove_failed"))
                return 1
            service.unlink(missing_ok=True)
            timer.unlink(missing_ok=True)
            _run(["systemctl", "--user", "daemon-reload"])
            print(msg("cli.upgrade.service_removed"))
            return 0
        expected = ((service, service_text), (timer, timer_text))
        if any(path.exists() and (path.is_symlink() or path.read_text() != text) for path, text in expected):
            print(msg("cli.upgrade.service_foreign"))
            return 2
        _atomic_write(service, service_text.encode())
        _atomic_write(timer, timer_text.encode())
        if _run(["systemctl", "--user", "daemon-reload"]) != 0 or _run(
            ["systemctl", "--user", "enable", "--now", "secrets-kit-update-check.timer"]
        ) != 0:
            print(msg("cli.upgrade.service_install_failed"))
            return 1
        print(msg("cli.upgrade.service_installed"))
        return 0
    print(msg("cli.upgrade.service_unsupported"))
    return 2


__all__ = ["manage_update_service"]
