"""
secrets_kit.daemon.service

Install and operate the same-user managed ``seckitd`` service.

The service definition always invokes the stable installed ``seckit`` launcher.
It never changes datastore authority, escalates privileges, or installs a
system-wide service.
"""

from __future__ import annotations

import os
import platform
import plistlib
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

from secrets_kit.daemon.client import ping_daemon, stop_daemon, wait_until_running
from secrets_kit.locale import msg

LAUNCHD_LABEL = "net.unixwzrd.secrets-kit.daemon"
SYSTEMD_UNIT_NAME = "secrets-kit-daemon.service"


class DaemonServiceError(RuntimeError):
    """Report one deterministic managed-service lifecycle failure."""


def _system() -> str:
    """Return the supported host service-manager family."""

    value = platform.system()
    if value not in {"Darwin", "Linux"}:
        raise DaemonServiceError(f"managed daemon service is unsupported on {value}")
    return value


def _launcher_path() -> Path:
    """Return the stable installed launcher path used by service definitions."""

    configured = os.environ.get("SECKIT_LAUNCHER_PATH")
    return Path(configured).expanduser() if configured else Path.home() / ".local/bin/seckit"


def service_definition_path() -> Path:
    """Return the current user's launchd plist or systemd user-unit path."""

    if _system() == "Darwin":
        boot_definition = _boot_definition_path()
        if boot_definition.exists() or boot_definition.is_symlink():
            _validate_boot_definition(boot_definition)
            return boot_definition
        configured = os.environ.get("SECKIT_LAUNCH_AGENT_PATH")
        return (
            Path(configured).expanduser()
            if configured
            else Path.home() / "Library/LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        )
    configured = os.environ.get("SECKIT_SYSTEMD_UNIT_PATH")
    return (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".config/systemd/user" / SYSTEMD_UNIT_NAME
    )


def _boot_definition_path() -> Path:
    """Return the fixed, per-account system definition; never an environment override."""

    return Path("/Library/LaunchDaemons") / f"{LAUNCHD_LABEL}.{os.getuid()}.plist"


def _validate_boot_definition(path: Path) -> None:
    """Reject unsafe system definitions before treating them as this user's job."""

    import pwd
    import stat

    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("unsafe definition")
        payload = plistlib.loads(path.read_bytes())
        account = pwd.getpwuid(os.getuid())
        if os.getuid() == 0 or payload.get("UserName") != account.pw_name:
            raise ValueError("wrong runtime account")
        if payload.get("Label") != f"{LAUNCHD_LABEL}.{os.getuid()}":
            raise ValueError("wrong job label")
        if payload.get("ProgramArguments") != [str(_launcher_path()), "daemon", "run"]:
            raise ValueError("wrong runtime launcher")
        if "Program" in payload or payload.get("EnvironmentVariables") != {"HOME": str(Path.home())}:
            raise ValueError("wrong runtime environment")
        expected = plistlib.loads(_launchd_payload(_launcher_path(), home=Path.home()))
        expected.pop("LimitLoadToSessionType")
        expected.update(Label=f"{LAUNCHD_LABEL}.{os.getuid()}", UserName=account.pw_name)
        if payload != expected:
            raise ValueError("unexpected system definition")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, plistlib.InvalidFileException) as exc:
        raise DaemonServiceError(msg("daemon.service.boot_definition_unsafe")) from exc


def _require_user_service() -> None:
    """Fail before changing a system job, its definition, or the customer runtime."""

    if _system() == "Darwin":
        if service_definition_path() == _boot_definition_path() or _launchd_target() == f"system/{LAUNCHD_LABEL}.{os.getuid()}":
            raise DaemonServiceError(msg("daemon.service.boot_admin_required"))


def service_installed() -> bool:
    """Return whether a managed-service definition exists for this user."""

    if service_definition_path().is_file():
        return True
    # A loaded boot job can outlive a removed definition. Never fall through to
    # detached startup in that state; administrator cleanup is still required.
    return _system() == "Darwin" and _launchd_target() == f"system/{LAUNCHD_LABEL}.{os.getuid()}"


def _run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one fixed service-manager command without a shell."""

    try:
        result = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DaemonServiceError("managed daemon service command failed") from exc
    if check and result.returncode != 0:
        raise DaemonServiceError("managed daemon service command was rejected")
    return result


def _launchd_target() -> str:
    """Locate an existing same-user job, including a legacy GUI installation."""

    targets = [f"user/{os.getuid()}/{LAUNCHD_LABEL}", f"gui/{os.getuid()}/{LAUNCHD_LABEL}", f"system/{LAUNCHD_LABEL}.{os.getuid()}"]
    loaded = [target for target in targets if _run(["launchctl", "print", target], check=False).returncode == 0]
    if len(loaded) > 1:
        raise DaemonServiceError("duplicate managed daemon jobs require resolution")
    return loaded[0] if loaded else targets[0]


def _launchd_domain() -> str:
    """Return the same-user background domain, available without GUI login."""

    return f"user/{os.getuid()}"


def _launchd_loaded() -> bool:
    """Return whether launchd currently knows the daemon job."""

    return _run(["launchctl", "print", _launchd_target()], check=False).returncode == 0


def _launchd_domain_available() -> bool:
    """Return whether launchd exposes the same-user background domain."""

    return _run(["launchctl", "print", _launchd_domain()], check=False).returncode == 0


def _systemd_active() -> bool:
    """Return whether the systemd user service is active."""

    return (
        _run(
            ["systemctl", "--user", "is-active", "--quiet", SYSTEMD_UNIT_NAME], check=False
        ).returncode
        == 0
    )


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    """Atomically replace one owner-controlled service definition."""

    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            os.fchmod(stream.fileno(), mode)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _launchd_payload(launcher: Path, *, home: Path) -> bytes:
    """Build the deterministic per-user LaunchAgent definition."""

    return plistlib.dumps(
        {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": [str(launcher), "daemon", "run"],
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            # Headless session placement is independent of scheduling policy.
            # Background throttling also affects runtime-access child workers.
            "ProcessType": "Standard",
            "LimitLoadToSessionType": "Background",
            "ThrottleInterval": 2,
            "EnvironmentVariables": {"HOME": str(home)},
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": "/dev/null",
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )


def _systemd_payload(launcher: Path) -> bytes:
    """Build the deterministic systemd user-unit definition."""

    executable = shlex.quote(str(launcher))
    value = (
        "[Unit]\n"
        "Description=Secrets Kit same-user daemon\n"
        "After=default.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={executable} daemon run\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "NoNewPrivileges=true\n"
        "PrivateTmp=true\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    return value.encode("utf-8")


def _stop_unmanaged_daemon() -> None:
    """Stop an existing detached daemon before service-manager adoption."""

    if ping_daemon(timeout=0.2):
        stop_daemon()


def _rollback_service_install(*, path: Path, previous_payload: bytes | None) -> None:
    """Remove a rejected definition or restore the previously installed one."""

    system = _system()
    if system == "Darwin":
        if _launchd_loaded():
            _run(["launchctl", "bootout", _launchd_target()], check=False)
    else:
        _run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT_NAME], check=False)
    if previous_payload is None:
        path.unlink(missing_ok=True)
        if system == "Linux":
            _run(["systemctl", "--user", "daemon-reload"], check=False)
        return
    _atomic_write(path, previous_payload)
    if system == "Darwin":
        _run(["launchctl", "bootstrap", _launchd_domain(), str(path)], check=False)
    else:
        _run(["systemctl", "--user", "daemon-reload"], check=False)
        _run(["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT_NAME], check=False)


def install_service(*, timeout: float = 30.0, reload_runtime: bool = False) -> bool:
    """Install, enable, and start the same-user managed daemon service.

    Returns ``True`` when the definition was newly created and ``False`` when
    an existing definition was refreshed. Existing detached daemon processes
    are stopped before the service manager starts the replacement.
    Set ``reload_runtime`` after changing startup configuration so an existing
    macOS job cannot keep using its previous in-memory configuration.
    """

    _require_user_service()
    configured_launcher = _launcher_path()
    if configured_launcher.is_symlink():
        raise DaemonServiceError("installed seckit launcher is unsafe or not executable")
    launcher = configured_launcher.resolve(strict=True)
    if not os.access(launcher, os.X_OK):
        raise DaemonServiceError("installed seckit launcher is unsafe or not executable")
    if _system() == "Darwin" and not _launchd_domain_available():
        raise DaemonServiceError("managed daemon service requires an available macOS user domain")
    path = service_definition_path()
    created = not path.exists()
    previous_payload = path.read_bytes() if path.is_file() else None
    if (
        _system() == "Darwin"
        and previous_payload == _launchd_payload(launcher, home=Path.home())
        and _launchd_loaded()
        and _launchd_target().startswith(f"{_launchd_domain()}/")
    ):
        # Reinstalling an unchanged definition must not tear down a healthy job.
        if reload_runtime:
            restart_service(timeout=timeout)
        else:
            start_service(timeout=timeout)
        return False
    try:
        # A managed daemon must be fully stopped by its manager. IPC shutdown
        # can unlink the socket before systemd observes process exit, causing
        # enable --now to leave the stopping unit stopped instead of restarting.
        if _system() == "Linux" and not created:
            _run(["systemctl", "--user", "stop", SYSTEMD_UNIT_NAME])
        if _system() == "Darwin" and _launchd_loaded():
            _run(["launchctl", "bootout", _launchd_target()])
        _stop_unmanaged_daemon()
        if _system() == "Darwin":
            _atomic_write(path, _launchd_payload(launcher, home=Path.home()))
            _run(["launchctl", "bootstrap", _launchd_domain(), str(path)])
            _run(["launchctl", "enable", _launchd_target()])
            _run(["launchctl", "kickstart", _launchd_target()])
        else:
            _atomic_write(path, _systemd_payload(launcher))
            _run(["systemctl", "--user", "daemon-reload"])
            _run(["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT_NAME])
        if not wait_until_running(timeout=timeout):
            raise DaemonServiceError("managed daemon did not become reachable")
    except (DaemonServiceError, OSError) as exc:
        _rollback_service_install(path=path, previous_payload=previous_payload)
        if isinstance(exc, DaemonServiceError):
            raise
        raise DaemonServiceError("managed daemon service installation failed") from exc
    return created


def start_service(*, timeout: float = 30.0) -> None:
    """Start an installed same-user daemon service and verify reachability."""

    _require_user_service()
    path = service_definition_path()
    if not path.is_file():
        raise DaemonServiceError("managed daemon service is not installed")
    if _system() == "Darwin":
        if not _launchd_loaded():
            _run(["launchctl", "bootstrap", _launchd_domain(), str(path)])
        _run(["launchctl", "enable", _launchd_target()])
        # RunAtLoad may already have started the bootstrapped process. Starting
        # must not kill it again; only the explicit restart operation uses -k.
        _run(["launchctl", "kickstart", _launchd_target()])
    else:
        _run(["systemctl", "--user", "start", SYSTEMD_UNIT_NAME])
    if not wait_until_running(timeout=timeout):
        raise DaemonServiceError("managed daemon did not become reachable")


def stop_service() -> None:
    """Stop an installed service without deleting its definition."""

    _require_user_service()
    if _system() == "Darwin":
        if _launchd_loaded():
            _run(["launchctl", "bootout", _launchd_target()])
    else:
        _run(["systemctl", "--user", "stop", SYSTEMD_UNIT_NAME])


def restart_service(*, timeout: float = 30.0) -> None:
    """Restart an installed service and verify bounded daemon recovery."""

    _require_user_service()
    if _system() == "Darwin":
        path = service_definition_path()
        if not path.is_file():
            raise DaemonServiceError("managed daemon service is not installed")
        if _launchd_loaded():
            _run(["launchctl", "kickstart", "-k", _launchd_target()])
        else:
            _run(["launchctl", "bootstrap", _launchd_domain(), str(path)])
    else:
        _run(["systemctl", "--user", "restart", SYSTEMD_UNIT_NAME])
    if not wait_until_running(timeout=timeout):
        raise DaemonServiceError("managed daemon did not recover after restart")


def uninstall_service() -> bool:
    """Stop and remove the same-user service definition if present."""

    _require_user_service()
    path = service_definition_path()
    if not path.exists():
        return False
    if _system() == "Linux":
        _run(["systemctl", "--user", "disable", SYSTEMD_UNIT_NAME], check=False)
    stop_service()
    path.unlink()
    if _system() == "Linux":
        _run(["systemctl", "--user", "daemon-reload"])
    return True


def service_status() -> dict[str, Any]:
    """Return payload-free managed-service status for CLI formatting."""

    system = _system()
    path = service_definition_path()
    installed = path.is_file()
    active = _launchd_loaded() if system == "Darwin" else _systemd_active()
    status: dict[str, Any] = {
        "manager": "launchd" if system == "Darwin" else "systemd-user",
        "installed": installed,
        "active": active,
        "definition": str(path),
        "daemon_reachable": ping_daemon(timeout=0.2),
    }
    if system == "Linux":
        linger = _run(
            ["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"],
            check=False,
        )
        status["linger"] = linger.stdout.strip() == "yes"
    return status


__all__ = [
    "DaemonServiceError",
    "install_service",
    "restart_service",
    "service_definition_path",
    "service_installed",
    "service_status",
    "start_service",
    "stop_service",
    "uninstall_service",
]
