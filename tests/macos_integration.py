"""macOS live integration gating for ``make test`` on a logged-in console session.

Auto-enables when ``launchctl print gui/<uid>`` succeeds and the run is not CI.
Opt-out: ``SECKIT_RUN_<NAME>=0``. Force on (e.g. SSH): ``=1``.
"""

from __future__ import annotations

import os
import subprocess
import sys

from platform_guards import SKIP_MACOS_ONLY


def in_ci_like_environment() -> bool:
    return os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"


def gui_launchd_domain_present() -> bool:
    if sys.platform != "darwin":
        return False
    uid = os.getuid()
    try:
        proc = subprocess.run(
            ["/bin/launchctl", "print", f"gui/{uid}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    if proc.returncode != 0:
        return False
    out = (proc.stdout or "") + (proc.stderr or "")
    if not out.strip():
        return False
    lowered = out.lower()
    for needle in ("does not exist", "could not find", "invalid service", "bad request"):
        if needle in lowered:
            return False
    return True


def interactive_macos_gui_session() -> bool:
    """Typical: logged-in user at the GUI, ``make test`` from Terminal — no env vars needed."""
    if sys.platform != "darwin" or in_ci_like_environment():
        return False
    return gui_launchd_domain_present()


def env_opt_in(env_key: str) -> bool:
    explicit = os.environ.get(env_key)
    if explicit == "1":
        return True
    if explicit == "0":
        return False
    return interactive_macos_gui_session()


def keychain_integration_enabled() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from secrets_kit.backends.security import check_security_cli
    except ImportError:
        return False
    if not check_security_cli():
        return False
    return env_opt_in("SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS")


def locked_keychain_tests_enabled() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from secrets_kit.backends.security import check_security_cli
    except ImportError:
        return False
    if not check_security_cli():
        return False
    return env_opt_in("SECKIT_RUN_LOCKED_KEYCHAIN_TESTS")


def launchd_tests_enabled() -> bool:
    return env_opt_in("SECKIT_RUN_LAUNCHD_TESTS")


def launchd_login_keychain_enabled() -> bool:
    return env_opt_in("SECKIT_RUN_LAUNCHD_LOGIN_KEYCHAIN_TESTS")


def launchd_service_keychain_enabled() -> bool:
    """Dedicated service-keychain smoke script — opt-in only (``=1``); not part of default ``make test``."""
    explicit = os.environ.get("SECKIT_RUN_LAUNCHD_SERVICE_KEYCHAIN_TESTS")
    if explicit == "0":
        return False
    return explicit == "1"


def launchd_sqlite_enabled() -> bool:
    explicit = os.environ.get("SECKIT_RUN_LAUNCHD_SQLITE_TESTS")
    if explicit == "1":
        return True
    if explicit == "0":
        return False
    if in_ci_like_environment():
        return False
    return launchd_tests_enabled()


_SKIP_INTERACTIVE = f"{SKIP_MACOS_ONLY}; SECKIT_RUN_*=0 off, =1 force"
