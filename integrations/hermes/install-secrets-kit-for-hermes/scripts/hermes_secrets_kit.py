#!/usr/bin/env python3
"""Install, configure, verify, or roll back Secrets Kit for Hermes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command without a shell or inherited stdin."""
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        cwd=cwd,
        timeout=120,
        check=False,
    )


def _sha256(path: Path) -> str:
    """Return the SHA-256 of one regular file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_owned(path: Path, *, executable: bool = False) -> None:
    """Reject symlinks, foreign ownership, and group/world-writable files."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError(f"not a regular file: {path}")
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise ValueError(f"unsafe ownership or mode: {path}")
    if executable and not os.access(path, os.X_OK):
        raise ValueError(f"not executable: {path}")


def _write_private_json(path: Path, payload: dict[str, object]) -> None:
    """Atomically write owner-only integration configuration."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ValueError("private configuration directory must not be a symlink")
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _bundle(args: argparse.Namespace) -> tuple[Path, Path]:
    """Validate the pinned release bundle and return installer and wheel."""
    bundle = args.bundle.expanduser().resolve(strict=True)
    if not bundle.is_dir() or bundle.is_symlink():
        raise ValueError("bundle must be a real directory")
    installer = bundle / "install.sh"
    release_id = bundle / "release-id"
    manifest = bundle / "manifest.sha256"
    wheels = list(bundle.glob("seckit-*-py3-none-any.whl"))
    if len(wheels) != 1:
        raise ValueError("bundle must contain exactly one Secrets Kit wheel")
    for path in (installer, release_id, manifest, wheels[0]):
        _regular_owned(path, executable=path == installer)
    expected = args.wheel_sha256.lower()
    if not _SHA256.fullmatch(expected) or _sha256(wheels[0]) != expected:
        raise ValueError("wheel SHA-256 mismatch")
    if args.release_ref.removeprefix("v") not in wheels[0].name:
        raise ValueError("release reference does not match wheel name")
    expected_files = {installer.name, release_id.name, wheels[0].name}
    observed_files: set[str] = set()
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        fields = raw.split(maxsplit=1)
        if len(fields) != 2:
            raise ValueError("invalid bundle manifest")
        digest, name = fields[0].lower(), fields[1].removeprefix("*")
        if not _SHA256.fullmatch(digest) or Path(name).name != name:
            raise ValueError("invalid bundle manifest entry")
        target = bundle / name
        _regular_owned(target, executable=target == installer)
        if _sha256(target) != digest:
            raise ValueError("bundle manifest verification failed")
        observed_files.add(name)
    if observed_files != expected_files:
        raise ValueError("bundle manifest layout mismatch")
    return installer, wheels[0]


def _hermes(path: Path) -> Path:
    """Validate the explicit Hermes executable."""
    resolved = path.expanduser().resolve(strict=True)
    _regular_owned(resolved, executable=True)
    return resolved


def preflight(args: argparse.Namespace) -> int:
    """Validate all immutable installation inputs."""
    _, wheel = _bundle(args)
    hermes = _hermes(args.hermes_command)
    print(json.dumps({"ok": True, "wheel": wheel.name, "hermes": str(hermes)}))
    return 0


def install(args: argparse.Namespace) -> int:
    """Install the verified local wheel through the supported installer."""
    installer, wheel = _bundle(args)
    _hermes(args.hermes_command)
    env = os.environ.copy()
    env["SECKIT_WHEEL_URL"] = wheel.as_uri()
    env["SECKIT_RUNTIME_PYTHON"] = args.runtime_python
    command = [
        str(installer), "--ref", args.release_ref, "--yes", "--no-init",
        "--no-shell-profile", "--json",
    ]
    result = subprocess.run(command, text=True, env=env, timeout=900, check=False)
    if result.returncode != 0:
        return result.returncode
    database = Path.home() / ".config" / "seckit" / "seckit.sqlite"
    if not database.exists():
        init = _run([str(Path.home() / ".local/bin/seckit"), "init", "--backend", "sqlite", "--yes"])
        if init.returncode != 0:
            return init.returncode
    return 0


def _dotenv_values(path: Path) -> list[str]:
    """Read values only for leakage detection; never return them to output."""
    values: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            value = line.split("=", 1)[1].strip().strip("\"'")
            if value:
                values.append(value)
    return values


def configure(args: argparse.Namespace) -> int:
    """Import dotenv values and configure the command source plus MCP."""
    hermes = _hermes(args.hermes_command)
    dotenv = args.dotenv.expanduser().resolve(strict=True)
    _regular_owned(dotenv)
    if dotenv.stat().st_uid != os.getuid() or dotenv.stat().st_mode & 0o077:
        raise ValueError("dotenv mode must be 0600 or stricter")
    names = [name.strip() for name in args.names.split(",") if name.strip()]
    if not names or len(set(names)) != len(names) or any(not _NAME.fullmatch(n) for n in names):
        raise ValueError("--names must be a unique comma-separated environment allowlist")
    retrieval_names = [
        name.strip() for name in args.mcp_retrieval_names.split(",") if name.strip()
    ]
    if (
        len(set(retrieval_names)) != len(retrieval_names)
        or any(not _NAME.fullmatch(name) for name in retrieval_names)
        or not set(retrieval_names).issubset(names)
    ):
        raise ValueError("--mcp-retrieval-names must be a unique subset of --names")

    home = Path.home()
    hermes_home = Path(os.environ.get("HERMES_HOME", home / ".hermes")).expanduser()
    config = hermes_home / "config.yaml"
    _regular_owned(config)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    backup = hermes_home / "backups" / f"secrets-kit-{stamp}"
    backup.mkdir(parents=True, mode=0o700)
    config_backup = backup / "config.yaml"
    shutil.copy2(config, config_backup)
    os.chmod(config_backup, 0o600)

    seckit = (home / ".local/bin/seckit").resolve(strict=True)
    mcp = (home / ".local/bin/seckit-mcp").resolve(strict=True)
    helper_dir = home / ".local/libexec"
    helper_dir.mkdir(parents=True, exist_ok=True)
    helper = helper_dir / "seckit-hermes-env"
    config_dir = home / ".config" / "seckit"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if config_dir.is_symlink() or config_dir.stat().st_uid != os.getuid():
        raise ValueError("Secrets Kit configuration directory is unsafe")
    os.chmod(config_dir, 0o700)
    names_file = config_dir / "hermes.env-names"
    mcp_policy = config_dir / "mcp-policy.json"
    source_helper = Path(__file__).with_name("seckit_hermes_env.py")
    for current in (helper, names_file, mcp_policy):
        if current.exists():
            _regular_owned(current, executable=current == helper)
            shutil.copy2(current, backup / current.name)
    shutil.copy2(source_helper, helper)
    os.chmod(helper, 0o700)
    names_file.write_text("".join(f"{name}\n" for name in names), encoding="utf-8")
    os.chmod(names_file, 0o600)
    _write_private_json(
        mcp_policy,
        {
            "version": 1,
            "backend": args.backend,
            "service": args.service,
            "account": args.account,
            "metadata_names": names,
            "retrieval_names": retrieval_names,
        },
    )

    base = [
        str(seckit), "import", "env", "--dotenv", str(dotenv),
        "--names", ",".join(names),
        "--account", args.account, "--service", args.service,
        "--backend", args.backend, "--kind", "token", "--yes",
    ]
    values = _dotenv_values(dotenv)
    dry = _run(base + ["--dry-run"])
    if dry.returncode != 0 or any(
        len(value) >= 16 and value in dry.stdout + dry.stderr for value in values
    ):
        raise ValueError("redacted dotenv dry-run failed")
    applied = _run(base + ["--upsert"])
    if applied.returncode != 0 or any(
        len(value) >= 16 and value in applied.stdout + applied.stderr for value in values
    ):
        raise ValueError("redacted dotenv import failed")

    managed = _run([str(seckit), "daemon", "service", "install"])
    if managed.returncode != 0:
        raise ValueError("failed installing the managed Secrets Kit daemon service")

    helper_command = " ".join([
        str(helper), "--seckit", str(seckit), "--names-file", str(names_file),
        "--account", args.account, "--service", args.service, "--backend", args.backend,
    ])
    settings = (
        ("secrets.command.enabled", "true"),
        ("secrets.command.command", helper_command),
        ("secrets.command.helper_timeout_seconds", "5"),
        ("secrets.command.override_existing", "false"),
    )
    for key, value in settings:
        result = _run([str(hermes), "config", "set", key, value, "--force"])
        if result.returncode != 0:
            raise ValueError(f"failed setting {key}")
    mcp_test = _run([str(hermes), "mcp", "test", "secrets_kit"])
    if mcp_test.returncode != 0:
        add = _run([str(hermes), "mcp", "add", "secrets_kit", "--command", str(mcp)], input_text="y\n")
        if add.returncode != 0:
            raise ValueError("failed adding Secrets Kit MCP")

    manifest = backup / "rollback.json"
    manifest.write_text(json.dumps({
        "config": str(config), "config_backup": str(config_backup),
        "helper": str(helper), "helper_backup": str(backup / helper.name),
        "names": str(names_file), "names_backup": str(backup / names_file.name),
        "mcp_policy": str(mcp_policy),
        "mcp_policy_backup": str(backup / mcp_policy.name),
    }, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest, 0o600)
    print(json.dumps({"ok": True, "rollback_manifest": str(manifest), "names": len(names)}))
    return 0


def verify(args: argparse.Namespace) -> int:
    """Verify installed-product, helper, and MCP behavior without values."""
    hermes = _hermes(args.hermes_command)
    seckit = Path.home() / ".local/bin/seckit"
    doctor = _run([str(seckit), "doctor", "--install-check"])
    mcp = _run([str(hermes), "mcp", "test", "secrets_kit"])
    config_get = _run([str(hermes), "config", "get", "secrets.command.command"])
    if doctor.returncode != 0 or mcp.returncode != 0 or config_get.returncode != 0:
        return 1
    helper_command = config_get.stdout.strip()
    helper = _run(shlex.split(helper_command))
    lines = [line for line in helper.stdout.splitlines() if line]
    if helper.returncode != 0 or not lines or any(not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.+$", line) for line in lines):
        return 1
    print(json.dumps({"ok": True, "helper_names": len(lines), "mcp": "connected"}))
    return 0


def rollback(args: argparse.Namespace) -> int:
    """Restore the prior Hermes config and integration files."""
    manifest_path = args.manifest.expanduser().resolve(strict=True)
    _regular_owned(manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    shutil.copy2(data["config_backup"], data["config"])
    for target_key, backup_key in (
        ("helper", "helper_backup"),
        ("names", "names_backup"),
        ("mcp_policy", "mcp_policy_backup"),
    ):
        target = Path(data[target_key])
        saved = Path(data[backup_key])
        if saved.exists():
            shutil.copy2(saved, target)
        elif target.exists():
            target.unlink()
    print(json.dumps({"ok": True, "restored": str(data["config"])}))
    return 0


def parser() -> argparse.ArgumentParser:
    """Build the bounded command-line interface."""
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="action", required=True)
    for action in ("preflight", "install"):
        command = sub.add_parser(action)
        command.add_argument("--bundle", type=Path, required=True)
        command.add_argument("--release-ref", required=True)
        command.add_argument("--wheel-sha256", required=True)
        command.add_argument("--hermes-command", type=Path, required=True)
        command.add_argument("--runtime-python", default="3.12")
        command.set_defaults(function=preflight if action == "preflight" else install)
    command = sub.add_parser("configure")
    command.add_argument("--hermes-command", type=Path, required=True)
    command.add_argument("--dotenv", type=Path, required=True)
    command.add_argument("--account", required=True)
    command.add_argument("--service", required=True)
    command.add_argument("--backend", choices=("keychain", "sqlite"), default="sqlite")
    command.add_argument("--names", required=True)
    command.add_argument("--mcp-retrieval-names", default="")
    command.set_defaults(function=configure)
    command = sub.add_parser("verify")
    command.add_argument("--hermes-command", type=Path, required=True)
    command.set_defaults(function=verify)
    command = sub.add_parser("rollback")
    command.add_argument("--manifest", type=Path, required=True)
    command.set_defaults(function=rollback)
    return root


def main() -> int:
    """Dispatch one action and render failures without sensitive values."""
    args = parser().parse_args()
    try:
        return int(args.function(args))
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(
            f"Secrets Kit Hermes integration failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
