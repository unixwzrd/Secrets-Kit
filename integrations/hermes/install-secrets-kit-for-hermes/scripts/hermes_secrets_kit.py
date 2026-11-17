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
_RESERVED_ENV_PREFIXES = ("PYTHON", "CONDA_", "DYLD_", "LD_", "OPENSSL_")
_EXPECTED_MCP_TOOLS = {
    "seckit_status", "seckit_list_secrets", "seckit_get_secret",
}


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    without: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command without a shell or Python/Conda contamination."""
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        capture_output=True,
        cwd=cwd,
        env=_runtime_env(env, without=without),
        timeout=120,
        check=False,
    )


def _runtime_env(source: dict[str, str] | None = None, *, without: tuple[str, ...] = ()) -> dict[str, str]:
    """Copy an environment without Python, Conda, or native-loader overrides."""
    env = dict(os.environ if source is None else source)
    for key in tuple(env):
        if key.startswith(("PYTHON", "CONDA_", "DYLD_", "LD_")) or key in {
            "VIRTUAL_ENV", "OPENSSL_CONF", "OPENSSL_MODULES",
        }:
            env.pop(key, None)
    for key in without:
        env.pop(key, None)
    return env


def _valid_env_name(name: str) -> bool:
    """Reject environment names that can alter Python or native runtime loading."""
    return (
        bool(_NAME.fullmatch(name))
        and name != "VIRTUAL_ENV"
        and not name.startswith(_RESERVED_ENV_PREFIXES)
    )


def _write_private_executable(path: Path, content: str) -> None:
    """Atomically create an owner-only launcher."""
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o700)
    finally:
        if temporary.exists():
            temporary.unlink()


def _private_directory(path: Path) -> None:
    """Create or validate an owner-controlled, non-writable-by-others directory."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
    ):
        raise ValueError(f"unsafe private directory: {path}")


def _runtime_python() -> Path:
    """Select the installed runtime Python reached by the stable client launcher."""
    runtime_dir = Path.home() / ".local/share/seckit/runtime"
    interpreter = runtime_dir / "current" / "bin" / "python"
    info = interpreter.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or not os.access(interpreter, os.X_OK):
        raise ValueError("installed seckit Python runtime is unsafe")
    return interpreter


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
    """Validate current release assets and return the installer and client wheel."""
    requested = args.bundle.expanduser()
    if requested.is_symlink():
        raise ValueError("bundle must not be a symlink")
    bundle = requested.resolve(strict=True)
    if not bundle.is_dir():
        raise ValueError("bundle must be a real directory")
    installer = bundle / "install.sh"
    manifest = bundle / "manifest.sha256"
    source_commit = bundle / "source-commit.txt"
    release_origin = bundle / "release-origin.json"
    pins = bundle / "installer-pins.sha256"
    _regular_owned(manifest)
    wheels = list(bundle.glob("seckit-*-py3-none-any.whl"))
    if len(wheels) != 1:
        raise ValueError("bundle must contain exactly one Secrets Kit wheel")
    expected = args.manifest_sha256.lower()
    if not _SHA256.fullmatch(expected) or _sha256(manifest) != expected:
        raise ValueError("independent manifest SHA-256 mismatch")
    observed_files: set[str] = set()
    observed_hashes: dict[str, str] = {}
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        fields = raw.split(maxsplit=1)
        if len(fields) != 2:
            raise ValueError("invalid bundle manifest")
        digest, name = fields[0].lower(), fields[1].removeprefix("*")
        if not _SHA256.fullmatch(digest) or Path(name).name != name:
            raise ValueError("invalid bundle manifest entry")
        target = bundle / name
        _regular_owned(target)
        if _sha256(target) != digest:
            raise ValueError("bundle manifest verification failed")
        if name in observed_files:
            raise ValueError("duplicate bundle manifest entry")
        observed_files.add(name)
        observed_hashes[name] = digest
    version = args.release_ref.removeprefix("v")
    required = {
        installer.name, source_commit.name, release_origin.name, pins.name,
        wheels[0].name, f"seckit-{version}.tar.gz",
    }
    if not required.issubset(observed_files):
        raise ValueError("supported release assets are missing from the manifest")
    pinned_names: set[str] = set()
    for raw in pins.read_text(encoding="utf-8").splitlines():
        fields = raw.split(maxsplit=1)
        if len(fields) != 2 or not _SHA256.fullmatch(fields[0].lower()):
            raise ValueError("invalid installer dependency pins")
        digest, name = fields[0].lower(), fields[1].removeprefix("*")
        if Path(name).name != name or name in pinned_names or observed_hashes.get(name) != digest:
            raise ValueError("installer dependency pin differs from the release manifest")
        pinned_names.add(name)
    required_manifest_files = required | pinned_names | {"install.sh.sha256"}
    if not required_manifest_files.issubset(observed_files):
        raise ValueError("release manifest is missing required assets")
    commit = source_commit.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid release source commit")
    if wheels[0].name != f"seckit-{version}-py3-none-any.whl":
        raise ValueError("release reference does not match wheel version")
    origin = json.loads(release_origin.read_text(encoding="utf-8"))
    if not isinstance(origin, dict):
        raise ValueError("invalid release origin")
    if (
        origin.get("install_ref") != args.release_ref
        or origin.get("version") != version
        or origin.get("source_commit") != commit
        or origin.get("channel") not in {"release", "prerelease"}
        or not isinstance(origin.get("repository"), str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", origin["repository"])
    ):
        raise ValueError("release origin does not match requested release")
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
    env = _runtime_env()
    env["SECKIT_WHEEL_URL"] = wheel.as_uri()
    env["SECKIT_RUNTIME_PYTHON"] = args.runtime_python
    origin_path = args.bundle.expanduser().resolve(strict=True) / "release-origin.json"
    origin = json.loads(origin_path.read_text(encoding="utf-8"))
    env["SECKIT_GITHUB_REPO"] = str(origin["repository"])
    env["SECKIT_RELEASE_CHANNEL"] = str(origin["channel"])
    command = [
        "bash", str(installer), "--ref", args.release_ref, "--yes", "--no-init",
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
    if not names or len(set(names)) != len(names) or any(not _valid_env_name(name) for name in names):
        raise ValueError("--names must be a unique comma-separated environment allowlist")
    retrieval_names = [
        name.strip() for name in args.mcp_retrieval_names.split(",") if name.strip()
    ]
    if (
        len(set(retrieval_names)) != len(retrieval_names)
        or any(not _valid_env_name(name) for name in retrieval_names)
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
    local_dir = home / ".local"
    _private_directory(local_dir)
    helper_dir = local_dir / "libexec"
    _private_directory(helper_dir)
    helper = helper_dir / "seckit-hermes-env"
    helper_script = helper_dir / "seckit-hermes-env.py"
    mcp_wrapper = helper_dir / "seckit-hermes-mcp"
    config_dir = home / ".config" / "seckit"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if config_dir.is_symlink() or config_dir.stat().st_uid != os.getuid():
        raise ValueError("Secrets Kit configuration directory is unsafe")
    os.chmod(config_dir, 0o700)
    names_file = config_dir / "hermes.env-names"
    mcp_policy = config_dir / "mcp-policy.json"
    source_helper = Path(__file__).with_name("seckit_hermes_env.py")
    runtime_python = _runtime_python()
    for current in (helper, helper_script, mcp_wrapper, names_file, mcp_policy):
        if current.exists():
            _regular_owned(current, executable=current in {helper, mcp_wrapper})
            shutil.copy2(current, backup / current.name)
    manifest = backup / "rollback.json"
    manifest.write_text(json.dumps({
        "config": str(config), "config_backup": str(config_backup),
        "helper": str(helper), "helper_backup": str(backup / helper.name),
        "helper_script": str(helper_script), "helper_script_backup": str(backup / helper_script.name),
        "mcp_wrapper": str(mcp_wrapper), "mcp_wrapper_backup": str(backup / mcp_wrapper.name),
        "names": str(names_file), "names_backup": str(backup / names_file.name),
        "mcp_policy": str(mcp_policy),
        "mcp_policy_backup": str(backup / mcp_policy.name),
    }, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest, 0o600)
    shutil.copy2(source_helper, helper_script)
    os.chmod(helper_script, 0o600)
    shell = "#!/bin/sh\n"
    for variable in (
        "CONDA_PREFIX", "CONDA_DEFAULT_ENV", "CONDA_EXE", "CONDA_SHLVL",
        "CONDA_PYTHON_EXE", "VIRTUAL_ENV", "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH", "LD_PRELOAD",
        "OPENSSL_CONF", "OPENSSL_MODULES",
    ):
        shell += f"unset {variable}\n"
    _write_private_executable(
        helper,
        shell + f"exec {shlex.quote(str(runtime_python))} -I {shlex.quote(str(helper_script))} \"$@\"\n",
    )
    _write_private_executable(
        mcp_wrapper,
        shell + f"exec {shlex.quote(str(runtime_python))} -I -m secrets_kit.mcp_server \"$@\"\n",
    )
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

    helper_command = shlex.join([
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
    if mcp_test.returncode == 0:
        remove = _run([str(hermes), "mcp", "remove", "secrets_kit"], input_text="y\n")
        if remove.returncode != 0:
            raise ValueError("failed replacing the Secrets Kit MCP launcher")
    add = _run(
        [str(hermes), "mcp", "add", "secrets_kit", "--command", shlex.join([str(mcp_wrapper)])],
        input_text="y\n",
    )
    if add.returncode != 0:
        raise ValueError("failed adding isolated Secrets Kit MCP")

    print(json.dumps({"ok": True, "rollback_manifest": str(manifest), "names": len(names)}))
    return 0


def _read_only_mcp_tools(command: Path) -> bool:
    """Check the installed MCP launcher exposes exactly the read-only tool set."""
    requests = "\n".join((
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        "",
    ))
    result = _run([str(command)], input_text=requests)
    if result.returncode != 0:
        return False
    try:
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        tools_response = next(item for item in responses if item.get("id") == 2)
        tools = tools_response["result"]["tools"]
    except (json.JSONDecodeError, KeyError, StopIteration, TypeError):
        return False
    if not isinstance(tools, list) or {tool.get("name") for tool in tools if isinstance(tool, dict)} != _EXPECTED_MCP_TOOLS:
        return False
    return all(
        isinstance(tool, dict)
        and tool.get("annotations", {}).get("readOnlyHint") is True
        and tool.get("annotations", {}).get("destructiveHint") is False
        and tool.get("annotations", {}).get("idempotentHint") is True
        for tool in tools
    )


def verify(args: argparse.Namespace) -> int:
    """Verify installed-product, helper, and MCP behavior without values."""
    hermes = _hermes(args.hermes_command)
    home = Path.home()
    seckit = home / ".local/bin/seckit"
    helper_expected = home / ".local/libexec/seckit-hermes-env"
    mcp_wrapper = home / ".local/libexec/seckit-hermes-mcp"
    doctor = _run([str(seckit), "doctor", "--install-check"])
    mcp = _run([str(hermes), "mcp", "test", "secrets_kit"])
    config_get = _run([str(hermes), "config", "get", "secrets.command.command"])
    mcp_command_get = _run([str(hermes), "config", "get", "mcp_servers.secrets_kit.command"])
    if (
        doctor.returncode != 0 or mcp.returncode != 0 or config_get.returncode != 0
        or mcp_command_get.returncode != 0
        or not _read_only_mcp_tools(mcp_wrapper)
    ):
        return 1
    try:
        mcp_command = shlex.split(mcp_command_get.stdout.strip())
    except ValueError:
        return 1
    if mcp_command != [str(mcp_wrapper)]:
        return 1
    try:
        helper_argv = shlex.split(config_get.stdout.strip())
    except ValueError:
        return 1
    if not helper_argv or Path(helper_argv[0]) != helper_expected:
        return 1
    try:
        names_index = helper_argv.index("--names-file") + 1
        names_file = Path(helper_argv[names_index])
        names = [line.strip() for line in names_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (ValueError, IndexError, OSError, UnicodeDecodeError):
        return 1
    if not names or len(names) > 128 or len(set(names)) != len(names) or any(not _valid_env_name(name) for name in names):
        return 1
    # Clearing the allowlisted names proves the helper can source them from
    # Secrets Kit instead of silently echoing variables inherited from dotenv.
    helper = _run(helper_argv, without=tuple(names))
    lines = [line for line in helper.stdout.splitlines() if line]
    emitted_names = [line.split("=", 1)[0] for line in lines if "=" in line]
    if (
        helper.returncode != 0 or len(lines) != len(names)
        or set(emitted_names) != set(names)
        or any("=" not in line or not line.split("=", 1)[1] for line in lines)
    ):
        return 1
    print(json.dumps({"ok": True, "helper_names": len(lines), "mcp": "connected", "mcp_tools": len(_EXPECTED_MCP_TOOLS), "helper_dotenv_fallback": "not_used"}))
    return 0


def rollback(args: argparse.Namespace) -> int:
    """Restore the prior Hermes config and integration files."""
    manifest_path = args.manifest.expanduser().resolve(strict=True)
    _regular_owned(manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    shutil.copy2(data["config_backup"], data["config"])
    for target_key, backup_key in (
        ("helper", "helper_backup"),
        ("helper_script", "helper_script_backup"),
        ("mcp_wrapper", "mcp_wrapper_backup"),
        ("names", "names_backup"),
        ("mcp_policy", "mcp_policy_backup"),
    ):
        if target_key not in data or backup_key not in data:
            continue
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
        command.add_argument("--manifest-sha256", required=True)
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
