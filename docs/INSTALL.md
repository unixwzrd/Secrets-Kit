# Install Secrets-Kit

**Updated**: 2026-09-26

Canonical operator install for macOS and Linux.

If creation, package installation or pre-activation transport validation fails, the installer preserves its newly created candidate in an owner-only `failed-install.*` recovery directory alongside the runtime directory. The previous installation is unchanged, and the failed candidate is excluded from the executable-generation inventory used by uninstall. Keep the reported recovery directory for diagnosis; it is not automatically deleted. This handling does not adopt or repair older unreceipted/modified runtimes, and it does not move a candidate once activation has begun. Uninstall continues to reject unknown or changed runtime contents.

The normal installer provisions UV and a managed Python runtime; preinstalled Python, pip, Git and GitHub CLI are not prerequisites. Release wheels are preferred. Explicit GitHub branch references without release wheels use a downloaded source archive, without Git. A custom non-GitHub Git URL still requires Git. Private downloads require repository access via `GH_TOKEN`, `GITHUB_TOKEN`, or an existing optional `gh` login; never put credentials in URLs or command arguments. The bootstrap needs Bash, standard platform utilities, and a downloader such as curl or wget. `--safe` and `--no-uv-download` deliberately prohibit bootstrap downloads and are not clean-machine installation defaults; use `--yes --no-shell-profile` for unattended installation with bootstrap enabled. Clean-machine qualification must test this default path without local Python or GitHub tools.

- [Install Secrets-Kit](#install-secrets-kit)
  - [Prerequisites](#prerequisites)
  - [Install](#install)
  - [Upgrade](#upgrade)
  - [Shared-host installation (qualification candidate)](#shared-host-installation-qualification-candidate)
  - [Runtime layout](#runtime-layout)
  - [Verify](#verify)
  - [Validation helpers](#validation-helpers)
  - [Remote install](#remote-install)
  - [Local development (checkout only)](#local-development-checkout-only)
  - [Makefile targets (clone only)](#makefile-targets-clone-only)
  - [Execution modes](#execution-modes)
  - [Troubleshooting](#troubleshooting)
  - [Advanced flags (appendix)](#advanced-flags-appendix)

## Prerequisites

- macOS or Linux
- Network access for first install (runtime bootstrap and release artifacts)

The installer pins `fastecdsa==3.0.1` and `cryptography==50.0.1`. It uses compatible prebuilt dependencies and never silently compiles native cryptography. Intel macOS uses pinned prebuilt publisher packages with metadata-directed OpenSSL relocation inside the isolated UV runtime; no Conda installation or custom native wheel is required. Installed versions, linkage, imports and Noise-only startup are verified before activation. See [NATIVE_DEPENDENCY_RELOCATION_ADR.md](NATIVE_DEPENDENCY_RELOCATION_ADR.md).

For non-editable Intel macOS installs, zeroconf uses its upstream-supported pure-Python path (`SKIP_CYTHON=1`). The UV package-install subprocess searches only the managed runtime's bin directory, preventing optional build probes from invoking Apple's Git/Xcode wrappers. The rest of installation and verification retains its normal environment. This does not introduce a locally maintained native dependency build or downgrade zeroconf below libp2p's requirement.

Customer beta platforms are macOS 14 or newer on ARM64, macOS x86_64, and Linux x86_64. Linux ARM remains an internal relay/infrastructure qualification platform and may use an explicitly enabled internal source build; it is not a supported compiler-free customer beta platform.

End users do not need to install Python, uv, virtual environments, or Git. The installer provisions **Python 3.12** via UV and installs the explicitly selected tag, or the latest release in the active channel when no tag is supplied. Git is only needed for development checkouts or non-release install paths.

## Install

For this private beta, download **`install.sh`** from the maintainer's supplied link. Open Terminal in the download folder and run:

```bash
bash ./install.sh
```

For supported Bash and Zsh shells, the generated single-file installer adds a marked Secrets Kit PATH block to the selected shell profile, including when downloaded and piped into Bash. Open a new terminal after installation, then run:

```bash
seckit --version
seckit doctor --install-check
seckit init
```

The PATH entry exposes stable launchers in `~/.local/bin`, not an internal UV Python or versioned runtime directory. The running installer cannot change its parent shell's environment. For immediate use without opening a new terminal, invoke `"$HOME/.local/bin/seckit"`. Use `--no-shell-profile` to opt out; `--safe` also suppresses profile changes. The underlying source installer retains its explicit `--shell-profile-force` option for unattended use, but users of the generated single-file installer do not need it. Unsupported shells require their own setup; report the shell to the maintainer if the new terminal still cannot find `seckit`. Bash startup-file selection is not a guarantee for every custom shell configuration.

Current uninstall preserves shell profiles, including the marked PATH block. Automatic removal of only the installer-owned, unchanged block is planned. Until implemented, users may remove the section between `# >>> seckit path >>>` and `# <<< seckit path <<<` after uninstall; do not remove unrelated PATH entries, UV installations or shared Python runtimes.

The selected release determines the version. CI records its repository, exact tag (or branch build commit) and update channel in the installer; you do not edit or supply them. This one file contains the pinned application assets and verifies them automatically before invoking the original installer. It downloads the managed runtime and dependencies. No archive extraction, individual packages, manual checksum checks, preinstalled Python, GitHub CLI or API token are needed. Keep the script for reinstall. Existing users should upgrade rather than initialize again.

The same script supports streaming from a **maintainer-supplied direct download URL** accessible to the terminal:

```bash
curl -fsSL "$INSTALLER_URL" | bash
# Alternatively:
wget -qO- "$INSTALLER_URL" | bash
```

These are alternative commands, not additional installation steps. `INSTALLER_URL` must be the supplied script URL, not a GitHub repository page or source archive. No unauthenticated hosting URL is implied here: private GitHub browser sign-in is not inherited by curl or wget. If terminal access to the URL is unavailable, download the single script in your authenticated browser and run it as shown above; do not set up developer tools just to install.

If verification fails, installation stops. Download a fresh script from the maintainer and retry; if it fails again, send a sanitized error, not credentials or full logs. The beta guide covers managed daemon startup and subsequent tests.

### Optional installer checksum

No manual checksum is required for normal installation. For independent comparison before executing a downloaded script, obtain the optional `install.sh.sha256` from the maintainer and run `shasum -a 256 -c install.sh.sha256` on macOS or `sha256sum -c install.sh.sha256` on Linux. A checksum from the same source is an integrity check, not an independent publisher signature. Automatic embedded-file verification does not authenticate a maliciously replaced installer script; obtain the script from the trusted distribution link.

### Advanced installation

The repository's source `install.sh` is the network-fetch engine used for automation and remote installation. The downloadable single-file release `install.sh` contains that engine and its pinned application assets; users keep the same filename across environments. Private network downloads require `GH_TOKEN`, `GITHUB_TOKEN`, or an existing optional `gh` login; browser authentication is not automatically shared with command-line downloads. Never put credentials in URLs or command arguments. Individual release assets and their manifest are maintainer/automation inputs, not the normal beta installation procedure.

## Upgrade

For an existing a22 installation, download the new generated `install.sh` and use the command below for the first upgrade. That older client's built-in downloader has a size limit too small for the new self-contained script. New client builds raise that bounded limit; existing release artifacts are not changed.

```bash
bash ./install.sh --upgrade
```

Or, after install:

```bash
seckit upgrade --check
seckit upgrade
```

`seckit upgrade` resolves an exact newer release tag from the repository and channel recorded by the installer, displays the current and target versions, requires confirmation, then delegates to the same preserving installer used by `seckit install --upgrade`. It rejects branch names, URLs and versions older than the installed version. `seckit upgrade --ref vX.Y.Z --yes` selects one exact non-older release tag for an unattended maintenance window.

An optional same-user daily checker caches only non-secret release status. It never installs automatically and never stores GitHub credentials:

```bash
seckit upgrade service install
seckit upgrade service status
seckit upgrade service uninstall
```

When the cache records a newer release, interactive `seckit status` displays a short notice. JSON status and MCP output remain unchanged. A private repository check without usable account authentication reports unavailable rather than claiming the installed version is current.

Upgrade preserves customer configuration, identity, enrollment and datastore, installs a new isolated runtime generation, and skips `seckit init`. Previous runtime generations are retained, not automatically removed. An installed same-user managed daemon is restarted through the stable launcher; if it cannot recover within the bounded readiness window, the installer attempts to restore the previous runtime and daemon. macOS system-level boot supervision requires the documented administrator-assisted upgrade instead of this user-service path.

Updates are explicitly installed; there is no background automatic installation or fleet-push service. Pin `--ref` to the approved release tag for repeatable upgrades. Private distributions also require the correct `SECKIT_GITHUB_REPO` and authenticated repository access; granting collaborator access does not eliminate authentication. To avoid relying on CLI installer-fetch authentication, run a downloaded and checksum-verified release installer with the existing private-download credentials:

```bash
bash ./install.sh --upgrade --ref "${RELEASE_TAG}" --yes --no-init --no-shell-profile
```

The CLI also exposes `seckit install --upgrade` and `seckit install user@hostname --upgrade --ref "${RELEASE_TAG}"`. A release-wheel installation without a local installer fetches it from the configured installation URL. Remote installation requires SSH access and appropriate download authentication on the target; it does not automatically distribute your local credentials.

## Shared-host installation (qualification candidate)

Before first activation, invoke `host configure` and `host activate` through the staged executable at `PREFIX/runtime/runtime-NAME/bin/seckit`; the stable `PREFIX/bin/seckit` launcher is not active yet.

This administrator path is under DEV qualification and is **not** a released beta procedure. It shares only verified executable code. Each Unix account retains its own initialized store, storage key, peer/node identity, managed daemon, and one-time RSS device enrollment. Host configuration grants neither billing nor peer admission.

Use a different root-owned prefix for each environment, such as `/opt/seckit/dev`, `/opt/seckit/qa`, and `/opt/seckit/production`. System mode requires a preinstalled, trusted, root-owned `uv` at `PREFIX/bin/uv` (or in a root-owned core system directory); it never runs a user-writable `/usr/local` tool or downloads a bootstrap script as root. The verified release installer stages a generation at its final path with `bash install.sh --system --prefix PREFIX --environment ENVIRONMENT --ref TAG`; it does not initialize users or activate code. From the staged CLI, run `seckit host configure --prefix PREFIX --environment ENVIRONMENT --organization NAME --client NAME` once. `Personal` is a valid organization display name. Another host in the same business scope may pass the generated `--organization-id` and `--client-id`, while retaining its own installation UUID. The root-owned `config/host.json` contains only IDs and labels, never credentials. Activate the first generation with the staged CLI's `seckit host activate --prefix PREFIX --generation runtime-NAME`; no users are registered yet, so this only enables the launcher.

After checking and preserving their existing installation, each user explicitly runs `PREFIX/bin/seckit host join --prefix PREFIX --environment ENVIRONMENT` under their own Unix account after initialization. Joining adds local scope metadata and a stable principal; it does not rewrite historical transactions or signatures, authorize peers, or reenroll RSS. The user installs their managed service via `PREFIX/bin/seckit daemon service install`. The administrator verifies that service uses that exact launcher and runs `PREFIX/bin/seckit host register --prefix PREFIX --user USER`. Later, after staging an exact new generation, the administrator runs `PREFIX/bin/seckit host activate --prefix PREFIX --generation runtime-NAME`. Activation switches code once, restarts registered user services sequentially, checks health and version, and restores the previous code pointer on failure without restoring user stores. A failed user restart still requires operator investigation.

Existing per-user installations remain unchanged until explicitly opted in. Installed macOS/Linux, historical-data preservation, and rolling-upgrade qualification must pass before this path is offered to beta testers.

## Runtime layout

| Path | Purpose |
| --- | --- |
| `~/.local/bin/seckit` | Launcher shim |
| `~/.local/share/seckit/runtime/` | Isolated uv venv generations |
| `~/.local/share/seckit/runtime/current` | Canonical runtime symlink (launcher target) |
| `~/.local/share/seckit/state/runtime-path` | Legacy pointer kept for older `doctor --install-check` builds |
| `~/.local/share/seckit/state/runtime.json` | Python version, release ref, package source |
| `~/.config/seckit/install.json` | Installed version, release ref, package source, and `verified` flag (set after successful post-install checks) |
| `~/.config/seckit/defaults.json` | Operator defaults |

## Verify

```bash
seckit --version
seckit info
seckit doctor --install-check
```

`--install-check` is fast (launcher, seeds, writable config; no backend roundtrip).

## Validation helpers

After installation, verify the installed product with the commands in [Verify](#verify). Release qualification runs against the published installed product from the separate engineering qualification workspace; it does not use an editable checkout. Developer-only qualification may use an explicit checkout for rapid feedback, but is not release evidence.

From a development clone, the product-owned validation helpers remain:

```bash
bash scripts/install-validation.sh
bash scripts/upgrade-validation.sh
```

## Remote install

First-time SSH setup: [QUICK_SSH_SETUP.md](QUICK_SSH_SETUP.md). Once SSH works, use the customer-facing install command from the initiating machine:

```bash
seckit install @host
seckit install seckit@other-host
```

Remote targets must include `@` (`@host` uses your local `$USER`; `user@host` sets the SSH user). Remote install implies `--yes` (non-interactive).

Remote install pins the **release wheel** for the caller’s version (`v` + `seckit --version`) via `SECKIT_REF` on the remote host (no `git` required). Override with `--ref TAG` only when an exact qualified release tag has been approved for that installation.

Remote install is installation only. It does not exchange peer identity keys, register peers, authorize service groups, configure synchronization trust, or perform authenticated peer bootstrap. A future `seckit username@host` bootstrap ceremony may combine install, identity exchange, explicit peer registration, static connectivity setup, and authenticated connectivity checks, but that is a separate peer-admission workflow and not implemented by the current install command.

When peer bootstrap is implemented, each node must generate or import its own long-lived signing and encryption keypairs during install/init. Private keys must remain on their originating node. Public keys and fingerprints are exchanged only during explicit peer admission. Node identity keys are distinct from the local SQLite storage key, and SQLite storage keys must not be shared between real peers.

For SQLite, current initialization provisions standalone local node identity material at `~/.config/seckit/node-identity.key` and stores only public keys plus private-key references in the SQLite `nodes` and `node_private` tables.
Normal runtime validates this identity state and does not silently repair it.

SQLite initialization also records an immutable datastore storage mode:

```bash
seckit init
```

Encrypted mode requires the local SQLite storage key. Plaintext mode is explicit, reports through `seckit info`, warns operators that local SQLite secret bytes are stored unencrypted, and is intended for controlled local synchronization testing before authenticated peer-envelope encryption exists.
The mode is persisted inside the SQLite database and is not switchable at runtime.

## Local development (checkout only)

From a git clone — not for operator `curl|bash`/`wget|bash`:

```bash
make install-dev
# or
./install.sh --dev
```

Uses editable install from the local checkout. Pin a git ref with `./install.sh --ref TAG` when testing non-release builds.

## Makefile targets (clone only)

| Target | Action |
| --- | --- |
| `make install` | Run `./install.sh` |
| `make install-dev` | Run `./install.sh --dev` |
| `make install-upgrade` | Run `./install.sh --upgrade` |
| `make install-check` | `seckit doctor --install-check` |

## Execution modes

- Default: concise progress output, quiet dependency chatter.
- `--verbose`: interpreter resolution, release selection, subprocess detail.
- Debug: pipe to `SECKIT_DEBUG=1 bash` for shell-level tracing.

## Troubleshooting

### Why does synchronization stop after logout on Linux?

On Linux with systemd user services, unattended synchronization requires the user's service manager to remain running after logout. Check `seckit daemon service status`; `linger: false` means this account has not enabled that behavior. After a successful Linux same-user service install, the installer prints a nonfatal warning in that case. Installation still completes; linger is not a prerequisite, and macOS is unchanged.

Ask an administrator to run the following as root, replacing `USERNAME` with the account running Secrets Kit:

```bash
loginctl enable-linger USERNAME
```

Then, as that ordinary user:

```bash
seckit daemon start
seckit daemon service status
```

Expect `linger: true`, `active: true` and `daemon_reachable: true`. With the user service installed/enabled, lingering permits startup at boot without an interactive login and continued operation after logout. It is a per-account Linux/systemd setting, not a requirement for installation or interactive CLI use. Do not run Secrets Kit itself as root. macOS uses launchd instead; this command does not apply there.

- `no GitHub release found`: no prerelease exists for the dev channel, or no stable release for the release channel.
- `no compatible release artifact found`: release assets missing; maintainer must publish the universal wheel and sdist.
- `runtime bootstrap unavailable` with `--safe` or `--no-uv-download`: remove those flags, or preinstall uv and `uv python install 3.12`.
- `need 'tar' (command not found)` during runtime bootstrap on minimal Linux: current installer falls back to a direct GitHub `uv` release when `tar` is missing (uses `python3` to unpack if needed). If both fail, install `tar` (`dnf install -y tar` on Rocky) or ensure `python3` is on `PATH`.
- Remote install over SSH with a bare `PATH`: the installer prepends standard system bin directories; you can also `export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"` before running.
- `git` / `git clone` errors on minimal Debian: default install uses the **release wheel** (no git). Git is only needed for non-tag refs (e.g. `--ref dev`) when no wheel exists. `seckit install user@host` pins the remote version via `SECKIT_REF` and the wheel, not `git+https://…`.
- `seckit: command not found`: add `~/.local/bin` to PATH (installer prints the line when it cannot edit your shell profile).
- `defaults.account` shows `root` after a sudo install: rerun `seckit init --yes` as the operator user.
- Cross-host TCP connection or receive failures while local operation works: verify that the Python interpreter executing the daemon is permitted to make and accept TCP connections by the host operating-system firewall and any endpoint-security or network-filtering software. These policies are an operating-system administration responsibility and can block peer communication even when Secrets-Kit is functioning correctly.
- Large `~/.cache/uv` after install: expected; the installer does not use a separate Secrets-Kit cache directory.

### LAN discovery works, but secrets do not synchronize

Discovery and delivery use different network traffic. Allowing mDNS does not also allow incoming peer TCP connections. Secrets Kit selects a dynamic listener port; an allowance for a previously used port is not sufficient after a restart or for another user on the same host. Inspect `seckit status --json`: `local_endpoint.host` and `local_endpoint.port` identify the current listener. Discovery candidates alone do not prove authenticated connectivity or successful synchronization.

On Linux with firewalld, an administrator can inspect the active interface zone using `firewall-cmd --get-active-zones`, then `firewall-cmd --zone=ZONE --list-all`. Check the actual LAN interface, mDNS allowance and incoming TCP policy. For diagnosis, use a temporary rule limited to the known peer's LAN address and the current listener port; recheck the endpoint after any daemon restart. A one-port diagnostic rule is not a persistent solution for dynamic listeners. Do not disable the firewall, trust an entire network or open all high ports as a routine installation step. A durable policy for dynamic listeners on restrictive port-based firewalls remains an unqualified deployment requirement; the installer does not automatically manage those rules.

On macOS, check the Python interpreter actually running this user's daemon, rather than another Python installation or another user's allowance. Also check separately installed network filters. An allow-list entry alone does not establish successful connectivity. Do not broaden home-directory permissions to browse to an interpreter in a graphical firewall dialog; use administrator-assisted configuration instead.

For firewalld administrators, inspect the active zone and current listener first:

```bash
firewall-cmd --get-active-zones
ss -ltnp
```

Identify the Secrets Kit daemon's actual listening TCP port, the LAN interface's zone and the other peer's LAN address. Replace `ZONE`, `PEER_IPV4` and `LISTENER_PORT` below before running as an administrator; these are placeholders, not fixed application values:

```bash
sudo firewall-cmd --zone=ZONE \
  --add-rich-rule='rule family="ipv4" source address="PEER_IPV4/32" port port="LISTENER_PORT" protocol="tcp" accept' \
  --timeout=1h
```

This diagnostic allowance expires automatically after one hour. It covers only that IPv4 peer and current TCP port, not discovery, IPv6 or other peers. Check the applicable mDNS service policy separately. Confirm connectivity from the other LAN machine; a local self-connection is not proof of LAN reachability, and a failed remote connection does not alone identify which firewall or network component blocked it. Permanent policy requires administrator review. The current installer neither generates this host-specific command nor prompts through polkit; both are planned usability improvements. Do not run the entire client installer or daemon as root.

These checks concern customer LAN peers, not the private operator console or hosted RSS administration. Local secret use does not require incoming LAN connectivity. Record the OS, listener address/port, active interface and exact connection failure when requesting support; do not include secret values, credential files or full identity exports.

## Advanced flags (appendix)

- `--upgrade` update package/runtime; skip `seckit init`
- `--dev` editable install from a local checkout (`SECKIT_INSTALL_ROOT`, default `PWD`)
- `--ref TAG` pin a published release tag; the release wheel is preferred and Git is only a maintainer fallback when that wheel is absent
- `--yes` non-interactive mode when init would prompt
- `--no-init` install package only; skip `seckit init`
- `--no-verify` skip post-install `seckit doctor --install-check`
- `--skip-verify-if-unchanged` skip verification when `install.json` already records this ref and package source as verified (speeds repeat installs of the same wheel)
- `--verbose`, `--repair`, `--safe`, `--no-uv-download`, `--no-shell-profile`, `--shell-profile-force`

Environment overrides:

- `SECKIT_RELEASE_CHANNEL=prerelease|release` choose latest prerelease vs stable release
- `SECKIT_INSTALL_BRANCH=dev|main` development-only branch override; it is not used by the canonical release path
- `SECKIT_RUNTIME_PYTHON=3.12` pin uv-managed Python series
- `SECKIT_REF=vX.Y.Z` pin a specific release tag
- `SECKIT_WHEEL_URL=URL` force a specific wheel or sdist URL (testing)
- `SECKIT_UV_RELEASE_BASE=URL` base URL for direct `uv` tarball bootstrap (default: Astral GitHub latest)
- `SECKIT_UV_RELEASE_URL=URL` full tarball URL override (skips arch detection)

See also: [QUICKSTART.md](QUICKSTART.md) (operator workflow), [CLI_REFERENCE.md](CLI_REFERENCE.md).
