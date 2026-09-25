# Quick SSH Setup

- [Quick SSH Setup](#quick-ssh-setup)
  - [Goal](#goal)
  - [Generate an SSH key if needed](#generate-an-ssh-key-if-needed)
  - [Install the public key with ssh-copy-id](#install-the-public-key-with-ssh-copy-id)
  - [Manual authorized\_keys fallback](#manual-authorized_keys-fallback)
  - [Verify SSH works](#verify-ssh-works)
  - [Run Secrets-Kit remote install](#run-secrets-kit-remote-install)

Use this when you want to install Secrets-Kit on another machine with:

```bash
seckit install user@host
```

## Goal

Set up ordinary SSH access from your current machine to the target host. Secrets-Kit remote install uses SSH; it does not configure SSH for you.

## Generate an SSH key if needed

If you do not already have an SSH key, create one:

```bash
ssh-keygen -t ed25519 -C "$USER@$(hostname)"
```

Press Enter to accept the default file location unless you have a reason to choose another path.

## Install the public key with ssh-copy-id

If `ssh-copy-id` is available:

```bash
ssh-copy-id user@host
```

Replace `user` with the login user on the remote host, and replace `host` with the hostname or address you SSH to.

## Manual authorized_keys fallback

If `ssh-copy-id` is not available, copy your public key manually:

```bash
cat ~/.ssh/id_ed25519.pub
```

On the remote host, append that line to:

```bash
~/.ssh/authorized_keys
```

Make sure the remote SSH files have normal SSH permissions:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

## Verify SSH works

From your current machine:

```bash
ssh user@host 'echo ok'
```

The command should print:

```text
ok
```

## Run Secrets-Kit remote install

After SSH works:

```bash
seckit install user@host
```

Remote install requires a target containing `@`. Use `user@host` to set the remote login user.
