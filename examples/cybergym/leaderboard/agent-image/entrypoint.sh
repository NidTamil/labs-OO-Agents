#!/bin/bash
set -euo pipefail
umask 077

if [[ "$(id -u)" != "0" ]]; then
    echo "task startup requires root PID 1" >&2
    exit 1
fi

if [[ -z "${CYBERGYM_SSH_PUBLIC_KEY:-}" || "${CYBERGYM_SSH_PUBLIC_KEY}" != ssh-ed25519\ * || "${CYBERGYM_SSH_PUBLIC_KEY}" == *$'\n'* ]]; then
    echo "task SSH public key is missing or malformed" >&2
    exit 1
fi

if [[ -e /var/run/docker.sock || -e /srv || -e /root ]]; then
    echo "forbidden host interface visible in task image" >&2
    exit 1
fi

for task_tmpfs in /tmp /run /home/agent /workspace/src; do
    if [[ "$(stat -f -c %T "$task_tmpfs")" != "tmpfs" ]]; then
        echo "required task tmpfs is absent" >&2
        exit 1
    fi
done

if ! findmnt -n -o OPTIONS --target /workspace | tr ',' '\n' | grep -qx ro; then
    echo "task bundle is not read-only" >&2
    exit 1
fi
if ! findmnt -n -o OPTIONS --target /workspace/output | tr ',' '\n' | grep -qx rw; then
    echo "task output is not writable" >&2
    exit 1
fi

chmod 0700 /home/agent
chmod 1777 /tmp
chown agent:agent /home/agent /workspace/src /workspace/output

if [[ ! -f /workspace/repo-vul.tar.gz ]]; then
    echo "vulnerable source archive is missing" >&2
    exit 1
fi

# Extraction happens as the unprivileged task user. The pinned image's
# extractor validates paths and link targets before creating any source file.
env -u CYBERGYM_TASK_TOKEN -u CYBERGYM_SSH_PUBLIC_KEY \
    runuser -u agent -- python3 /usr/local/bin/cybergym-extract \
        /workspace/repo-vul.tar.gz /workspace/src

# This is a startup gate: no SSH session or model request can begin before
# every extracted Git metadata path and the known stale PoC path disappear.
find /workspace/src -name .git -prune -exec rm -rf -- {} +
rm -rf -- /tmp/poc
if [[ -n "$(find /workspace/src -name .git -print -quit)" || -e /tmp/poc ]]; then
    echo "task source cleanup failed" >&2
    exit 1
fi

install -d -m 0755 -o root -g root /run/ssh
install -d -m 0755 -o root -g root /run/sshd
printf '%s\n' "$CYBERGYM_SSH_PUBLIC_KEY" > /run/ssh/authorized_keys
chmod 0644 /run/ssh/authorized_keys
if ! ssh-keygen -l -f /run/ssh/authorized_keys >/dev/null 2>&1; then
    echo "task SSH public key is invalid" >&2
    exit 1
fi

ssh-keygen -q -t ed25519 -N '' -C '' -f /run/ssh/ssh_host_ed25519_key
chmod 0600 /run/ssh/ssh_host_ed25519_key
/usr/sbin/sshd -t -f /etc/ssh/sshd_config

host_public="$(awk '{print $1 " " $2}' /run/ssh/ssh_host_ed25519_key.pub)"
host_fingerprint="$(ssh-keygen -l -E sha256 -f /run/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"
printf 'CYBERGYM_SSH_HOST_KEY_PUBLIC=%s\n' "$host_public"
printf 'CYBERGYM_SSH_HOST_KEY_FINGERPRINT=%s\n' "$host_fingerprint"

# sshd is PID 1. Its authenticated sessions are always the non-root agent.
unset CYBERGYM_SSH_PUBLIC_KEY CYBERGYM_TASK_TOKEN
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
