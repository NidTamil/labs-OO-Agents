#!/bin/bash
set -euo pipefail
umask 077

if [[ "$(id -u)" != "0" || "$(stat -f -c %T /home/agent)" != "tmpfs" ]]; then
    echo "native runtime requires fresh task home tmpfs" >&2
    exit 1
fi
python3 /usr/local/lib/cybergym/native-home.py
exec /usr/local/bin/cybergym-entrypoint
