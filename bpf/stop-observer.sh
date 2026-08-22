#!/usr/bin/env bash
# Stop the protectme BPF observer (all instances).
# Usage:
#   ./stop-observer.sh                    # interactive sudo
#   echo 'password' | ./stop-observer.sh  # automation: password from stdin
set -u

while pgrep -x loader >/dev/null 2>&1; do
    if ! sudo -n true 2>/dev/null; then
        IFS= read -r PW || PW=""
        printf '%s\n' "$PW" | sudo -S -v
        exec 0</dev/null
    fi
    sudo pkill -x loader
    sleep 1
done

echo "observer stopped"
