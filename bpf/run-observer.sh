#!/usr/bin/env bash
# Start the protectme BPF observer in the background.
# Usage:
#   ./run-observer.sh [logfile]           # interactive: sudo prompts normally
#   echo 'password' | ./run-observer.sh   # automation: password from stdin
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="${1:-/tmp/pm-observe.log}"

if pgrep -x loader >/dev/null 2>&1; then
    echo "loader already running: $(pgrep -ax loader)"
    exit 0
fi

[ -x "$DIR/loader" ] || (cd "$DIR" && make >/dev/null)

if ! sudo -n true 2>/dev/null; then
    IFS= read -r PW || PW=""
    printf '%s\n' "$PW" | sudo -S -v
    exec 0</dev/null
fi

sudo -b bash -c "cd '$DIR' && exec setsid ./loader > '$LOG' 2>&1"
sleep 2

if pgrep -x loader >/dev/null 2>&1; then
    echo "observer running (pid $(pgrep -x loader)) -> $LOG"
else
    echo "FAILED to start observer; see $LOG" >&2
    exit 1
fi
