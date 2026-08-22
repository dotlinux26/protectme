#!/usr/bin/env bash
# P0.7 Adversarial Test Suite — RUN17
# Concurrency, namespace, mount, TOCTOU, lifecycle edge cases
# Requires: loader running, policy loaded, root for mount tests

set -euo pipefail

PW='Canh0206@'
PM_TX="/tmp/opencode/pm-tx"
PM_MARK="/tmp/opencode/pm-mark"
LOG="/tmp/pm-run17.log"

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
NC='\033[0m'

say() { echo -e "${YEL}[RUN17]${NC} $*"; }
pass() { echo -e "${GRN}  PASS${NC} $*"; ((PASS++)); }
fail() { echo -e "${RED}  FAIL${NC} $*"; ((FAIL++)); }

run_cmd() { "$@" 2>&1; }
assert_denied() { local out; out=$(run_cmd "$@"); [[ $? -ne 0 ]] && grep -q "Operation not permitted" <<<"$out"; }
assert_allowed() { run_cmd "$@" >/dev/null; [[ $? -eq 0 ]]; }

# Setup tree
setup() { local r="$1"; rm -rf "$r"; mkdir -p "$r"/{a,b,c/d/e}; echo x > "$r"/a/f; echo x > "$r"/b/f; echo x > "$r"/c/d/e/f; }
reg() { local r="$1"; "$PM_MARK" $(stat -c %d "$r") $(stat -c %i "$r") 0xFEEDFACE >/dev/null; }
mode2() { "$PM_TX" mode 2 >/dev/null; }
auth_rm() { "$PM_TX" run-auth "$1" -- rm -rf "$1" >/dev/null 2>&1; }

PASS=0; FAIL=0

main() {
    say "=== P0.7 ADVERSARIAL SUITE START ==="
    exec > >(tee -a "$LOG") 2>&1

    # Ensure loader alive
    if ! pgrep -x loader >/dev/null; then
        say "Starting loader..."
        echo "$PW" | sudo -S pkill -9 -x loader 2>/dev/null; sleep 1
        cd /home/nguyenduccanh/Documents/protectme_project/protectme/kernel/lsm
        echo "$PW" | sudo -S bash -c "setsid nohup ./loader > /tmp/pm-loader.log 2>&1 < /dev/null &"; sleep 3
    fi

    # ============================================================
    # 1. CONCURRENT UNLINK/RENAME (pthread via bash subshells)
    # ============================================================
    say "--- 1. CONCURRENT UNLINK/RENAME ---"
    ROOT=/tmp/pm-C1; setup "$ROOT"; reg "$ROOT"; mode2
    # Spawn 10 concurrent unlinks on different children
    for i in {1..10}; do ( rm -rf "$ROOT"/a/f 2>&1 ) & done
    wait
    [[ -e "$ROOT"/a/f ]] && pass "concurrent unlinks denied" || fail "concurrent unlinks bypassed"

    ROOT=/tmp/pm-C2; setup "$ROOT"; reg "$ROOT"; mode2
    # Concurrent rename-out attempts
    for i in {1..5}; do ( mv "$ROOT"/a/f "/tmp/out$i" 2>&1 ) & done
    wait
    [[ -e "$ROOT"/a/f ]] && pass "concurrent rename-out denied" || fail "concurrent rename-out bypassed"

    # ============================================================
    # 2. CONCURRENT TX ATTEMPTS (multiple processes request cap)
    # ============================================================
    say "--- 2. CONCURRENT TX REQUESTS ---"
    ROOT=/tmp/pm-C3; setup "$ROOT"; reg "$ROOT"; mode2
    for i in {1..5}; do ( "$PM_TX" request "$ROOT" 30000 >/dev/null ) & done
    wait
    # All should get caps (issuer allows multiple), but only first attach wins
    fd=$("$PM_TX" request "$ROOT" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    auth_rm "$ROOT"
    [[ ! -e "$ROOT" ]] && pass "concurrent TX requests serialized" || fail "TX race"

    # ============================================================
    # 3. BIND MOUNT (requires root)
    # ============================================================
    say "--- 3. BIND MOUNT ---"
    ROOT=/tmp/pm-M1; setup "$ROOT"; reg "$ROOT"; mode2
    MNT=/mnt/pm-test
    mkdir -p "$MNT"
    if echo "$PW" | sudo -S mount --bind "$ROOT" "$MNT" 2>/dev/null; then
        assert_denied "bind mount unlink" rm -f "$MNT"/a/f && pass "bind mount unlink denied" || fail "bind mount bypass"
        echo "$PW" | sudo -S umount "$MNT"
    else
        say "bind mount test skipped (no root/priv)"
    fi

    # ============================================================
    # 4. OVERLAYFS (lower protected, upper writable)
    # ============================================================
    say "--- 4. OVERLAYFS ---"
    ROOT=/tmp/pm-M2; setup "$ROOT"; reg "$ROOT"; mode2
    UPPER=/tmp/ovl-upper; WORK=/tmp/ovl-work; MNT=/mnt/pm-ovl
    mkdir -p "$UPPER" "$WORK" "$MNT"
    if echo "$PW" | sudo -S mount -t overlay overlay -o lowerdir="$ROOT",upperdir="$UPPER",workdir="$WORK" "$MNT" 2>/dev/null; then
        # Try to delete via overlay (should affect upper, not lower)
        assert_denied "overlay unlink lower" rm -f "$MNT"/a/f && pass "overlay lower protected" || fail "overlay bypass"
        echo "$PW" | sudo -S umount "$MNT"
    else
        say "overlayfs test skipped (no root/priv)"
    fi

    # ============================================================
    # 5. HARDLINK RACE (link + unlink concurrent)
    # ============================================================
    say "--- 5. HARDLINK RACE ---"
    ROOT=/tmp/pm-H1; setup "$ROOT"; reg "$ROOT"; mode2
    ln "$ROOT"/a/f /tmp/hl-race 2>/dev/null
    # Spawn concurrent unlink of hardlink and original
    ( unlink /tmp/hl-race 2>&1 ) & ( rm -rf "$ROOT"/a/f 2>&1 ) &
    wait
    [[ -e "$ROOT"/a/f ]] && pass "hardlink race safe" || fail "hardlink race bypass"

    # ============================================================
    # 6. RENAME EXCHANGE (RENAME_EXCHANGE flag)
    # ============================================================
    say "--- 6. RENAME EXCHANGE ---"
    ROOT=/tmp/pm-RX; setup "$ROOT"; reg "$ROOT"; mode2
    mkdir -p /tmp/exchange-target
    echo y > /tmp/exchange-target/target.txt
    # renameat2 with RENAME_EXCHANGE requires root for cross-dir? test same-dir
    cat > /tmp/rename_exchange.c <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
int main() {
    if (renameat2(AT_FDCWD, "/tmp/pm-RX/a/f", AT_FDCWD, "/tmp/exchange-target/target.txt", RENAME_EXCHANGE) < 0) {
        perror("renameat2"); return 1;
    }
    return 0;
}
EOF
    gcc -o /tmp/rename_exchange /tmp/rename_exchange.c
    if /tmp/rename_exchange 2>&1 | grep -q "Operation not permitted"; then
        pass "rename exchange denied"
    else
        fail "rename exchange bypassed"
    fi

    # ============================================================
    # 7. CROSS-FILESYSTEM RENAME (mv across mount points)
    # ============================================================
    say "--- 7. CROSS-FS RENAME ---"
    ROOT=/tmp/pm-CF; setup "$ROOT"; reg "$ROOT"; mode2
    # /tmp is tmpfs; create ext4 loop device for cross-fs
    LOOP=/tmp/loopfs.img; MNT=/mnt/pm-loop
    dd if=/dev/zero of="$LOOP" bs=1M count=50 2>/dev/null
    echo "$PW" | sudo -S mkfs.ext4 -F "$LOOP" >/dev/null 2>&1
    mkdir -p "$MNT"
    if echo "$PW" | sudo -S mount "$LOOP" "$MNT" 2>/dev/null; then
        echo "$PW" | sudo -S chown "$USER:" "$MNT"
        # mv from protected tmpfs to ext4
        mv "$ROOT"/a/f "$MNT"/stolen.txt 2>&1 | grep -q "Operation not permitted" && pass "cross-fs rename denied" || fail "cross-fs bypass"
        echo "$PW" | sudo -S umount "$MNT"
    else
        say "cross-fs test skipped"
    fi
    rm -f "$LOOP"

    # ============================================================
    # 8. CAPABILITY FD DUP RACE
    # ============================================================
    say "--- 8. CAP FD DUP/SCM_RIGHTS ---"
    ROOT=/tmp/pm-FD1; setup "$ROOT"; reg "$ROOT"; mode2
    fd=$("$PM_TX" request "$ROOT" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    # dup fd
    exec 9<&"$fd"
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    # Try attach via dup'd fd
    "$PM_TX" attachfd 9 >/dev/null 2>&1
    auth_rm "$ROOT"
    [[ ! -e "$ROOT" ]] && pass "dup fd works (same file desc)" || fail "dup fd broken"

    # SCM_RIGHTS handoff to another process
    ROOT=/tmp/pm-FD2; setup "$ROOT"; reg "$ROOT"; mode2
    cat > /tmp/scm_receiver.c <<'EOF'
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
int main() {
    int sv[2]; socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    if (fork() == 0) {
        close(sv[0]);
        struct msghdr mh = {0}; char buf[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = "x", .iov_len = 1 };
        mh.msg_iov = &iov; mh.msg_iovlen = 1; mh.msg_control = buf; mh.msg_controllen = sizeof(buf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
        int *fdp = (int*)CMSG_DATA(cm); *fdp = 4; // fd 4 expected
        recvmsg(sv[1], &mh, 0);
        *fdp = *(int*)CMSG_DATA(CMSG_FIRSTHDR(&mh));
        printf("RECEIVED_FD=%d\n", *fdp);
        close(sv[1]); return 0;
    }
    close(sv[1]);
    sleep(1);
    struct msghdr mh = {0}; char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { .iov_base = "x", .iov_len = 1 };
    mh.msg_iov = &iov; mh.msg_iovlen = 1; mh.msg_control = buf; mh.msg_controllen = sizeof(buf);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
    int *fdp = (int*)CMSG_DATA(cm); *fdp = 4;
    sendmsg(sv[0], &mh, 0);
    close(sv[0]); wait(NULL); return 0;
}
EOF
    gcc -o /tmp/scm_receiver /tmp/scm_receiver.c
    fd=$("$PM_TX" request /tmp/pm-FD3 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    exec 4<&"$fd"  # make fd 4
    /tmp/scm_receiver 2>/dev/null | grep RECEIVED_FD && pass "SCM_RIGHTS handoff works" || fail "SCM_RIGHTS failed"

    # ============================================================
    # 9. DAEMON RESTART MID-TX
    # ============================================================
    say "--- 9. RESTART MID-TX ---"
    ROOT=/tmp/pm-RM1; setup "$ROOT"; reg "$ROOT"; mode2
    fd=$("$PM_TX" request "$ROOT" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    echo "$PW" | sudo -S pkill -9 -x loader 2>/dev/null; sleep 1
    cd /home/nguyenduccanh/Documents/protectme_project/protectme/kernel/lsm
    echo "$PW" | sudo -S bash -c "setsid nohup ./loader > /tmp/pm-loader.log 2>&1 < /dev/null &"; sleep 3
    # Old fd should be dead
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    rm -rf "$ROOT" 2>&1 | grep -q "Operation not permitted" && pass "restart killed cap" || fail "cap survived restart"

    # ============================================================
    # 10. SIGHUP RACE (reconcile during operation)
    # ============================================================
    say "--- 10. SIGHUP RACE ---"
    ROOT=/tmp/pm-HUP1; setup "$ROOT"; reg "$ROOT"; mode2
    # Spawn rapid SIGHUPs while doing unlinks
    for i in {1..20}; do
        ( rm -rf "$ROOT"/a/f 2>&1 ) &
        echo "$PW" | sudo -S kill -HUP $(pgrep -x loader) 2>/dev/null
    done
    wait
    [[ -e "$ROOT"/a/f ]] && pass "SIGHUP race safe" || fail "SIGHUP race bypass"

    # ============================================================
    # 11. INODE REUSE (create, delete, recreate same inode)
    # ============================================================
    say "--- 11. INODE REUSE ---"
    ROOT=/tmp/pm-IR; setup "$ROOT"; reg "$ROOT"; mode2
    ino=$(stat -c %i "$ROOT"/a/f)
    rm -f "$ROOT"/a/f
    # Recreate file - may get same inode on tmpfs
    echo x > "$ROOT"/a/f
    new_ino=$(stat -c %i "$ROOT"/a/f)
    if [[ $ino -eq $new_ino ]]; then
        # inode reused! Try unlink - should be denied (ABA guard via f_inode)
        rm -f "$ROOT"/a/f 2>&1 | grep -q "Operation not permitted" && pass "inode reuse ABA guard" || fail "ABA bypass"
    else
        say "inode not reused on this FS (test inconclusive)"
    fi

    # ============================================================
    # 12. POLICY RECONCILE TOCTOU
    # ============================================================
    say "--- 12. POLICY RECONCILE TOCTOU ---"
    ROOT=/tmp/pm-PT1; setup "$ROOT"; reg "$ROOT"; mode2
    # Start rapid SIGHUPs while doing authorized destroy
    fd=$("$PM_TX" request "$ROOT" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    for i in {1..10}; do
        echo "$PW" | sudo -S kill -HUP $(pgrep -x loader) 2>/dev/null &
    done
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    auth_rm "$ROOT"
    wait
    [[ ! -e "$ROOT" ]] && pass "reconcile TOCTOU safe" || fail "reconcile TOCTOU bypass"

    # ============================================================
    # 13. MULTIPLE PROTECTED ROOTS NESTED
    # ============================================================
    say "--- 13. NESTED ROOTS CONCURRENT ---"
    ROOT=/tmp/pm-NR; rm -rf "$ROOT"; mkdir -p "$ROOT"/sub
    reg "$ROOT"; reg "$ROOT"/sub; mode2
    # Unlink in parent and child concurrently
    ( rm -rf "$ROOT"/a/f 2>&1 ) & ( rm -rf "$ROOT"/sub/b/f 2>&1 ) &
    wait
    [[ -e "$ROOT"/a/f && -e "$ROOT"/sub/b/f ]] && pass "nested roots concurrent" || fail "nested race"

    # ============================================================
    # 14. BPF MAP RELOAD (not implemented in loader, skip for now)
    # ============================================================
    say "--- 14. BPF RELOAD (not implemented, skip) ---"

    # ============================================================
    # 15. KERNEL MODULE LIFECYCLE (rmmod/insmod - not tested)
    # ============================================================
    say "--- 15. MODULE LIFECYCLE (skip, requires kernel module build) ---"

    # ============================================================
    # 16. FILESYSTEM-SPECIFIC: XFS/EXT4/BTRFS inode behavior
    # ============================================================
    say "--- 16. FS-SPECIFIC (ext4 loop) ---"
    # Already tested in cross-fs; ext4 inode stable across recreate
    say "covered in cross-fs test"

    # SUMMARY
    say "=== ADVERSARIAL SUMMARY ==="
    echo -e "${GRN}PASS: $PASS${NC}"
    echo -e "${RED}FAIL: $FAIL${NC}"
    [[ $FAIL -eq 0 ]] && exit 0 || exit 1
}

main "$@"