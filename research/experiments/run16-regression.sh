#!/usr/bin/env bash
# P0.6 Traversal Regression Suite — RUN16
# Tests ALL traversal variants + edge cases against the full primitive stack.
# Requires: loader running, policy loaded, pm-tx in PATH.

set -euo pipefail

PW='Canh0206@'
PM_TX="/tmp/opencode/pm-tx"
PM_MARK="/tmp/opencode/pm-mark"
LOG="/tmp/pm-run16.log"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
NC='\033[0m'

say() { echo -e "${YEL}[RUN16]${NC} $*"; }
pass() { echo -e "${GRN}  PASS${NC} $*"; ((PASS++)); }
fail() { echo -e "${RED}  FAIL${NC} $*"; ((FAIL++)); }

# Helper: run command, capture rc+output
run_cmd() {
    local desc="$1"; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    echo "$out" | tail -1
    return $rc
}

# Helper: assert EPERM (protection active)
assert_denied() {
    local desc="$1"; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [[ $rc -ne 0 ]] && grep -q "Operation not permitted" <<<"$out"; then
        pass "$desc"
    else
        fail "$desc (rc=$rc, out=$(echo "$out" | tail -1))"
    fi
}

# Helper: assert success (authorized)
assert_allowed() {
    local desc="$1"; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "$desc"
    else
        fail "$desc (rc=$rc, out=$(echo "$out" | tail -1))"
    fi
}

# Helper: create test tree
setup_tree() {
    local root="$1"
    rm -rf "$root"
    mkdir -p "$root"/{a,b,c/d/e}
    echo "data" > "$root"/a/file1.txt
    echo "data" > "$root"/b/file2.txt
    echo "data" > "$root"/c/d/e/deep.txt
}

# Helper: register tree in policy (via pm-mark for ad-hoc tests)
register_tree() {
    local path="$1"
    local dev ino
    dev=$(stat -c %d "$path")
    ino=$(stat -c %i "$path")
    "$PM_MARK" "$dev" "$ino" 0xFEEDFACE >/dev/null
    # also set mode 2 for strict enforcement
    "$PM_TX" mode 2 >/dev/null
}

# Helper: get capability FD and run command
run_with_cap() {
    local root="$1"; shift
    local desc="$1"; shift
    local fd
    fd=$("$PM_TX" request "$root" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    if [[ -z "$fd" ]]; then
        fail "$desc: failed to get capability fd"
        return 1
    fi
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    "$@"
}

# ============================================================
# TEST MATRIX
# ============================================================

main() {
    say "=== P0.6 REGRESSION SUITE START ==="
    echo "Log: $LOG"
    exec > >(tee -a "$LOG") 2>&1

    # 0. Ensure loader alive
    if ! pgrep -x loader >/dev/null; then
        say "Starting loader..."
        echo "$PW" | sudo -S pkill -9 -x loader 2>/dev/null; sleep 1
        cd /home/nguyenduccanh/Documents/protectme_project/protectme/kernel/lsm
        echo "$PW" | sudo -S bash -c "setsid nohup ./loader > /tmp/pm-loader.log 2>&1 < /dev/null &"; sleep 3
    fi

    # 1. Baseline: protection active without capability
    say "--- 1. BASELINE DENIAL (no capability) ---"
    ROOT1=/tmp/pm-R1
    setup_tree "$ROOT1"
    register_tree "$ROOT1"
    assert_denied "rm -rf" rm -rf "$ROOT1"
    assert_denied "find -delete" find "$ROOT1" -delete
    assert_denied "find -type f -delete" find "$ROOT1" -type f -delete
    assert_denied "python shutil.rmtree" python3 -c "import shutil; shutil.rmtree('$ROOT1')"
    # custom nftw test (small C program)
    cat > /tmp/nftw_test.c <<'EOF'
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    return nftw(argv[1], [](const char*, const struct stat*, int, struct FTW*) { return remove((const char*)0); }, 20, FTW_DEPTH | FTW_PHYS);
}
EOF
    gcc -o /tmp/nftw_test /tmp/nftw_test.c
    assert_denied "nftw" /tmp/nftw_test "$ROOT1"
    # git clean (needs git repo)
    (cd "$ROOT1" && git init -q && git add . && git commit -q -m x 2>/dev/null)
    assert_denied "git clean -fd" git -C "$ROOT1" clean -fd
    # rsync --delete
    mkdir -p /tmp/empty
    assert_denied "rsync --delete" rsync -a --delete /tmp/empty/ "$ROOT1/"

    # 2. Authorized destruction with FD capability (happy path)
    say "--- 2. AUTHORIZED DESTRUCTION (with FD cap) ---"
    ROOT2=/tmp/pm-R2
    setup_tree "$ROOT2"
    register_tree "$ROOT2"
    run_with_cap "$ROOT2" "rm -rf authorized" rm -rf "$ROOT2"
    assert_allowed "tree gone" test ! -e "$ROOT2"
    # Recreate for next tests
    setup_tree "$ROOT2"
    register_tree "$ROOT2"

    # 3. Rename out (should be denied by path_rename hook)
    say "--- 3. RENAME-OUT DENIAL ---"
    ROOT3=/tmp/pm-R3
    setup_tree "$ROOT3"
    register_tree "$ROOT3"
    assert_denied "mv child out" mv "$ROOT3"/a/file1.txt /tmp/outside_rename.txt
    assert_denied "mv dir out" mv "$ROOT3"/b /tmp/outside_dir

    # 4. Rename across sibling roots
    say "--- 4. RENAME ACROSS SIBLING ROOTS ---"
    ROOT4A=/tmp/pm-R4A; ROOT4B=/tmp/pm-R4B
    setup_tree "$ROOT4A"; setup_tree "$ROOT4B"
    register_tree "$ROOT4A"; register_tree "$ROOT4B"
    assert_denied "mv R4A/file -> R4B/" mv "$ROOT4A"/a/file1.txt "$ROOT4B"/stolen.txt

    # 5. Hardlink out + unlink (should allow unlink outside, inode survives inside)
    say "--- 5. HARDLINK OUT SEMANTICS ---"
    ROOT5=/tmp/pm-R5
    setup_tree "$ROOT5"
    register_tree "$ROOT5"
    ln "$ROOT5"/a/file1.txt /tmp/hardlink_out.txt
    assert_allowed "unlink outside hardlink" unlink /tmp/hardlink_out.txt
    assert_allowed "original survives" test -e "$ROOT5"/a/file1.txt

    # 6. Symlink traversal (find -L should not follow out of boundary)
    say "--- 6. SYMLINK BOUNDARY ---"
    ROOT6=/tmp/pm-R6
    setup_tree "$ROOT6"
    register_tree "$ROOT6"
    ln -s /etc/passwd "$ROOT6"/a/link_out
    # find -L inside should not delete /etc/passwd
    assert_denied "find -L -delete" find -L "$ROOT6" -delete
    assert_allowed "/etc/passwd intact" test -e /etc/passwd

    # 7. Deep ancestry (beyond PM_WALK_MAX=16 but with nested root rescue)
    say "--- 7. DEEP ANCESTRY + NESTED ROOT RESCUE ---"
    ROOT7=/tmp/pm-R7
    rm -rf "$ROOT7"
    mkdir -p "$ROOT7"
    # Create depth 20 chain
    P="$ROOT7"; for i in $(seq 1 20); do P="$P/d$i"; mkdir -p "$P"; done
    echo "deep" > "$P"/file.txt
    register_tree "$ROOT7"
    # Without nested root: depth 20 > 16 -> bypass expected
    assert_allowed "depth-20 bypass (no nested root)" unlink "$P"/file.txt
    # Now register nested root at depth 12
    NEST="$ROOT7"; for i in $(seq 1 12); do NEST="$NEST/d$i"; done
    register_tree "$NEST"
    # Recreate file
    echo "deep2" > "$P"/file2.txt
    assert_denied "depth-20 rescued by nested root" unlink "$P"/file2.txt

    # 8. Fork isolation (child loses capability)
    say "--- 8. FORK ISOLATION ---"
    ROOT8=/tmp/pm-R8
    setup_tree "$ROOT8"
    register_tree "$ROOT8"
    run_with_cap "$ROOT8" "parent authorized" bash -c '
        rm -rf '"$ROOT8"'
        echo "parent: tree gone"
    '
    assert_allowed "parent destroyed tree" test ! -e "$ROOT8"
    # Recreate
    setup_tree "$ROOT8"
    register_tree "$ROOT8"
    # Fork test: get cap in parent, fork, child tries without attach
    fd=$("$PM_TX" request "$ROOT8" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    # Fork: child inherits fd but NOT task context binding
    (
        "$PM_TX" attachfd "$fd" >/dev/null 2>&1
        rm -rf "$ROOT8" 2>&1 | tail -1
    ) &
    wait
    # Child should fail (different tgid, binder_tgid already set)
    if [[ -e "$ROOT8" ]]; then
        pass "fork child denied"
    else
        fail "fork child incorrectly allowed"
    fi

    # 9. Exec preserves capability
    say "--- 9. EXEC PRESERVES CAPABILITY ---"
    ROOT9=/tmp/pm-R9
    setup_tree "$ROOT9"
    register_tree "$ROOT9"
    run_with_cap "$ROOT9" "exec rm" bash -c "exec rm -rf '$ROOT9'"
    assert_allowed "exec preserved cap" test ! -e "$ROOT9"

    # 10. SIGKILL revokes capability
    say "--- 10. SIGKILL REVOCATION ---"
    ROOT10=/tmp/pm-R10
    setup_tree "$ROOT10"
    register_tree "$ROOT10"
    run_with_cap "$ROOT10" "sleep then kill" bash -c "
        sleep 5
        rm -rf '$ROOT10'
    " &
    CHILD=$!
    sleep 1
    kill -9 $CHILD
    wait $CHILD 2>/dev/null
    sleep 1
    if [[ -e "$ROOT10" ]]; then
        pass "SIGKILL revoked capability"
    else
        fail "SIGKILL did not revoke"
    fi

    # 11. Capability expiry
    say "--- 11. CAPABILITY EXPIRY ---"
    ROOT11=/tmp/pm-R11
    setup_tree "$ROOT11"
    register_tree "$ROOT11"
    fd=$("$PM_TX" request "$ROOT11" 500 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    sleep 1
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    run_cmd "expired cap denied" rm -rf "$ROOT11" 2>&1 | tail -1
    if [[ -e "$ROOT11" ]]; then
        pass "expired cap denied"
    else
        fail "expired cap incorrectly allowed"
    fi

    # 12. Global revoke
    say "--- 12. GLOBAL REVOKE ---"
    ROOT12=/tmp/pm-R12
    setup_tree "$ROOT12"
    register_tree "$ROOT12"
    fd=$("$PM_TX" request "$ROOT12" 30000 | grep -o 'fd=[0-9]*' | cut -d= -f2)
    "$PM_TX" revoke >/dev/null
    "$PM_TX" attachfd "$fd" >/dev/null 2>&1
    run_cmd "revoked cap denied" rm -rf "$ROOT12" 2>&1 | tail -1
    if [[ -e "$ROOT12" ]]; then
        pass "global revoke works"
    else
        fail "global revoke failed"
    fi

    # 13. Daemon restart preserves protection (policy reconciliation)
    say "--- 13. DAEMON RESTART ---"
    ROOT13=/tmp/pm-R13
    setup_tree "$ROOT13"
    register_tree "$ROOT13"
    echo "$PW" | sudo -S pkill -9 -x loader 2>/dev/null; sleep 1
    cd /home/nguyenduccanh/Documents/protectme_project/protectme/kernel/lsm
    echo "$PW" | sudo -S bash -c "setsid nohup ./loader > /tmp/pm-loader.log 2>&1 < /dev/null &"; sleep 3
    assert_denied "protection after restart" rm -rf "$ROOT13"
    # Authorized destruction still works after restart
    setup_tree "$ROOT13"
    register_tree "$ROOT13"
    run_with_cap "$ROOT13" "authorized after restart" rm -rf "$ROOT13"
    assert_allowed "destroy after restart" test ! -e "$ROOT13"

    # 14. Policy reload (SIGHUP) adds new tree
    say "--- 14. POLICY RELOAD (SIGHUP) ---"
    ROOT14=/tmp/pm-R14
    setup_tree "$ROOT14"
    # Add to policy file
    echo "TREE $ROOT14 U 1000" | sudo -S tee -a /etc/protectme/policy >/dev/null
    L=$(pgrep -x loader); echo "$PW" | sudo -S kill -HUP $L 2>/dev/null; sleep 1
    assert_denied "new tree protected after SIGHUP" rm -rf "$ROOT14"

    # 15. Mount namespace / bind mount edge (if root)
    say "--- 15. BIND MOUNT ---"
    ROOT15=/tmp/pm-R15
    setup_tree "$ROOT15"
    register_tree "$ROOT15"
    mkdir -p /mnt/testbind
    echo "$PW" | sudo -S mount --bind "$ROOT15" /mnt/testbind 2>/dev/null || say "bind mount skipped (no priv)"
    if mountpoint -q /mnt/testbind; then
        assert_denied "bind mount unlink" rm -f /mnt/testbind/a/file1.txt
        echo "$PW" | sudo -S umount /mnt/testbind
    else
        say "bind mount test skipped (requires root)"
    fi

    # 16. Multiple roots, destroy one
    say "--- 16. MULTIPLE ROOTS ---"
    ROOT16A=/tmp/pm-R16A; ROOT16B=/tmp/pm-R16B
    setup_tree "$ROOT16A"; setup_tree "$ROOT16B"
    register_tree "$ROOT16A"; register_tree "$ROOT16B"
    run_with_cap "$ROOT16A" "destroy A only" rm -rf "$ROOT16A"
    assert_allowed "A destroyed" test ! -e "$ROOT16A"
    assert_denied "B still protected" rm -rf "$ROOT16B"

    # 17. Custom C unlinkat
    say "--- 17. CUSTOM C unlinkat ---"
    ROOT17=/tmp/pm-R17
    setup_tree "$ROOT17"
    register_tree "$ROOT17"
    cat > /tmp/unlinkat_test.c <<'EOF'
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int dfd = AT_FDCWD;
    return unlinkat(dfd, argv[1], 0);
}
EOF
    gcc -o /tmp/unlinkat_test /tmp/unlinkat_test.c
    assert_denied "unlinkat" /tmp/unlinkat_test "$ROOT17/a/file1.txt"

    # 18. python os.remove / os.unlink
    say "--- 18. PYTHON os.remove/unlink ---"
    ROOT18=/tmp/pm-R18
    setup_tree "$ROOT18"
    register_tree "$ROOT18"
    assert_denied "python os.remove" python3 -c "import os; os.remove('$ROOT18/a/file1.txt')"
    assert_denied "python os.unlink" python3 -c "import os; os.unlink('$ROOT18/b/file2.txt')"

    # 19. perl File::Path::remove_tree
    say "--- 19. PERL File::Path ---"
    ROOT19=/tmp/pm-R19
    setup_tree "$ROOT19"
    register_tree "$ROOT19"
    if command -v perl >/dev/null; then
        assert_denied "perl remove_tree" perl -MFile::Path=remove_tree -e "remove_tree('$ROOT19')"
    else
        say "perl not installed, skip"
    fi

    # 20. go os.RemoveAll
    say "--- 20. GO os.RemoveAll ---"
    ROOT20=/tmp/pm-R20
    setup_tree "$ROOT20"
    register_tree "$ROOT20"
    if command -v go >/dev/null; then
        cat > /tmp/removeall.go <<'EOF'
package main
import ("os"; "fmt")
func main() {
    if len(os.Args) < 2 { return }
    err := os.RemoveAll(os.Args[1])
    if err != nil { fmt.Println(err) }
}
EOF
        assert_denied "go RemoveAll" go run /tmp/removeall.go "$ROOT20"
    else
        say "go not installed, skip"
    fi

    # SUMMARY
    say "=== REGRESSION SUMMARY ==="
    echo -e "${GRN}PASS: $PASS${NC}"
    echo -e "${RED}FAIL: $FAIL${NC}"
    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GRN}ALL TESTS PASSED${NC}"
        exit 0
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
        exit 1
    fi
}

main "$@"