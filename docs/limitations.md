# Limitations

## Ancestor Traversal Depth

**Bound:** `PM_WALK_MAX = 16` hops (compile-time constant)

**Behavior:**
- Operations within 16 ancestors of a protected root → enforced
- Operations beyond 16 hops with no nearer registered root → **allowed** (bypass)

**Mitigation:** Register nested roots at depth ≤12 for deep trees. Nested roots restore enforcement via nearest-root locality.

**Rationale:** BPF bounded loops; production should use RCU or pinned-map reconciliation for unbounded walks.

## SIGKILL Daemon Survival

**Issue:** `pkill -9 protectmed` leaves BPF programs attached and maps intact.

**Effect:** Capabilities survive across restart; new loader loads second program set.

**Not a semantic bypass** — enforcement logic unchanged — but operational concern.

**Mitigations:**
- systemd: `KillSignal=SIGTERM`, `Restart=on-failure`
- Loader SIGTERM handler: graceful BPF detach + map cleanup
- Startup: detect stale maps → force cleanup + epoch bump
- Capability epoch: RVKE on startup invalidates all stale caps

## OverlayFS

**Lower (protected) layer:** Protected via whiteout mechanism — deletion creates whiteout in upper layer, lower inode preserved.

**Upper layer:** Writable (not protected). Files created in upper layer not protected.

**Cross-layer rename:** Blocked when source is in lower protected layer.

## Cross-Filesystem Rename

Blocked when source is under protected tree, regardless of destination filesystem.

## Kernel Requirements

- **Linux 5.2+** (BPF-LSM support)
- **CONFIG_BPF_LSM=y**
- **CONFIG_BPF_SYSCALL=y**
- **CONFIG_DEBUG_INFO_BTF=y** (for CO-RE)
- **CAP_SYS_ADMIN** for loader (to load BPF programs)

Tested on: 5.15, 6.1, 6.6, 6.8 (x86_64)

## Filesystem Support

| FS | Inode Stability | Inode Reuse | Notes |
|----|-----------------|-------------|-------|
| ext4 | Stable | Rare | ABA guard effective |
| xfs | Stable | Rare | |
| btrfs | Stable | Rare | |
| tmpfs | Stable within boot | Possible | ABA guard (f_inode) handles reuse |
| overlayfs | Lower stable | Lower stable | Upper not protected |

## No Protection Against

- **Root compromise** — root can always bypass (unload BPF, modify policy, etc.)
- **Kernel exploits** — BPF verifier bypass, kernel RCE
- **Side-channels** — timing, cache, etc.
- **Physical access**
- **Supply chain** — compromised binary/kernel
- **Encryption / integrity** — only traversal enforcement
- **Network filesystem** — NFS, SMB not tested; may have inode semantics differences

## Multi-User Security

**Not production-ready.** Current prototype:
- Single global capability epoch
- No per-user capability isolation beyond UID check
- Capability issuer socket world-writable (0666) for research
- Policy file root-only but daemon runs as root

Production hardening needed:
- Per-user capability namespaces
- Issuer socket permissions (group-based)
- Audit logging
- SELinux/AppArmor integration

## Performance

- **Overhead:** ~50-200ns per unlink/rmdir/rename (BPF-LSM hook)
- **Memory:** ~256 entries per map (configurable)
- **Startup:** ~200ms (BPF load + policy reconcile)

## Debug / Forensics

- Verbose mode: `protectme --debug` (raw VFS events)
- Audit log: `/var/log/protectme/audit.log` (transaction-level)
- State: `/run/protectme/state` (ACTIVE/STOPPED, epoch, roots)
- Maps: `bpftool map dump name <map>`

## Known Issues

1. **Depth bound bypass** — documented, not a bug
2. **SIGKILL survival** — BPF limitation, mitigated operationally
3. **Journal path truncation** — paths with spaces truncated in identity journal
4. **No cross-mount bind detection** — bind mount of protected tree into unprotected location still protected (correct)
5. **No capability delegation UI** — admin must edit policy for UID changes

## Future Work (Post v0.1)

- Unbounded ancestor walk (RCU / pinned maps)
- Per-user capability namespaces
- Capability delegation API
- OverlayFS upper-layer protection option
- Network filesystem support
- SELinux/AppArmor integration
- Formal verification of BPF logic