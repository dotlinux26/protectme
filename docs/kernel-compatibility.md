# Protectme — Kernel Compatibility

Status: v0.2 (2026-08-22). Facts verified on the development host; roadmap for
widest kernel-family support.

## Verified environment (dev host)

| Item | Value |
|---|---|
| Kernel | 6.18.12+kali-amd64 (x86_64) |
| BPF LSM | **active** — `bpf` present in `/sys/kernel/security/lsm` |
| Config | `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY=y` |
| CO-RE | runtime BTF `/sys/kernel/btf/vmlinux` available |
| Features in use | kprobes, syscall tracepoints, ringbuf, task-local storage (BPF_LOCAL_STORAGE_GET_F_CREATE), LRU hash, prctl tracepoint |

## Enforcement requirements (target)

BPF LSM hooks (`lsm/inode_unlink|rmdir|rename`) require:
- kernel ≥ 5.7 (BPF LSM introduced)
- `CONFIG_BPF_LSM=y` AND `bpf` listed in the `lsm=` boot parameter
- libbpf ≥ 0.1 style program attach (auto-detect via `bpf_program__type == BPF_PROG_TYPE_LSM`)

Fallback ladder when BPF LSM unavailable:
1. kprobes/fentry observation + userspace kill/notify (detect-only)
2. LSM via out-of-tree module (distro-dependent signing burden)
3. ptrace-based supervisor (fragile; last resort)

## Function-signature portability notes (learned the hard way)

- `vfs_rmdir/vfs_unlink` gained `struct mnt_idmap *` first arg in ~6.3 →
  arg indices shift. Mitigation used: read target from dentry (stable), parent
  from `dentry->d_parent->d_inode` or renamedata fields — avoid hard-coded
  positional inode args where a struct pointer exists.
- `vfs_rename(struct renamedata *)` single-arg since ~5.x; fields
  `old_parent/old_dentry/new_parent/new_dentry` confirmed via vmlinux.h BTF.
- Event ABI must be mirrored exactly between BPF and userspace (`event.h`,
  verified by offsetof printout at loader start).

## Compatibility philosophy

> Support the widest set of kernel families that has the needed primitive;
> give userspace a minimal compatibility layer.

Not "run everywhere": if a kernel lacks object/task state + LSM decision hooks,
Protectme degrades to detect-only and says so honestly.
