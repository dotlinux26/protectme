# Kernel State Primitives

Kernel-resident state backing enforcement decisions. Currently implemented
inside `kernel/lsm/obs.bpf.c`; will be split out as enforcement matures.

## Task state (BPF_MAP_TYPE_TASK_STORAGE, `syscall_marker`)

```
struct task_ctx { u32 active; u32 sticky; }
```

| Field | Meaning | Lifetime |
|---|---|---|
| active | transient syscall marker (0xC0DE0001..3), set at sys_enter_*, cleared at sys_exit_* | one syscall |
| sticky | userspace-set persistent context via prctl(0xC0DEC0DE, val); delegation value 0xDEADBEEF propagates explicitly at task_newtask | task lifetime, survives execve, NOT inherited by fork/threads without explicit propagation |

Planned: destruction-transaction fields `{tx_dev, tx_ino}` binding a task to
BEGIN(root)/COMMIT(root) (P0-B).

**Update 2026-08-22 (run 8): tx_dev/tx_ino IMPLEMENTED** — bound via prctl
transport (`pm-tx run ROOT -- CMD`), exec preserves, fork/thread do not inherit,
exit auto-revokes. Still TRANSPORT-only; production authority = CAP-01E
(kernel-issued FD capability).

## Object state (BPF_MAP_TYPE_LRU_HASH, `inode_state`)

```
key   = { dev:u32, ino:u32 }        # object identity
value = { active:u32, sticky:u32 }  # payload (e.g. 0xFEEDFACE protected)
set via prctl(0x494E4F44, dev, ino, payload)   # pm-mark tool
```

Verified properties (run 7):
- lookup at VFS kprobes for TARGET inode and PARENT dir inode
- depth-1 descendants see protected parent; depth ≥ 2 do NOT
  (**ancestor gap**, P0-OBS-06) → ancestry resolution (bounded d_parent walk or
  mark-on-create propagation) is required for tree-wide policy

## Decision inputs available at hook time

```
WHO    : task ctx (sticky/delegation) + credentials (attribution only!)
WHAT   : target identity (dev+ino+type+mode) + target state
WHERE  : parent identity + parent state (+ planned nearest-root walk)
WHEN   : syscall context marker; operation type
```

Enforcement point: BPF LSM hooks (`lsm/inode_unlink`, `lsm/inode_rmdir`,
`lsm/inode_rename`) return verdicts; kprobes remain observation-only.
