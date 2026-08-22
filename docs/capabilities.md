# Capabilities

## Overview

A capability is an **FD-based kernel object** representing explicit authorization to perform destructive traversal on a protected tree. It is obtained via `protectme destroy` and exists only in the requesting process's context.

## Design Principles

- **Possession = Authority** — no secret crosses the trust boundary; the FD itself is the authority
- **Close = Revoke** — closing the FD (process exit, exec, explicit close) instantly revokes authority
- **Single-use** — each capability is bound to a single process (first binder wins)
- **Time-bound** — TTL clamped to ≤60 seconds
- **Epoch-bound** — global revoke invalidates all capabilities instantly

## Lifecycle

```
1. REQUEST
   protectme destroy /path -- cmd
         │
         ▼
2. ISSUER (root daemon)
   - validates policy ownership (U <uid>)
   - creates memfd "protectme-tx"
   - registers in kernel (REGF): dev, ino, owner_uid, TTL, epoch
   - sends FD via SCM_RIGHTS
         │
         ▼
3. ATTACH (client process)
   - receives FD via SCM_RIGHTS
   - presents via ATFD: fd_number
   - kernel validates: epoch, TTL, owner_uid, binder_tgid, f_inode
   - binds task context: tx_dev, tx_ino
         │
         ▼
4. EXECUTE
   - cmd runs with task context bound
   - destructive ops under protected tree → ALLOWED
   - capability remains bound to task (survives exec)
         │
         ▼
5. TERMINATION
   - process exit / close(fd) / TTL expiry / global REVOKE
   - capability revoked
   - subsequent destructive ops → DENIED
```

## Capability Properties

| Property | Enforcement |
|----------|-------------|
| **Possession** | FD must be open in process |
| **Epoch** | Must match current global epoch |
| **TTL** | `now < expires_ns` |
| **Owner UID** | `current_uid == cap.owner_uid` |
| **Binder TGID** | First attach claims; fork loses it |
| **ABA guard** | `f_inode` must match registration |

## Revoke

Global revoke (`protectme revoke` or daemon startup epoch bump):

```c
// Kernel: single array map cap_epoch[1]
epoch++  // O(1), invalidates ALL capabilities instantly
```

No per-capability revocation list needed. Stale capabilities denied on next ATFD or operation.

## Fork / Exec Semantics

| Event | Capability |
|-------|------------|
| `fork()` | **Lost** — child has different TGID; binder_tgid mismatch |
| `exec()` | **Preserved** — FD not CLOEXEC; task context bound to new program |
| `close(fd)` | **Revoked** — immediate |
| Process exit | **Revoked** — FD closed |

## SCM_RIGHTS Handoff

Capabilities can be transferred between processes via `SCM_RIGHTS` on unix domain sockets:

```c
// Sender
sendmsg(fd, SCM_RIGHTS, &cap_fd);

// Receiver
recvmsg(fd, &msg);
cap_fd = CMSG_DATA(cm);
```

The FD refers to the **same struct file*** — kernel authorization uses the same capability entry.

## UX Flow

```bash
# Interactive
protectme destroy /protected/tree -- rm -rf /protected/tree

# In scripts
protectme destroy /data/backup -- \
    tar -czf /tmp/backup.tar.gz /data/backup && rm -rf /data/backup

# The `destroy` subcommand handles: request → attach → exec in one atomic flow
```

## Kernel ABI (Research)

| Magic | Name | Args | Purpose |
|-------|------|------|---------|
| `0x52454746` | REGF | fd, (owner<<32)\|dev, ino, ttl | Loader registers memfd as capability |
| `0x41544644` | ATFD | fd | Client presents FD for attach |
| `0x52564B45` | RVKE | — | Bump global epoch (revoke all) |

All via `prctl(SYS_prctl, MAGIC, ...)` traced at `tp/syscalls/sys_enter_prctl`.