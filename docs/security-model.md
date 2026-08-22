# Protectme — Security Model & Research-Mode Disclaimers

Status: v0.1 (2026-08-22). Governs the P0-B destruction-transaction prototype.

## 1. prctl-magic channel is TRANSPORT, never AUTHORIZATION

The experiment uses `prctl(PM_TX_BEGIN, dev, ino)` to deliver a transaction
binding into BPF task-local storage:

```
prctl(...)          ← any process can call this
      ↓
BPF task storage    ← execution context
```

**This is an experiment channel only.** In a product, this exact call would be
trivially abusable (`malicious-program` calls it and gains destruction
authority). Production authorization must be policy-controlled (e.g., mediated
by the privileged daemon, key/capability-bound) — designed under CAP-01F.
Nothing from the prctl channel may leak into product architecture as-is.

## 2. Research modes (none is a finished product)

| Mode | Name | Meaning | Claim |
|---|---|---|---|
| 0 | OBSERVE | telemetry only, verdicts logged not enforced | research / telemetry |
| 1 | ROOT_ONLY | deny removal/rename-out of protected root itself | partial protection |
| 2 | TRANSACTION_STRICT | ALL destructive ops inside boundary require bound TX | protocol experiment |

**No mode claims Protectme-MVP completeness.**

Mode 2 deliberately breaks invariant R1 (`rm /protected/a` denied without a
transaction). That is NOT an experiment bug — it is empirical proof of the P0
trade-off: with current primitives, R1 (ordinary descendant mutation stays
allowed) and R2 (recursive destruction stopped before first child) cannot hold
simultaneously unless destruction context is explicitly represented at the
kernel boundary.

## 3. Transaction lifetime model

```
pm-tx run ROOT -- CMD [args…]
    fork → bind TX to task → exec CMD   (exec preserves task ctx, CAP-01B)
    CMD exits → automatic revoke
```

No separate `begin`/`commit` processes (task-local state dies with the task;
independent CLI processes would not share execution context). Long-lived
transactions, if ever needed, require a kernel-backed handle/FD — future work.

Least privilege: fork/threads do NOT inherit the transaction; explicit
delegation only (CAP-01C primitive).

## 4. Kernel state minimality

BPF maps hold **runtime enforcement state** only:

- protected-root identity `(dev, ino)`
- policy mode (single u32)
- task→transaction relationship

No path strings, no object trees, no serialized configuration inside the kernel.
Authoritative policy stays in userspace; kernel sees the minimal decision state.

## 5. Observe / decide separation

- `kprobe/vfs_*` programs: observation only, never decide.
- `lsm/inode_*` programs: the sole enforcement point (return verdicts).
