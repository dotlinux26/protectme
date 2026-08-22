# Protectme — Semantics Layer (protectme-semantics)

Status: research formulation v0.2 (2026-08-22). This is the "HOW TO UNDERSTAND"
half of the project. It may evolve on traces/graphs independently of kernel code.

## Positioning: a semantic safety plane, not a new filesystem

Protectme does NOT replace ext4/xfs/btrfs/tmpfs and does not touch block/storage
layers. It inserts a decision layer between VFS and the real filesystem:

```
            Applications
   ┌─────────┬─────────┬─────────┐
  Git      SQLite      rm     Python
   └─────────┴─────────┴─────────┘
                 │
                 ▼
                VFS
                 │
                 ▼
      ┌──────────────────────┐
      │  Protectme           │
      │  Semantic Safety     │
      │  Layer               │
      └─────────┬────────────┘
          ┌─────┴─────┐
          ▼           ▼
        ALLOW       DENY
          └─────┬─────┘
                ▼
        real filesystem (untouched)
```

Academic naming candidates:
- **Semantic Filesystem Safety Layer**
- **Kernel-Enforced Destructive-Operation Safety Layer**

## The new object model

Traditional FS object = namespace entry + inode + data + metadata.

Protectme's protected object adds:

```
namespace + inode + data + metadata
+ protection state
+ object boundary (root ↔ descendants relationship)
+ operation context (WHO/WHY channel)
+ destruction semantics (tree-collapse grammar)
```

That extension is the conceptual contribution.

## Two policy contracts (object semantics)

### FILE protection — immutable semantics

```
read → ALLOW;  write/truncate/delete/rename/replace → DENY
```

### TREE (FOLDER_ROOT) protection — mutation-allowing, destruction-vetoing

```
git pull / db update / editor / rm child / rename child   → ALLOW
destroy root or collapse subtree                          → DENY
```

This is not chmod, not ACL, not immutable bit, not snapshot: it is a
**semantic safety contract** bound to the object and its tree.

## The classification problem (OPEN)

Input: VFS operation stream. Output: `NORMAL_MUTATION` | `DESTRUCTIVE_TRAVERSAL`.

```
unlink(R,a); unlink(R,b); rmdir(R)             → DESTRUCTIVE_TREE
unlink(R,a); create(R,c); rename(R,b,R/c)      → NORMAL_MUTATION
```

Constraints inherited from evidence (see threat-model.md): per-op equivalence,
root-event-free variants, ancestor gap at depth ≥ 2. Any classifier must not
rely on process names, op-count thresholds, or timing.

Candidate directions:
1. explicit transaction protocol (`BEGIN(root) … COMMIT(root)`) — cooperative;
   proven primitive pieces exist (CAP-01A..C delegation/state)
2. dir-handle-bound authorization (bind intent to an open directory fd)
3. stream-level semantic state machine over events + fs graph — the open boss

## Offline evaluation path

Semantics research runs against recorded syscall/VFS traces (research/
directories) without touching the kernel — enabling CI-style regression over
labeled streams before any enforcement integration.
