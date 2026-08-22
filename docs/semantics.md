# Protectme — Semantics Layer (protectme-semantics)

Status: research formulation v0.3 (2026-08-22). This is the "HOW TO UNDERSTAND"
half of the project — the **filesystem intent model**. It may evolve on
traces/graphs independently of kernel code.

## Core principle: intent is a primitive, not a heuristic

```
intent = explicit, kernel-visible, constrained semantic context
NOT    = "model thinks this looks like rm -rf"
```

Protectme must NOT become an EDR/AI behavior detector. Applications (or a
compatibility wrapper) declare operation context explicitly; the layer validates,
binds, tracks, enforces:

```
Application
    │  explicit operation/context declaration
    ▼
Protectme Intent Layer
    ├── validate scope
    ├── bind objects
    ├── track lifecycle
    └── enforce invariants
    │
    ▼
LSM / VFS
```

## Intent taxonomy (beyond destruction)

`rm -rf` is the FIRST USE CASE — chosen because it is the hardest problem, so it
hardens the model against vague abstraction. The same primitive generalizes:

| Intent | Meaning | Example |
|---|---|---|
| SAFE | ordinary mutation | editor save, git checkout |
| DESTRUCTIVE | subtree collapse | `rm -rf`, rmtree |
| SENSITIVE | policy-routed special object | keys, configs |
| INTEGRITY | "never modify" | RFC/spec/config files |
| REPLACEMENT | no atomic-replace | binaries, signing keys, release artifacts |
| MIGRATION | deliberate move sequence | renames+unlinks as one authorized op |
| BULK_MUTATION | valid transaction touching many objects | differs semantically from "thousands of odd changes" |
| RECOVERY | rollback/restore operation | separate policy class for restore flows |

Triage shape:

```
filesystem operations
        │
        ▼
Protectme Intent
        │
  ┌─────┼──────┐
SAFE  DESTRUCTIVE  SENSITIVE
 │       │            │
ALLOW   DENY       POLICY
```

## Division of labor between the two projects

```
protectme-semantics : WHAT is this operation semantically trying to do?
                      (filesystem intent model)
protectme-kernel    : IS this intent permitted?
                      (enforcement substrate)

intent → policy → ALLOW / DENY
```

Long-term: protectme-semantics may decouple from any specific LSM
implementation and become a **semantic model/API for Linux filesystem tooling**
in general.

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
