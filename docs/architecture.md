# Protectme — System Architecture

Status: v1.1 (2026-08-22). FEATURE FREEZE in effect: hardening only until
0.1.0 Definition of Done (below). New ideas → FUTURE.md.

## The boundary, nailed

> Policy lives in userspace. Authority is represented by a kernel-backed
> capability. Enforcement lives in LSM. The filesystem remains owned by
> the filesystem.

## Three layers

```text
                Protectme
                    │
     ┌──────────────┼──────────────┐
     │              │              │
 Semantics      Authority     Enforcement
     │              │              │
 destructive    capability      BPF-LSM
 traversal      lifecycle         VFS
 intent         binding          veto
```

## 0.1.0 Definition of Done

```text
protectme /project            → protected
git pull / vim / db / rm child→ normal operation
rm -rf /project               → DENIED
find -delete / shutil.rmtree  → DENIED (LSM, not wrapper)
custom C traversal            → DENIED (LSM, not wrapper)
protectme -u /project         → protection lifted, fs normal
reboot                        → policy restored, protection active
daemon death                  → NO silent-unprotected state (DEGRADED shown)
non-wrapper userspace         → still enforced by LSM
```

Failure semantics must distinguish: ACTIVE · DEGRADED · UNSUPPORTED ·
NOT PROTECTED. "Looks protected but isn't" is a release blocker.

## Execution order (frozen)

```text
 1. FD capability                      (CAP-02)
 2. persistent policy + state restore  (STATE-01/02)
 3. object identity / ancestor correctness
 4. capability revoke/lifetime spec
 5. BPF-LSM attach/reload stability
 6. systemd service
 7. CLI: protectme PATH | -u | -l | -s
 8. rm integration (shim = UX only)
 9. test matrix
10. .deb package
```

## One system, two layers, one user-facing surface

```
                         ┌───────────────────────┐
                         │       User/App        │
                         │  rm git python ...    │
                         └──────────┬────────────┘
                                    │  normal filesystem ops
                                    ▼
                 ┌──────────────────────────────────┐
                 │       Protectme Semantics        │
                 │ object graph / traversal state   │
                 │ destruction intent / TX (research)│
                 └────────────────┬─────────────────┘
                                  │ semantic decision
                                  ▼
                 ┌──────────────────────────────────┐
                 │        Protectme Kernel          │
                 │            BPF-LSM               │
                 │ TASK context · INODE/root state  │
                 │ TX capability · unlink/rmdir/    │
                 │ rename checks                    │
                 └────────────────┬─────────────────┘
                                  │ ALLOW / DENY
                                  ▼
                                VFS  →  ext4/xfs/btrfs/tmpfs/…
```

## Components

### protectme-kernel — enforcement substrate
`lsm/` + `state/` (task_ctx, inode_state, tx_state) + loader. Does exactly one
thing: `operation + semantic state → ALLOW/DENY`. BPF-LSM + CO-RE + libbpf +
BPF maps for runtime state. No policy database, no own filesystem, no network.
Complex things that don't belong in BPF (policy management, TX lifecycle,
persistent config) stay in userspace.

### protectme-semantics — research layer
Produces: FILE protection, TREE protection, DESTRUCTION transaction,
object identity, ancestry, operation context. Long-term intent taxonomy:
NORMAL_MUTATION / DESTRUCTIVE_TRAVERSAL / REPLACEMENT / MIGRATION.
**Never modifies the filesystem itself** — only creates semantic context.

### protectmed — system daemon (systemd)
Loads policy → maintains kernel state → creates/revokes TX → lifecycle +
audit. Must NEVER do filesystem work (no rm/cp/mv/backup/restore/shell).
Daemon death ≠ system failure: `protectme -s` reports DEGRADED / NOT ACTIVE;
active protection state is always explicit and visible.

### protectme — the only CLI users learn (git-style, minimal)

```bash
protectme /project          # protect object (dir → TREE, file → FILE)
protectme -u /project       # unprotect that object
protectme -l                # list protected objects
protectme -s                # status
```

Type resolution is automatic from the object itself — users never learn about
"TREE policy" vs "FILE policy"; they just protect *things*, like git tracks
*things*. `-u` does NOT recurse by default (`protectme -u /project` removes
only that root's protection, never `/project/*`) — recursion would smuggle a
destructive semantic into an unprotect command.

## THE PIVOT (2026-08-22): protection is a state, not an authority to bypass

```
PROTECTED      ├── normal mutation → ALLOW
               └── destruction     → DENY
UNPROTECTED    └── filesystem behaves normally
```

To really destroy: **change the state first**.

```bash
protectme protect-tree ~/project   # or: protectme ~/project
rm -rf ~/project                   # works — it's unprotected now
```

Consequences:

- There is NO user-facing "destruction authority" that punches through
  protection. `protectme destroy`, if it ever exists, is pure UX sugar
  (confirm intent → unprotect → exec rm) and is NOT in the MVP.
- The RUN8 destruction-TX primitive is demoted to a RESEARCH primitive:
  evidence that explicit kernel-visible destruction context works (PART XIV),
  candidate substrate for advanced semantics later — not a product authority path.
- Security model becomes monotone and auditable: protection can only be
  lifted by changing protection state via the same privileged path that
  created it. No magic env var / argv / PID / process name grants anything
  (RUN8 case E proved why).

## State discipline (architectural principle #1)

```
Persistent : policy           (/etc/protectme/policy)
Transient  : transactions     (kernel maps; reboot = all gone — desired)
Kernel     : enforcement state (BPF maps only)
Userspace  : orchestration
Filesystem : NEVER owned by Protectme
```

Policy format stays dumb and auditable:

```text
TREE /home/ubuntu/project
FILE /etc/my-rfc.md
```

No YAML/JSON parser, no DB, no dependencies. `cat /etc/protectme/policy`.

## Packaging & install (Linux-native)

.deb first (+ .tar.gz; RPM later):

```text
/usr/bin/protectme
/usr/lib/protectme/protectmed
/usr/lib/protectme/bpf/...
/usr/libexec/protectme/rm-wrapper      # optional, see rm-integration.md
/etc/protectme/policy
/lib/systemd/system/protectmed.service
```

First install: detect kernel → detect BPF-LSM → load substrate → start
daemon → verify health. Missing kernel capability ⇒ honest error
("kernel capability unavailable"), **never a fake fallback**.

systemd hardening (initial): Restart=on-failure, NoNewPrivileges=true,
PrivateTmp=true, ProtectSystem=strict, RestrictAddressFamilies=AF_UNIX —
adjusted later against required BPF/LSM capabilities.

## Final privilege boundary

```
ROOT ── protectmed ── kernel/BPF-LSM     ← ALL authority lives here
CLI · rm wrapper · policy parser · UI · logs  ← zero override power
```

## Repo shape

```text
protectme/
├── README.md LICENSE Makefile
├── docs/         architecture security-model semantics kernel-compat threat-model
├── research/     traversal/ semantics/ experiments/ findings/
├── kernel/       bpf/ lsm/ maps/ loader/
├── daemon/       policy/ tx/ lifecycle/ audit/
├── cli/
├── integrations/ coreutils/
├── tests/        kernel/ semantics/ tx/ traversal/ integration/
└── packaging/    deb/ systemd/
```

Product code stays small; research may grow large:

> Research proves complexity; product contains complexity.
