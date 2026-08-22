# Security Model & Threat Model

## Security Claims

| Claim | Status | Evidence |
|-------|--------|----------|
| Unauthorized traversal denied before first child mutation | ✅ Tested | RUN16: rm/find/shutil/custom all denied |
| Tool-independent enforcement | ✅ Tested | RUN16: rm, find, python, custom C, git clean |
| Explicit destruction capability | ✅ Prototype | RUN11-RUN15: FD capability lifecycle |
| FD capability (possession = authority) | ✅ Prototype | RUN11: close=revoke, first-binder-wins |
| Capability expiry | ✅ Prototype | RUN10, RUN15: TTL enforcement |
| Global revoke (epoch bump) | ✅ Prototype | RUN15: O(1) epoch bump |
| Persistent policy + reconcile | ✅ Prototype | RUN12: startup/SIGHUP reconcile |
| Rename-out protection | ✅ Prototype | RUN15: path_rename hook |
| Object identity / drift detection | ✅ Prototype | RUN13: FRESH/REASSERT/DRIFT/SKIP |
| Ancestor boundary walk | ⚠️ Bounded | RUN14: PM_WALK_MAX=16 |
| OverlayFS / bind mount / cross-fs | ✅ Tested | RUN17: all denied |
| SIGKILL daemon survival | ⚠️ Documented | RUN17: BPF programs persist |
| Production-grade multi-user security | ❌ Not claimed | Requires hardening |

## Threat Model

### In Scope
- Accidental destructive traversal by authorized users (`rm -rf` typo)
- Automated tools run without proper context (CI, scripts, ansible)
- Destructive operations from compromised but non-root processes
- Rename exfiltration (mv protected → outside)
- Capability theft via FD handoff / SCM_RIGHTS
- Capability replay / stale capability reuse

### Out of Scope
- Root compromise (root can always bypass)
- Kernel exploits / BPF verifier bypass
- Side-channel attacks
- Physical access
- Supply chain attacks

### Trust Boundaries
- **Kernel** — enforces boundary, issues no trust
- **Loader/daemon (root)** — trusted to issue capabilities per policy
- **Policy file** — source of truth, editable only by root
- **User processes** — untrusted; must present valid capability for destruction

## Architecture

```
User Process
    │
    ├─ mutation ops (create, write, rename within, hardlink) → ALLOW
    │
    └─ destructive ops (unlink child, rmdir, rename out)
            │
            ▼
    BPF-LSM Hook (unlink/rmdir/rename)
            │
            ├─ classify: boundary? depth? crossing?
            │
            ├─ no capability / invalid capability → EPERM
            │
            └─ valid capability → ALLOW
```

## Capability Design

- **Object**: memfd (kernel-backed, no secret crosses trust boundary)
- **Possession** = authority (FD transferred via SCM_RIGHTS)
- **Epoch** — global counter; REVOKE bumps epoch → all caps die O(1)
- **Binder TGID** — first attach claims; fork/exec handled
- **TTL** — clamped ≤60s; expiry enforced in-kernel
- **Owner UID** — set at issuance; re-checked at attach
- **ABA guard** — f_inode stored at registration; verified at attach

## Policy Semantics

- **TREE** — protects entire subtree; mutation allowed, destruction vetoed
- **FILE** — protects single file; same semantics
- **MODE** — 0=off, 1=root-only, 2=strict (default)
- **U <uid>** — which user may request capabilities for this object
- **Reconcile** — idempotent; FRESH/REASSERT/DRIFTED/SKIP classification
- **Journal** — `/var/lib/protectme/identities.journal` remembers last (dev,ino) per path

## Daemon Lifecycle

- Startup: load BPF, attach LSM, reconcile policy, start capability issuer socket
- SIGHUP: re-reconcile policy (add/remove/modify)
- SIGTERM: graceful BPF detach, map cleanup, state=STOPPED
- SIGKILL: BPF programs remain attached (limitation); mitigated by systemd KillSignal=SIGTERM
- Heartbeat: `/run/protectme/state` written every ~1s; state=ACTIVE|STOPPED
- Status check: `protectme -s` reads heartbeat, judges ACTIVE if mtime <5s

## Known Limitations

1. **Depth bound**: PM_WALK_MAX=16; deeper trees need nested roots
2. **SIGKILL**: capabilities survive until epoch bump; use systemd KillSignal=SIGTERM
3. **No capability delegation to other users** without policy change
4. **Kernel 5.2+ required** (BPF-LSM)
5. **No filesystem encryption / integrity protection** — only traversal enforcement
6. **OverlayFS upper layer** writable; lower protected via whiteout