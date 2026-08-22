# Protectme — Threat Model

Status: draft v0.2 (2026-08-22). Grounded in P0 evidence; no speculation.

## Protected asset

A directory subtree ("protected root") registered by the user via
`protectme <path>`. Asset = **tree content + boundary existence**, not just the
root inode.

## Adversary

| Adversary | Capability | Example |
|---|---|---|
| A1 careless user | arbitrary shell commands, own UID | `rm -rf`, wrong cwd |
| A2 misbehaving tool | legitimate program with destructive bug/config | build script gone wrong, bad `git clean` args |
| A3 malicious process | same UID, arbitrary syscalls, knows Protectme exists | malware under user account |

Explicitly OUT of scope: root/other-UID attackers, kernel-level adversaries,
offline attacks. Protectme is a safety layer for *one's own* destructive power,
not a sandbox or MAC against privilege escalation.

## Attack surface (what must be caught)

Any VFS-visible path that empties or removes a protected tree, regardless of
implementation:

```
rm -rf R            find R -delete        find R -type f -delete
shutil.rmtree(R)    custom C nftw()       git clean -fdx (planned test)
mv R elsewhere      rename-over-boundary  ...any future tool
```

Evidence that these form one semantic class: research/traversal/README.md
(P0-OBS-04: four implementations converge on identical VFS mutation sequence).

## Known hard constraints (empirical)

1. **P0-OBS-01**: first op of destruction ≡ ordinary deletion at hook level —
   per-syscall classification cannot separate them.
2. **P0-OBS-02**: root rmdir arrives last → root-only veto preserves nothing.
3. **P0-OBS-05**: content can be fully destroyed with zero root events.
4. **P0-OBS-06**: parent-state lookup loses the boundary at depth ≥ 2.
5. **P0-OBS-03**: process identity (comm/ppid) is attribution, not authorization.

## Defense layers required by the model

```
L1 enforcement  : kernel must veto reliably once decided     (protectme-kernel)
L2 semantics    : classify streams as mutation/destruction   (protectme-semantics)
L3 protocol     : cooperative tools declare intent explicitly (BEGIN/COMMIT)
```

## Non-goals

- No data management, no backup, no snapshots, no ownership of user data.
- No heuristics on process names, thresholds, or timing (all bypassable /
  false-positive-prone; see P0-THEOREM scope note).
- Not chmod/ACL/immutable-bit/snapshot — those answer different questions.
